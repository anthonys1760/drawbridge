import { serveStdio } from "@modelcontextprotocol/server/stdio";
import {
  JsonlAuditLog,
  YamlPolicy,
  loadPinFile,
  ulid,
  type DrawbridgeConfig,
  type PolicyEngine,
} from "@drawbridge/core";
import { createGatewayServer } from "./server.js";
import { SdkUpstreamPool, type UpstreamPool } from "./upstreams.js";

export interface ServeOptions {
  policy?: PolicyEngine;
  /** Override the process session id. Tests use this; production mints a ULID. */
  sessionId?: string;
}

/**
 * Connect upstreams in the background so `server/discover` is not blocked by
 * slow stdio or HTTP handshakes, open the audit log first (a broken chain
 * refuses to start), then serve stdio for 2026-07-28 clients only.
 */
export async function serveConfig(config: DrawbridgeConfig, options: ServeOptions = {}): Promise<void> {
  const sessionId = options.sessionId ?? ulid();
  const audit = await JsonlAuditLog.open(config.audit.path);
  const pins = config.upstreams.some((entry) => entry.upstream.pinTools)
    ? await loadPinFile(config.pins.path)
    : undefined;
  const policy = options.policy ?? new YamlPolicy(config, pins ? { pins } : {});
  let pool: UpstreamPool | undefined;
  let closed = false;
  let settleReady: (pool: UpstreamPool) => void = () => undefined;
  let failReady: (error: unknown) => void = () => undefined;
  const ready = new Promise<UpstreamPool>((resolve, reject) => {
    settleReady = resolve;
    failReady = reject;
  });

  void ready.catch(() => undefined);

  const connecting = SdkUpstreamPool.connect(config.upstreams)
    .then((created) => {
      if (closed) {
        return created.close().then(() => {
          throw new Error("Drawbridge shut down before upstreams were ready");
        });
      }
      pool = created;
      settleReady(created);
      const names = created.names().join(", ");
      console.error(`drawbridge upstreams ready: ${names}`);
      return created;
    })
    .catch((error: unknown) => {
      const text = error instanceof Error ? error.message : String(error);
      failReady(error);
      if (!closed) {
        console.error(`drawbridge: upstream connection failed: ${text}`);
        void shutdown(1);
      }
      throw error;
    });

  console.error(`drawbridge ${sessionId}`);
  console.error(`drawbridge audit log ${config.audit.path}`);
  console.error("drawbridge listening on stdio (MCP 2026-07-28; legacy initialize is rejected)");

  const handle = serveStdio(
    () =>
      createGatewayServer({
        sessionId,
        policy,
        audit,
        pool: () => ready,
      }),
    {
      legacy: "reject",
      onerror: (error) => {
        console.error(`drawbridge: ${error.message}`);
      },
    },
  );

  let shuttingDown = false;
  async function shutdown(code: number): Promise<void> {
    if (shuttingDown) return;
    shuttingDown = true;
    closed = true;
    await handle.close().catch(() => undefined);
    await connecting.catch(() => undefined);
    await pool?.close().catch(() => undefined);
    await audit.close().catch(() => undefined);
    process.exit(code);
  }

  process.stdin.on("end", () => {
    void shutdown(0);
  });
  process.on("SIGINT", () => {
    void shutdown(0);
  });
  process.on("SIGTERM", () => {
    void shutdown(0);
  });
}
