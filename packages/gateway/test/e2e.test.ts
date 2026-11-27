import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer, type Server as HttpServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport, getDefaultEnvironment } from "@modelcontextprotocol/client/stdio";
import { localhostHostValidation, localhostOriginValidation, toNodeHandler } from "@modelcontextprotocol/node";
import { McpServer, createMcpHandler } from "@modelcontextprotocol/server";
import { spawn } from "node:child_process";
import { afterEach, describe, expect, it } from "vitest";
import { z } from "zod";
import { verifyAuditJsonl } from "@drawbridge/core";

const root = fileURLToPath(new URL("../../..", import.meta.url));
const cli = join(root, "packages/gateway/dist/cli.js");
const demo = join(root, "examples/demo-upstream/dist/index.js");
const TOKEN = "test-token-value";
const SECRET = "super-secret-token";

const cleanups: Array<() => Promise<void>> = [];

afterEach(async () => {
  await Promise.all(cleanups.splice(0).map((cleanup) => cleanup()));
});

describe("gateway e2e", () => {
  it("namespaces tools, forwards calls, and detects audit tampering", async () => {
    const dir = await mkdtemp(join(tmpdir(), "drawbridge-e2e-"));
    cleanups.push(() => rm(dir, { recursive: true, force: true }));
    const auditPath = join(dir, "audit.jsonl");
    const configPath = join(dir, "drawbridge.yaml");
    const remote = await startRemote();
    const { writeFile } = await import("node:fs/promises");
    await writeFile(
      configPath,
      `version: 1
audit:
  path: ${auditPath}
upstreams:
  notes:
    transport: stdio
    command: ["${process.execPath}", "${demo}"]
  remote:
    transport: http
    url: ${remote.url}
    headers:
      Authorization: Bearer \${REMOTE_TOKEN}
`,
    );

    const stderr: string[] = [];
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [cli, "serve", "--config", configPath],
      env: { ...getDefaultEnvironment(), REMOTE_TOKEN: TOKEN },
      stderr: "pipe",
    });
    transport.stderr?.on("data", (chunk: Buffer | string) => {
      stderr.push(typeof chunk === "string" ? chunk : chunk.toString());
    });
    const client = new Client(
      { name: "e2e-client", version: "9.0.0" },
      { versionNegotiation: { mode: { pin: "2026-07-28" } } },
    );
    cleanups.push(async () => {
      const pid = transport.pid ?? undefined;
      await client.close().catch(() => undefined);
      if (pid !== undefined) await waitForExit(pid);
    });
    try {
      await client.connect(transport);
    } catch (error) {
      throw new Error(`${error instanceof Error ? error.message : String(error)}\n${stderr.join("")}`);
    }

    const listed = await client.listTools();
    const names = listed.tools.map((tool) => tool.name).sort();
    expect(names).toEqual(["notes__echo", "notes__read", "remote__ping"]);
    const read = listed.tools.find((tool) => tool.name === "notes__read");
    expect(read?.inputSchema).toMatchObject({
      type: "object",
      properties: { path: { type: "string" } },
    });
    expect(read?.annotations).toMatchObject({ readOnlyHint: true });

    const echoed = await client.callTool({
      name: "notes__echo",
      arguments: { message: "hello", token: SECRET },
    });
    expect(text(echoed)).toContain("hello");
    expect(text(echoed)).toContain(SECRET);

    const note = await client.callTool({ name: "notes__read", arguments: { path: "notes/a.md" } });
    expect(text(note)).toBe("note:notes/a.md");

    const ping = await client.callTool({ name: "remote__ping", arguments: {} });
    expect(text(ping)).toBe("pong");
    expect(remote.authorizations).toContain(`Bearer ${TOKEN}`);

    const unknown = await client.callTool({ name: "nope", arguments: {} });
    expect(unknown.isError).toBe(true);

    const pid = transport.pid ?? undefined;
    await client.close();
    if (pid !== undefined) await waitForExit(pid);

    const log = await readFile(auditPath, "utf8");
    expect(log).toContain("e2e-client");
    expect(log).toContain("notes__echo");
    expect(log).toContain("[REDACTED]");
    expect(log).not.toContain(SECRET);
    const verified = verifyAuditJsonl(log);
    expect(verified.ok).toBe(true);

    const verify = await runCli(["audit", "verify", "--log", auditPath]);
    expect(verify.status).toBe(0);
    expect(verify.stdout).toMatch(/audit verify ok:/);

    const lines = log.trimEnd().split("\n");
    const event = JSON.parse(lines[0] ?? "{}") as { reason?: string };
    event.reason = "tampered";
    lines[0] = JSON.stringify(event);
    await writeFile(auditPath, `${lines.join("\n")}\n`);
    const failed = await runCli(["audit", "verify", "--log", auditPath]);
    expect(failed.status).toBe(1);
    expect(failed.stderr).toMatch(/hash does not match/);
    expect(stderr.join("")).not.toContain(SECRET);
  }, 30_000);
});

function text(result: { content: { type: string; text?: string }[] }): string {
  return result.content.map((block) => block.text ?? "").join("\n");
}

async function startRemote(): Promise<{ url: string; authorizations: string[]; close: () => Promise<void> }> {
  const authorizations: string[] = [];
  const handler = createMcpHandler(
    () => {
      const server = new McpServer({ name: "remote-demo", version: "0.1.0" });
      server.registerTool(
        "ping",
        {
          description: "Ping the remote demo",
          annotations: { readOnlyHint: true },
          inputSchema: z.object({}),
        },
        async () => ({ content: [{ type: "text", text: "pong" }] }),
      );
      return server;
    },
    { legacy: "reject" },
  );
  const nodeHandler = toNodeHandler(handler);
  const validateHost = localhostHostValidation();
  const validateOrigin = localhostOriginValidation();
  const http: HttpServer = createServer((req, res) => {
    const auth = req.headers.authorization;
    if (typeof auth === "string") authorizations.push(auth);
    if (!validateHost(req, res) || !validateOrigin(req, res)) return;
    void nodeHandler(req, res);
  });
  await new Promise<void>((resolve) => http.listen(0, "127.0.0.1", () => resolve()));
  const address = http.address();
  if (address === null || typeof address === "string") throw new Error("remote fixture failed to bind");
  const url = `http://127.0.0.1:${address.port}/mcp`;
  const close = () =>
    new Promise<void>((resolve, reject) => {
      http.close((error) => (error ? reject(error) : resolve()));
    });
  cleanups.push(close);
  return { url, authorizations, close };
}

function runCli(args: string[]): Promise<{ status: number; stdout: string; stderr: string }> {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(process.execPath, [cli, ...args], { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
    });
    child.on("error", reject);
    child.on("close", (status) => resolvePromise({ status: status ?? 1, stdout, stderr }));
  });
}

async function waitForExit(pid: number): Promise<void> {
  const started = Date.now();
  while (Date.now() - started < 5_000) {
    try {
      process.kill(pid, 0);
    } catch {
      return;
    }
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 50));
  }
}
