import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { JsonlAuditLog, verifyAuditJsonl, type PolicyEngine } from "@drawbridge/core";
import { handleToolCall, type GatewayDeps } from "../src/dispatch.js";
import type { CatalogTool, UpstreamPool } from "../src/upstreams.js";

const dirs: string[] = [];

afterEach(async () => {
  await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("handleToolCall", () => {
  it("forwards raw arguments and writes a redacted intent before the call", async () => {
    const pool = new FakePool();
    const { deps, path, close } = await depsWith(pool);
    const result = await handleToolCall(deps, {
      name: "notes__echo",
      args: { message: "hi", token: "super-secret" },
      client: { name: "unit", version: "1" },
    });
    await close();

    expect(pool.calls).toEqual([{ upstream: "notes", tool: "echo", args: { message: "hi", token: "super-secret" } }]);
    expect(text(result)).toContain("super-secret");
    const log = await import("node:fs/promises").then((fs) => fs.readFile(path, "utf8"));
    expect(log).not.toContain("super-secret");
    expect(log).toContain("[REDACTED]");
    expect(verifyAuditJsonl(log).ok).toBe(true);
    const events = log.trimEnd().split("\n").map((line) => JSON.parse(line) as { resultHash?: string; tool?: string });
    expect(events).toHaveLength(2);
    expect(events[0]?.resultHash).toBeUndefined();
    expect(events[1]?.resultHash).toEqual(expect.any(String));
    expect(events[1]?.prevHash).toBe(events[0]?.hash);
  });

  it("does not call the upstream when policy denies or the audit write fails", async () => {
    const denied = new FakePool();
    const denying: PolicyEngine = {
      async preCall() {
        return { decision: "deny", ruleId: "test:deny", reason: "nope" };
      },
      async postResult(input) {
        return { result: input.result };
      },
    };
    const denyDeps = await depsWith(denied, denying);
    const deniedResult = await handleToolCall(denyDeps.deps, {
      name: "notes__echo",
      args: { message: "x" },
      client: {},
    });
    await denyDeps.close();
    expect(denied.calls).toHaveLength(0);
    expect(text(deniedResult)).toContain("nope");

    const blocked = new FakePool();
    const failing: GatewayDeps = {
      sessionId: "s",
      policy: denying,
      audit: {
        async append() {
          throw new Error("disk full");
        },
      },
      pool: async () => blocked,
    };
    // Policy would deny anyway. Use an allow policy so the only stop is the audit write.
    failing.policy = {
      async preCall() {
        return { decision: "allow", ruleId: "stub", reason: "ok" };
      },
      async postResult(input) {
        return { result: input.result };
      },
    };
    const blockedResult = await handleToolCall(failing, {
      name: "notes__echo",
      args: { message: "x" },
      client: {},
    });
    expect(blocked.calls).toHaveLength(0);
    expect(text(blockedResult)).toContain("audit log write failed");
  });
});

class FakePool implements UpstreamPool {
  calls: { upstream: string; tool: string; args: Record<string, unknown> }[] = [];

  names(): string[] {
    return ["notes"];
  }

  trusted(): boolean {
    return false;
  }

  annotations(): undefined {
    return undefined;
  }

  async listTools(): Promise<CatalogTool[]> {
    return [{ name: "echo", inputSchema: { type: "object" } }];
  }

  async callTool(upstream: string, tool: string, args: Record<string, unknown>) {
    this.calls.push({ upstream, tool, args });
    return { content: [{ type: "text" as const, text: JSON.stringify(args) }] };
  }

  async close(): Promise<void> {}
}

async function depsWith(pool: UpstreamPool, policy?: PolicyEngine) {
  const dir = await mkdtemp(join(tmpdir(), "drawbridge-dispatch-"));
  dirs.push(dir);
  const path = join(dir, "audit.jsonl");
  const audit = await JsonlAuditLog.open(path);
  const deps: GatewayDeps = {
    sessionId: "session-1",
    policy: policy ?? {
      async preCall() {
        return { decision: "allow", ruleId: "stub:allow-all", reason: "allow" };
      },
      async postResult(input) {
        return { result: input.result };
      },
    },
    audit,
    pool: async () => pool,
  };
  return { deps, path, close: () => audit.close() };
}

function text(result: { content: { text?: string }[] }): string {
  return result.content.map((block) => block.text ?? "").join("\n");
}
