import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ApprovalHub, startApprovalServer } from "../src/approvals.js";

const cleanups: Array<() => Promise<void>> = [];

afterEach(async () => {
  await Promise.all(cleanups.splice(0).map((cleanup) => cleanup()));
});

describe("local approval server", () => {
  it("requires the per-run token and the drawbridge request header", async () => {
    const dir = await mkdtemp(join(tmpdir(), "drawbridge-http-"));
    const auditPath = join(dir, "audit.jsonl");
    await writeFile(auditPath, "");
    const server = await startApprovalServer({
      hub: new ApprovalHub(),
      auditPath,
      sessionId: "session-http",
      channels: ["elicitation", "dashboard", "cli"],
    });
    cleanups.push(async () => {
      await server.close();
      await rm(dir, { recursive: true, force: true });
    });

    expect(server.url.startsWith("http://127.0.0.1:")).toBe(true);

    const missing = await fetch(new URL("/api/state", server.url));
    expect(missing.status).toBe(401);

    const crossSite = await fetch(new URL("/api/decide", server.url), {
      method: "POST",
      headers: {
        Authorization: `Bearer ${server.token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ id: "missing", action: "deny" }),
    });
    expect(crossSite.status).toBe(403);

    const unknown = await fetch(new URL("/api/decide", server.url), {
      method: "POST",
      headers: {
        Authorization: `Bearer ${server.token}`,
        "X-Drawbridge-Request": "1",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ id: "missing", action: "deny", channel: "dashboard" }),
    });
    expect(unknown.status).toBe(409);

    const page = await fetch(new URL(`/?token=${server.token}`, server.url), { redirect: "manual" });
    expect(page.status).toBe(302);
    expect(page.headers.get("set-cookie")).toContain("db_token=");
    const home = await fetch(new URL("/", server.url), { headers: { cookie: `db_token=${server.token}` } });
    const html = await home.text();
    expect(home.status).toBe(200);
    expect(html).toContain("Drawbridge");
    expect(html).not.toMatch(/https?:\/\/(?!127\.0\.0\.1)/);
  });

  it("persists pause and auto-denies a held call without returning the secret", async () => {
    const dir = await mkdtemp(join(tmpdir(), "drawbridge-pause-http-"));
    const auditPath = join(dir, "audit.jsonl");
    await writeFile(auditPath, "");
    const hub = new ApprovalHub();
    const secret = "seed-pause-secret-ffff";
    const commits: { cause?: string; action?: string }[] = [];
    hub.open(
      {
        id: "pending-1",
        tool: "mail__send",
        upstream: "mail",
        sessionId: "session-http",
        reason: "held",
        taint: { tainted: true, sources: ["notes"] },
        argsRedacted: { token: "[REDACTED]" },
        argsHash: "abc",
        expiresAt: "2099-01-01T00:00:00.000Z",
        ts: new Date().toISOString(),
        client: { name: "unit" },
      },
      "inline",
      async (resolution) => {
        commits.push(resolution);
        return "event-1";
      },
    );
    const server = await startApprovalServer({
      hub,
      auditPath,
      sessionId: "session-http",
      channels: ["dashboard", "cli"],
    });
    cleanups.push(async () => {
      await server.close();
      await rm(dir, { recursive: true, force: true });
    });
    const response = await fetch(new URL("/api/pause", server.url), {
      method: "POST",
      headers: {
        Authorization: `Bearer ${server.token}`,
        "X-Drawbridge-Request": "1",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ paused: true, channel: "cli", token: secret }),
    });
    const body = await response.text();
    expect(response.status).toBe(200);
    expect(body).not.toContain(secret);
    expect(hub.paused).toBe(true);
    expect(hub.list()).toHaveLength(0);
    expect(commits[0]).toMatchObject({ action: "deny", cause: "pause" });
    const file = JSON.parse(await readFile(join(dir, "drawbridge-pause.json"), "utf8")) as { paused?: boolean };
    expect(file.paused).toBe(true);
  });
});
