import { mkdtemp, rm, writeFile } from "node:fs/promises";
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
});
