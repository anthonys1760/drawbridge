import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  GENESIS_HASH,
  JsonlAuditLog,
  auditEventSchema,
  eventHash,
  sha256,
  stableStringify,
  ulid,
  verifyAuditJsonl,
  type NewAuditEvent,
} from "../src/index.js";

const dirs: string[] = [];

afterEach(async () => {
  await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("audit log", () => {
  it("links events and rejects a rewritten line", async () => {
    const dir = await mkdtemp(join(tmpdir(), "drawbridge-audit-"));
    dirs.push(dir);
    const path = join(dir, "audit.jsonl");
    const log = await JsonlAuditLog.open(path);
    const first = await log.append(sample("tools/list"));
    const second = await log.append(sample("tools/call", "notes__echo"));
    await log.close();

    expect(first.prevHash).toBe(GENESIS_HASH);
    expect(first.hash).toBe(eventHash(withoutHash(first)));
    expect(second.prevHash).toBe(first.hash);
    expect(first.id < second.id).toBe(true);

    const original = await readFile(path, "utf8");
    expect(verifyAuditJsonl(original).ok).toBe(true);

    const lines = original.trimEnd().split("\n");
    const tampered = JSON.parse(lines[0] ?? "{}") as { reason?: string };
    tampered.reason = "rewritten";
    lines[0] = JSON.stringify(tampered);
    const broken = verifyAuditJsonl(`${lines.join("\n")}\n`);
    expect(broken.ok).toBe(false);
    if (!broken.ok) expect(broken.line).toBe(1);

    const reopened = await JsonlAuditLog.open(path);
    const third = await reopened.append(sample("tools/call", "notes__read"));
    await reopened.close();
    expect(third.prevHash).toBe(second.hash);
  });

  it("detects a dropped middle line and a swapped prevHash", () => {
    const first = sealed(sample("tools/list"), GENESIS_HASH);
    const second = sealed(sample("tools/call", "notes__echo"), first.hash);
    const third = sealed(sample("tools/call", "notes__read"), second.hash);
    const ok = [first, second, third].map((event) => JSON.stringify(event)).join("\n") + "\n";
    expect(verifyAuditJsonl(ok).ok).toBe(true);

    const dropped = [first, third].map((event) => JSON.stringify(event)).join("\n") + "\n";
    expect(verifyAuditJsonl(dropped).ok).toBe(false);

    const swapped = { ...second, prevHash: GENESIS_HASH, hash: second.hash };
    const relinked = [first, swapped].map((event) => JSON.stringify(event)).join("\n") + "\n";
    expect(verifyAuditJsonl(relinked).ok).toBe(false);
  });

  it("hashes prevHash plus canonical JSON, and key order does not matter", () => {
    const first = sealed(sample("tools/list"), GENESIS_HASH);
    const { hash, ...rest } = first;
    const canonical = stableStringify(rest);
    expect(hash).toBe(sha256(rest.prevHash + canonical));
    expect(hash).not.toBe(sha256(canonical));
    expect(rest.prevHash).toBe(GENESIS_HASH);
    expect(GENESIS_HASH).toBe("0".repeat(64));

    const parsed = JSON.parse(stableStringify(first)) as Record<string, unknown>;
    const keys = Object.keys(parsed).reverse();
    const flipped = `{${keys.map((key) => `${JSON.stringify(key)}:${JSON.stringify(parsed[key])}`).join(",")}}`;
    expect(flipped.startsWith('{"hash"')).toBe(false);
    expect(verifyAuditJsonl(`${flipped}\n`).ok).toBe(true);
  });

  it("accepts pendingId, expiresAt, and a blocked scanner hit", () => {
    const pending = sealed(
      {
        ...sample("tools/call", "mail__send"),
        decision: "approve_pending",
        expiresAt: "2026-12-01T00:02:00.000Z",
        approval: { channel: "dashboard" },
      },
      GENESIS_HASH,
    );
    expect(auditEventSchema.parse(pending).expiresAt).toBe("2026-12-01T00:02:00.000Z");

    const decision = sealed(
      {
        ...sample("tools/call", "mail__send"),
        decision: "approved",
        approval: { channel: "dashboard", by: "anthony", latencyMs: 40, pendingId: pending.id },
        scanner: {
          verdict: "blocked",
          hits: [{ rule: "instruction-override", span: [1, 4], target: "args", path: "body" }],
        },
      },
      pending.hash,
    );
    const parsed = auditEventSchema.parse(decision);
    expect(parsed.approval?.pendingId).toBe(pending.id);
    expect(parsed.scanner?.verdict).toBe("blocked");
    expect(parsed.scanner?.hits[0]).toEqual({
      rule: "instruction-override",
      span: [1, 4],
      target: "args",
      path: "body",
    });

    const missingTarget = {
      ...decision,
      scanner: { verdict: "flagged", hits: [{ rule: "x", span: [0, 1], path: "body" }] },
    };
    expect(auditEventSchema.safeParse(missingTarget).success).toBe(false);
    const chain = [pending, decision].map((event) => JSON.stringify(event)).join("\n") + "\n";
    expect(verifyAuditJsonl(chain).ok).toBe(true);
  });
});

describe("ulid", () => {
  it("is monotonic inside one millisecond", () => {
    const now = Date.now();
    const a = ulid(now);
    const b = ulid(now);
    expect(a < b).toBe(true);
    expect(a).toHaveLength(26);
  });
});

function sample(method: NewAuditEvent["method"], tool?: string): NewAuditEvent {
  return {
    sessionId: "session",
    client: { name: "test", version: "0" },
    upstream: "notes",
    method,
    ...(tool ? { tool } : {}),
    argsRedacted: {},
    argsHash: "abc",
    decision: "allow",
    taint: { tainted: false, sources: [] },
    reason: "original",
  };
}

function sealed(event: NewAuditEvent, prevHash: string) {
  const without = {
    ...event,
    id: ulid(),
    ts: new Date().toISOString(),
    prevHash,
  };
  return { ...without, hash: eventHash(without) };
}

function withoutHash<T extends { hash: string }>(event: T): Omit<T, "hash"> {
  const { hash, ...rest } = event;
  void hash;
  return rest;
}
