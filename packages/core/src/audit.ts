import { open, readFile, mkdir, type FileHandle } from "node:fs/promises";
import { dirname } from "node:path";
import { AuditIntegrityError } from "./errors.js";
import { sha256, stableStringify } from "./hash.js";
import { ulid } from "./ulid.js";

/**
 * Audit event. Field names match the milestone schema. Optional fields are
 * omitted on the wire when they do not apply (no `scanner` until milestone 3,
 * no `approval` until milestone 4).
 *
 * An allowed call is two records: an intent record written before the
 * upstream is contacted (no `resultHash` / `durationMs`), then an outcome
 * record written after. A denial is a single record and is not forwarded.
 */
export interface AuditEvent {
  id: string;
  ts: string;
  sessionId: string;
  client: { name?: string; version?: string };
  upstream: string;
  method: AuditMethod;
  tool?: string;
  argsRedacted: unknown;
  argsHash: string;
  decision: AuditDecision;
  ruleId?: string;
  reason?: string;
  taint: AuditTaint;
  scanner?: AuditScanner;
  approval?: AuditApproval;
  resultHash?: string;
  durationMs?: number;
  prevHash: string;
  hash: string;
}

export type AuditMethod = "tools/call" | "tools/list" | "resources/read" | "prompts/get";

export type AuditDecision =
  | "allow"
  | "deny"
  | "approve_pending"
  | "approved"
  | "denied_by_human"
  | "timeout";

export interface AuditTaint {
  tainted: boolean;
  sources: string[];
}

export interface AuditScanner {
  verdict: "clean" | "flagged" | "wrapped";
  hits: { rule: string; span: [number, number] }[];
}

export interface AuditApproval {
  channel: "elicitation" | "dashboard" | "cli";
  by?: string;
  latencyMs: number;
}

/** Fields the gateway supplies. The log assigns id, ts, prevHash, and hash. */
export type NewAuditEvent = Omit<AuditEvent, "id" | "ts" | "prevHash" | "hash">;

/** Hash of a chain that has no previous event. 64 zero hex characters. */
export const GENESIS_HASH = "0".repeat(64);

export interface AuditVerifyOk {
  ok: true;
  events: number;
  lastHash: string;
}

export interface AuditVerifyFailure {
  ok: false;
  events: number;
  error: string;
  line?: number;
}

export type AuditVerifyResult = AuditVerifyOk | AuditVerifyFailure;

export function eventHash(event: Omit<AuditEvent, "hash">): string {
  return sha256(stableStringify(event));
}

export function verifyAuditJsonl(contents: string): AuditVerifyResult {
  if (contents.length === 0) return { ok: true, events: 0, lastHash: GENESIS_HASH };
  const lines = contents.split("\n");
  if (lines.at(-1) === "") lines.pop();
  let previous = GENESIS_HASH;
  let events = 0;
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    const lineNumber = index + 1;
    if (line.length === 0) {
      return { ok: false, events, error: "blank line in audit log", line: lineNumber };
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(line) as unknown;
    } catch {
      return { ok: false, events, error: "line is not valid JSON", line: lineNumber };
    }
    if (!isAuditEvent(parsed)) {
      return { ok: false, events, error: "line is not an audit event", line: lineNumber };
    }
    if (parsed.prevHash !== previous) {
      return {
        ok: false,
        events,
        error: "prevHash does not match the previous event",
        line: lineNumber,
      };
    }
    const { hash, ...rest } = parsed;
    const expected = eventHash(rest);
    if (expected !== hash) {
      return { ok: false, events, error: "hash does not match the event contents", line: lineNumber };
    }
    previous = hash;
    events += 1;
  }
  return { ok: true, events, lastHash: previous };
}

export interface AuditSink {
  append(event: NewAuditEvent): Promise<AuditEvent>;
}

/**
 * Append-only JSONL log. Writes are serialized and fsynced before `append`
 * resolves, so a caller can treat resolution as "this intent is durable".
 * Opening a file that fails verification throws; the gateway must not start.
 */
export class JsonlAuditLog implements AuditSink {
  private chain: Promise<void> = Promise.resolve();

  private constructor(
    private readonly handle: FileHandle,
    private lastHash: string,
  ) {}

  static async open(path: string): Promise<JsonlAuditLog> {
    await mkdir(dirname(path), { recursive: true });
    const existing = await readFile(path, "utf8").catch((error: NodeJS.ErrnoException) => {
      if (error.code === "ENOENT") return "";
      throw error;
    });
    const verified = verifyAuditJsonl(existing);
    if (!verified.ok) {
      throw new AuditIntegrityError(`Refusing to append to ${path}: ${verified.error} (line ${verified.line ?? "?"})`);
    }
    const handle = await open(path, "a");
    return new JsonlAuditLog(handle, verified.lastHash);
  }

  append(event: NewAuditEvent): Promise<AuditEvent> {
    const run = this.chain.then(() => this.write(event));
    this.chain = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  async close(): Promise<void> {
    await this.chain;
    await this.handle.close();
  }

  private async write(event: NewAuditEvent): Promise<AuditEvent> {
    const withoutHash: Omit<AuditEvent, "hash"> = {
      ...event,
      id: ulid(),
      ts: new Date().toISOString(),
      prevHash: this.lastHash,
    };
    const full: AuditEvent = { ...withoutHash, hash: eventHash(withoutHash) };
    await this.handle.write(`${stableStringify(full)}\n`);
    await this.handle.sync();
    this.lastHash = full.hash;
    return full;
  }
}

function isAuditEvent(value: unknown): value is AuditEvent {
  if (value === null || typeof value !== "object") return false;
  const event = value as Record<string, unknown>;
  return (
    typeof event.id === "string" &&
    typeof event.ts === "string" &&
    typeof event.sessionId === "string" &&
    typeof event.upstream === "string" &&
    typeof event.method === "string" &&
    typeof event.argsHash === "string" &&
    typeof event.decision === "string" &&
    typeof event.prevHash === "string" &&
    typeof event.hash === "string" &&
    event.taint !== null &&
    typeof event.taint === "object"
  );
}
