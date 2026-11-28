import { open, readFile, mkdir, type FileHandle } from "node:fs/promises";
import { dirname } from "node:path";
import { z } from "zod";
import { AuditIntegrityError } from "./errors.js";
import { sha256, stableStringify } from "./hash.js";
import { ulid } from "./ulid.js";

/**
 * Audit event. Optional fields are omitted on the wire until the milestone
 * that writes them (scanner in milestone 3, approval in milestone 4).
 *
 * An allowed call is two records: an intent record written before the
 * upstream is contacted (no `resultHash` / `durationMs`), then an outcome
 * record written after. A denial is a single record and is not forwarded.
 *
 * `taint` is the session state before this event (what policy sees).
 * `taintAfter` is set only when this event changes that state, so replay can
 * show the flip on the event that introduced the untrusted content.
 * The normative write-up is docs/audit-schema.md. `verifyAuditJsonl` and
 * `JsonlAuditLog.open` (gateway startup) both use `auditEventSchema`.
 *
 * A decision that resolves an `approve_pending` record sets
 * `approval.pendingId` to that record's `id`. The pending record itself sets
 * `expiresAt`. Approvals are once-only, so a retry is a new pending record.
 */
export const scannerHitTargetSchema = z.enum(["args", "result", "description"]);
export const scannerVerdictSchema = z.enum(["clean", "flagged", "wrapped", "blocked"]);

/**
 * Bracket/dot field path. Identifiers, numeric indexes, or both:
 * `content[0].text`, `args.to`, `body`. Dot-numeric (`content.0.text`) is
 * not accepted; use brackets for indexes.
 */
export const HIT_PATH = /^(?:[A-Za-z_][A-Za-z0-9_]*)(?:\.[A-Za-z_][A-Za-z0-9_]*|\[(?:0|[1-9][0-9]*)\])*$/;

export const auditScannerHitSchema = z.strictObject({
  rule: z.string(),
  span: z.tuple([z.number(), z.number()]),
  target: scannerHitTargetSchema,
  path: z.string().regex(HIT_PATH),
});

export const auditScannerSchema = z.strictObject({
  verdict: scannerVerdictSchema,
  hits: z.array(auditScannerHitSchema),
});

export const auditApprovalSchema = z.strictObject({
  channel: z.enum(["elicitation", "dashboard", "cli"]).optional(),
  by: z.string().optional(),
  latencyMs: z.number().optional(),
  /** `id` of the `approve_pending` event this decision resolves. */
  pendingId: z.string().optional(),
});

export const auditTaintSchema = z.strictObject({
  tainted: z.boolean(),
  sources: z.array(z.string()),
});

export const auditEventSchema = z.strictObject({
  id: z.string(),
  ts: z.string(),
  sessionId: z.string(),
  client: z.strictObject({
    name: z.string().optional(),
    version: z.string().optional(),
  }),
  upstream: z.string(),
  method: z.enum(["tools/call", "tools/list", "resources/read", "prompts/get"]),
  tool: z.string().optional(),
  argsRedacted: z.unknown(),
  argsHash: z.string(),
  decision: z.enum(["allow", "deny", "approve_pending", "approved", "denied_by_human", "timeout"]),
  ruleId: z.string().optional(),
  reason: z.string().optional(),
  taint: auditTaintSchema,
  /** Session taint after this event. Omitted when it equals `taint`. */
  taintAfter: auditTaintSchema.optional(),
  scanner: auditScannerSchema.optional(),
  approval: auditApprovalSchema.optional(),
  /** ISO 8601 UTC. Set on `approve_pending` records. */
  expiresAt: z.string().optional(),
  /**
   * `id` of the intent line this outcome completes. Set on outcome lines of
   * a forwarded call so interleaved identical calls still pair. Approval
   * decisions use `approval.pendingId` instead, and do not repeat scanner hits.
   */
  intentId: z.string().optional(),
  resultHash: z.string().optional(),
  durationMs: z.number().optional(),
  prevHash: z.string(),
  hash: z.string(),
});

export type AuditEvent = z.infer<typeof auditEventSchema>;
export type AuditMethod = AuditEvent["method"];
export type AuditDecision = AuditEvent["decision"];
export type AuditTaint = z.infer<typeof auditTaintSchema>;
export type AuditScanner = z.infer<typeof auditScannerSchema>;
export type AuditScannerHit = z.infer<typeof auditScannerHitSchema>;
export type ScannerHitTarget = z.infer<typeof scannerHitTargetSchema>;
export type AuditApproval = z.infer<typeof auditApprovalSchema>;

/** Fields the gateway supplies. The log assigns id, ts, prevHash, and hash. */
export type NewAuditEvent = Omit<AuditEvent, "id" | "ts" | "prevHash" | "hash">;

/** Hash of a chain that has no previous event. 64 zero hex characters. */
export const GENESIS_HASH = "0".repeat(64);

/**
 * The value to store in `taintAfter`, or `undefined` when the session taint
 * did not change. Callers omit the field in that case.
 */
export function taintAfterIfChanged(before: AuditTaint, after: AuditTaint): AuditTaint | undefined {
  if (before.tainted === after.tainted && sameSources(before.sources, after.sources)) return undefined;
  return after;
}

function sameSources(left: string[], right: string[]): boolean {
  return left.length === right.length && left.every((source, index) => source === right[index]);
}

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

/**
 * sha256(prevHash + canonical JSON of the event with the hash field removed).
 *
 * The prefix is the raw prevHash hex with no separator. That same value is
 * also a field inside the JSON, because only `hash` is stripped. The first
 * event's prevHash is GENESIS_HASH. Canonical JSON is stableStringify.
 */
export function eventHash(event: Omit<AuditEvent, "hash">): string {
  return sha256(event.prevHash + stableStringify(event));
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
    const checked = auditEventSchema.safeParse(parsed);
    if (!checked.success) {
      // This is the schema `audit verify` and gateway startup both use.
      // Optional taintAfter and intentId are part of it. The detail names the
      // field that was missing, mistyped, or unknown.
      const detail = checked.error.issues
        .map((issue) => `${issue.path.join(".") || "(root)"}: ${issue.message}`)
        .join("; ");
      return { ok: false, events, error: `line is not an audit event (${detail})`, line: lineNumber };
    }
    const event = checked.data;
    if (event.prevHash !== previous) {
      return {
        ok: false,
        events,
        error: "prevHash does not match the previous event",
        line: lineNumber,
      };
    }
    const { hash, ...rest } = event;
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
