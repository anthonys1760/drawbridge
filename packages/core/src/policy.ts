import type { AuditDecision, AuditMethod, AuditScanner, AuditTaint } from "./audit.js";
import type { ArgConstraint, DrawbridgeConfig, PolicyAction, PolicyRule, RateLimitConfig } from "./config.js";
import { toolDefinitionHash, type PinFile, type ToolDefinition } from "./pins.js";
import { applyScanner } from "./scanner.js";

/**
 * Tool annotation hints copied from an upstream tool definition.
 * The spec says to treat these as untrusted unless the server is trusted.
 * The policy file wins over them. Untrusted servers are ignored.
 */
export interface ToolAnnotationHints {
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
  title?: string;
}

export interface PolicyClient {
  name?: string;
  version?: string;
}

/**
 * Runs before a call is forwarded. `allow` and `approved` may proceed.
 * Every other decision, and any thrown error, denies the call.
 */
export interface PreCallInput {
  sessionId: string;
  method: AuditMethod;
  upstream: string;
  tool?: string;
  args?: unknown;
  client: PolicyClient;
  trusted: boolean;
  annotations?: ToolAnnotationHints;
  /**
   * `ready` means tools/list succeeded. `unavailable` means it threw.
   * Omitted in unit tests that are not checking pins; pinTools then treats
   * a missing definition as a mismatch.
   */
  catalog?: "ready" | "unavailable";
  definition?: ToolDefinition;
}

/**
 * `approve` is the policy action. The audit log does not store that word:
 * the gateway writes `approve_pending` and then a linked `deny`.
 */
export type PolicyCallDecision = AuditDecision | "approve";

export interface PreCallDecision {
  decision: PolicyCallDecision;
  ruleId?: string;
  reason?: string;
  /** Session taint policy evaluated. Defaults to untainted when omitted. */
  taint?: AuditTaint;
  /** Set when `decision` is `approve`. The pending audit record stores this. */
  expiresAt?: string;
}

/**
 * Runs after an upstream responds and before the result is returned.
 * Milestone 3's scanner and taint tracker plug in here. The returned `result`
 * is what the client sees. Throwing withholds the upstream payload.
 *
 * `taint`, when set, is the session state after this result. The audit record
 * keeps `taint` as the state policy saw before the event, and sets
 * `taintAfter` only when this value differs. Milestone 1 does not carry that
 * update into the next event.
 */
export interface PostResultInput {
  sessionId: string;
  method: AuditMethod;
  upstream: string;
  tool?: string;
  result: unknown;
  trusted: boolean;
  client: PolicyClient;
}

export interface PostResultDecision {
  result: unknown;
  taint?: AuditTaint;
  scanner?: AuditScanner;
}

export interface PolicyEngine {
  preCall(input: PreCallInput): Promise<PreCallDecision>;
  postResult(input: PostResultInput): Promise<PostResultDecision>;
  /** Session taint the next preCall will evaluate. Untainted if omitted. */
  sessionTaint?(): AuditTaint;
}

const UNTAINTED: AuditTaint = { tainted: false, sources: [] };

/**
 * Milestone 1 stub. Every routed call is allowed. The rule id is written to
 * the audit log so a reader can see that no policy was enforced.
 */
export class AllowAllPolicy implements PolicyEngine {
  async preCall(): Promise<PreCallDecision> {
    return {
      decision: "allow",
      ruleId: "stub:allow-all",
      reason: "Milestone 1 policy stub allows every routed call",
    };
  }

  async postResult(input: PostResultInput): Promise<PostResultDecision> {
    return { result: input.result, taint: UNTAINTED };
  }
}

export const UNTAINTED_SESSION: AuditTaint = UNTAINTED;

/** Decisions that may be forwarded to an upstream. `approve` is held, not forwarded. */
export function decisionForwards(decision: PolicyCallDecision): boolean {
  return decision === "allow" || decision === "approved";
}

const ACTION_RANK: Record<PolicyAction, number> = { allow: 0, approve: 1, deny: 2 };

/**
 * `*` matches any sequence, `?` matches one character. Matching is anchored
 * and case-sensitive, so `notes__read` does not match `notes__reader`.
 */
export function toolGlobMatches(glob: string, name: string): boolean {
  let pattern = "^";
  for (const char of glob) {
    if (char === "*") pattern += ".*";
    else if (char === "?") pattern += ".";
    else pattern += /[\\^$+?.()|[\]{}]/.test(char) ? `\\${char}` : char;
  }
  return new RegExp(`${pattern}$`).test(name);
}

export interface PolicyRuntime {
  pins?: PinFile;
  now?: () => number;
  taint?: AuditTaint;
}

/**
 * First matching rule wins. A flow runs only when its `when` matches the
 * session taint and its tool glob matches, and it can only tighten the
 * decision (`deny` over `approve` over `allow`). Argument failures and
 * rate limits deny. Pin mismatches are decided before rules.
 *
 * Session taint starts untainted. A tool result from an untrusted upstream
 * marks the session tainted, and so does any scanner hit. `seedTaint` is for tests.
 */
export class YamlPolicy implements PolicyEngine {
  private taint: AuditTaint;
  private readonly toolMinute = new Map<string, number[]>();
  private readonly toolSession = new Map<string, number>();
  private sessionMinute: number[] = [];
  private sessionCount = 0;

  constructor(
    private readonly config: DrawbridgeConfig,
    private readonly runtime: PolicyRuntime = {},
  ) {
    this.taint = runtime.taint ?? { tainted: false, sources: [] };
  }

  seedTaint(taint: AuditTaint): void {
    this.taint = taint;
  }

  sessionTaint(): AuditTaint {
    return this.taint;
  }

  async preCall(input: PreCallInput): Promise<PreCallDecision> {
    if (input.method !== "tools/call" || input.tool === undefined) {
      return {
        decision: "allow",
        ruleId: "default:tools/list",
        reason: "Tool listing is audited and is not gated by tool rules",
        taint: this.taint,
      };
    }
    const upstream = this.config.upstreams.find((entry) => entry.name === input.upstream)?.upstream;
    if (upstream?.pinTools) {
      const pinned = this.pinDecision(input);
      if (pinned) return pinned;
    }
    return this.ruleDecision(input);
  }

  async postResult(input: PostResultInput): Promise<PostResultDecision> {
    const scanned = applyScanner(input.result, input.upstream, {
      mode: this.config.scanner.mode,
      scanDescriptions: this.config.scanner.scanDescriptions,
      allowlist: this.config.scanner.allowlist,
      ...(this.runtime.now ? { now: this.runtime.now() } : {}),
    });
    if ((!input.trusted && input.method === "tools/call") || scanned.scanner) {
      this.markTainted(input.upstream);
    }
    return {
      result: scanned.result,
      taint: this.taint,
      ...(scanned.scanner ? { scanner: scanned.scanner } : {}),
    };
  }

  private markTainted(upstream: string): void {
    const sources = this.taint.sources.includes(upstream) ? this.taint.sources : [...this.taint.sources, upstream];
    this.taint = { tainted: true, sources };
  }

  private pinDecision(input: PreCallInput): PreCallDecision | undefined {
    const tool = input.tool ?? "";
    const expected = this.runtime.pins?.tools[tool];
    const actual = input.catalog === "ready" && input.definition ? toolDefinitionHash(input.definition) : undefined;
    if (input.catalog === "ready" && actual !== undefined && expected !== undefined && actual === expected) {
      return undefined;
    }
    const upstream = this.config.upstreams.find((entry) => entry.name === input.upstream)?.upstream;
    const action = upstream?.onPinMismatch ?? "deny";
    const reason =
      input.catalog === "unavailable"
        ? `Could not list tools for "${input.upstream}", so the pin for ${tool} could not be checked.`
        : `Tool definition for ${tool} does not match the pinned hash.`;
    return this.finish(action, `pin:${tool}`, reason, undefined);
  }

  private ruleDecision(input: PreCallInput): PreCallDecision {
    const tool = input.tool ?? "";
    let action: PolicyAction = this.config.defaults.action;
    let ruleId = `default:${action}`;
    let reason = `No rule matched ${tool}; default is ${action}`;
    let matched: PolicyRule | undefined;
    let ruleLimit: RateLimitConfig | undefined;

    for (const [index, rule] of this.config.rules.entries()) {
      if (!toolGlobMatches(rule.tool, tool)) continue;
      matched = rule;
      action = rule.action;
      ruleId = `rule:${index}`;
      reason = `Matched rule ${index} (${rule.tool})`;
      ruleLimit = rule.rateLimit;
      break;
    }

    if (matched && matched.action !== "deny" && matched.args) {
      const problem = argumentProblem(input.args, matched.args);
      if (problem) return { decision: "deny", ruleId, reason: problem, taint: this.taint };
    }

    if (!matched && input.trusted && this.config.defaults.fromAnnotations) {
      if (input.annotations?.destructiveHint === true) {
        action = "approve";
        ruleId = "annotation:destructiveHint";
        reason = "Trusted server annotation destructiveHint";
      } else if (input.annotations?.readOnlyHint === true) {
        action = "allow";
        ruleId = "annotation:readOnlyHint";
        reason = "Trusted server annotation readOnlyHint";
      }
    }

    for (const flow of this.config.flows) {
      if (flow.when.sessionTainted !== this.taint.tainted) continue;
      if (!flow.tools.some((pattern) => toolGlobMatches(pattern, tool))) continue;
      if (ACTION_RANK[flow.action] > ACTION_RANK[action]) {
        action = flow.action;
        ruleId = `flow:${flow.name}`;
        reason = flow.reason ?? `Matched flow ${flow.name}`;
      }
      break;
    }

    return this.finish(action, ruleId, reason, ruleLimit, tool);
  }

  private finish(
    action: PolicyAction,
    ruleId: string,
    reason: string,
    ruleLimit: RateLimitConfig | undefined,
    tool?: string,
  ): PreCallDecision {
    if (action === "deny") {
      return { decision: "deny", ruleId, reason, taint: this.taint };
    }
    if (tool !== undefined) {
      const limited = this.consume(tool, ruleLimit);
      if (!limited.ok) {
        const scope = limited.scope === "session" ? "session" : tool;
        return {
          decision: "deny",
          ruleId: limited.scope === "session" ? "rate:session" : `rate:${tool}`,
          reason: `Rate limit exceeded for ${scope}`,
          taint: this.taint,
        };
      }
    }
    if (action === "approve") {
      const expiresAt = new Date(this.now() + this.config.approval.timeoutSeconds * 1000).toISOString();
      return { decision: "approve", ruleId, reason, taint: this.taint, expiresAt };
    }
    return { decision: "allow", ruleId, reason, taint: this.taint };
  }

  private consume(tool: string, ruleLimit: RateLimitConfig | undefined): { ok: true } | { ok: false; scope: "tool" | "session" } {
    const now = this.now();
    const defaults = this.config.defaults.rateLimit;
    const toolHits = prune(this.toolMinute.get(tool) ?? [], now);
    if (ruleLimit?.perMinute !== undefined && toolHits.length >= ruleLimit.perMinute) {
      return { ok: false, scope: "tool" };
    }
    if (ruleLimit?.perSession !== undefined && (this.toolSession.get(tool) ?? 0) >= ruleLimit.perSession) {
      return { ok: false, scope: "tool" };
    }
    const sessionHits = prune(this.sessionMinute, now);
    if (defaults?.perMinute !== undefined && sessionHits.length >= defaults.perMinute) {
      return { ok: false, scope: "session" };
    }
    if (defaults?.perSession !== undefined && this.sessionCount >= defaults.perSession) {
      return { ok: false, scope: "session" };
    }
    toolHits.push(now);
    this.toolMinute.set(tool, toolHits);
    this.toolSession.set(tool, (this.toolSession.get(tool) ?? 0) + 1);
    sessionHits.push(now);
    this.sessionMinute = sessionHits;
    this.sessionCount += 1;
    return { ok: true };
  }

  private now(): number {
    return this.runtime.now ? this.runtime.now() : Date.now();
  }
}

function prune(times: number[], now: number): number[] {
  return times.filter((time) => now - time < 60_000);
}

function argumentProblem(args: unknown, constraints: Record<string, ArgConstraint>): string | undefined {
  const record = asRecord(args);
  for (const [key, constraint] of Object.entries(constraints)) {
    if (!Object.hasOwn(record, key)) return `Argument "${key}" is required by this rule`;
    const value = record[key];
    const items = Array.isArray(value) ? value : [value];
    if (items.length === 0) return `Argument "${key}" is required by this rule`;
    for (const item of items) {
      if (typeof item !== "string") return `Argument "${key}" must be a string`;
      if (constraint.maxLength !== undefined && item.length > constraint.maxLength) {
        return `Argument "${key}" exceeds maxLength ${constraint.maxLength}`;
      }
      if (constraint.pattern !== undefined && !new RegExp(constraint.pattern).test(item)) {
        return `Argument "${key}" does not match ${constraint.pattern}`;
      }
      if (constraint.enum !== undefined && !constraint.enum.includes(item)) {
        return `Argument "${key}" must be one of ${constraint.enum.join(", ")}`;
      }
      if (constraint.allowDomains !== undefined) {
        const domain = recipientDomain(item);
        const allowed = constraint.allowDomains.some((entry) => entry.toLowerCase() === domain);
        if (!allowed) return `Argument "${key}" domain is not allowed`;
      }
    }
  }
  return undefined;
}

function asRecord(args: unknown): Record<string, unknown> {
  if (args !== null && typeof args === "object" && !Array.isArray(args)) return args as Record<string, unknown>;
  return {};
}

function recipientDomain(value: string): string | undefined {
  const at = value.lastIndexOf("@");
  if (at <= 0 || at === value.length - 1) return undefined;
  return value.slice(at + 1).toLowerCase();
}
