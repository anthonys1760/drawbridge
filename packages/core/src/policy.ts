import type { AuditDecision, AuditMethod, AuditScanner, AuditTaint } from "./audit.js";

/**
 * Tool annotation hints copied from an upstream tool definition.
 * The spec says to treat these as untrusted unless the server is trusted.
 * Milestone 2's policy file wins over them; milestone 1 only passes them through.
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
}

export interface PreCallDecision {
  decision: AuditDecision;
  ruleId?: string;
  reason?: string;
}

/**
 * Runs after an upstream responds and before the result is returned.
 * Milestone 3's scanner and taint tracker plug in here. The returned `result`
 * is what the client sees. Throwing withholds the upstream payload.
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

/** Decisions that may be forwarded to an upstream. */
export function decisionForwards(decision: AuditDecision): boolean {
  return decision === "allow" || decision === "approved";
}
