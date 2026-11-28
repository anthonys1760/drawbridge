import {
  AllowAllPolicy,
  UNTAINTED_SESSION,
  decisionForwards,
  isOutboundTool,
  namespaceTool,
  parseNamespacedTool,
  credentialNote,
  redact,
  sha256,
  stripClientCredentials,
  stableStringify,
  taintAfterIfChanged,
  type AuditEvent,
  type AuditScanner,
  type AuditSink,
  type AuditTaint,
  type NewAuditEvent,
  type PolicyCallDecision,
  type PolicyClient,
  type PolicyEngine,
} from "@drawbridge/core";
import { inputRequired, inputResponse, type CallToolResult } from "@modelcontextprotocol/server";
import { z } from "zod";
import { ApprovalHub, type ApprovalChannel, type PendingView } from "./approvals.js";
import type { CatalogTool, JsonObjectSchema, UpstreamPool } from "./upstreams.js";

const BLOCKED = "Blocked by policy";
const CONFIRM = z.object({ approve: z.boolean() });

const UNROUTED = "_unrouted";

export interface ApprovalSettings {
  channels: ApprovalChannel[];
  highRisk: "dashboard-only";
  timeoutSeconds: number;
}

export interface GatewayDeps {
  sessionId: string;
  policy: PolicyEngine;
  audit: AuditSink;
  pool: () => Promise<UpstreamPool>;
  approvals: ApprovalHub;
  approval: ApprovalSettings;
  /**
   * Re-read drawbridge-pause.json and update `approvals.paused`.
   * A throw fail-closes: the gateway stays paused.
   */
  refreshPause?: () => Promise<void>;
}

export interface ToolCallContext {
  /** Signed pending id from a previous input-required round. */
  approvalState?: string;
  inputResponses?: Record<string, unknown>;
  /** True when the client declared the elicitation capability. */
  elicitation?: boolean;
}

export interface ListedTool {
  name: string;
  description?: string;
  title?: string;
  inputSchema: JsonObjectSchema;
  outputSchema?: Record<string, unknown>;
  annotations?: CatalogTool["annotations"];
}

/**
 * Aggregate every upstream catalog under `<upstream>__<tool>`.
 * A failed upstream list fails the whole request (no partial catalog).
 * A failed audit write fails the request before that upstream is contacted.
 */
export async function handleToolsList(
  deps: GatewayDeps,
  input: { client: PolicyClient },
): Promise<{ tools: ListedTool[] }> {
  await syncPause(deps);
  if (deps.approvals.paused) {
    throw new Error("All calls paused");
  }
  const pool = await deps.pool();
  const tools: ListedTool[] = [];
  for (const upstream of pool.names()) {
    const pre = await safePreCall(deps.policy, {
      sessionId: deps.sessionId,
      method: "tools/list",
      upstream,
      args: {},
      client: input.client,
      trusted: pool.trusted(upstream),
    });
    const base = eventBase(deps, {
      client: input.client,
      upstream,
      method: "tools/list",
      args: {},
      decision: pre.decision === "approve" ? "approve_pending" : pre.decision,
      ruleId: pre.ruleId,
      reason: pre.reason,
      taint: pre.taint,
    });
    if (!decisionForwards(pre.decision)) {
      await appendOrThrow(deps.audit, base);
      continue;
    }
    const intent = await appendOrThrow(deps.audit, base);
    const started = Date.now();
    let listed: CatalogTool[];
    try {
      listed = await pool.listTools(upstream);
    } catch (error) {
      const failure = `tools/list failed for upstream "${upstream}": ${message(error)}`;
      await appendOrThrow(deps.audit, {
        ...base,
        intentId: intent.id,
        reason: failure,
        resultHash: sha256(stableStringify({ error: failure })),
        durationMs: Date.now() - started,
      });
      throw new Error(failure);
    }
    let scanner = undefined;
    let taintAfter: AuditTaint | undefined;
    try {
      const post = await deps.policy.postResult({
        sessionId: deps.sessionId,
        method: "tools/list",
        upstream,
        result: { tools: listed },
        trusted: pool.trusted(upstream),
        client: input.client,
      });
      if (isToolCatalog(post.result)) listed = post.result.tools as CatalogTool[];
      if (post.taint) taintAfter = taintAfterIfChanged(base.taint, post.taint);
      if (post.scanner) scanner = post.scanner;
    } catch (error) {
      const failure = `post-result hook failed for upstream "${upstream}": ${message(error)}`;
      await appendOrThrow(deps.audit, {
        ...base,
        intentId: intent.id,
        decision: "deny",
        ruleId: "hook:post-result",
        reason: failure,
        resultHash: sha256(stableStringify({ error: failure })),
        durationMs: Date.now() - started,
      });
      throw new Error(failure);
    }
    await appendOrThrow(deps.audit, {
      ...base,
      intentId: intent.id,
      ...(taintAfter ? { taintAfter } : {}),
      ...(scanner ? { scanner } : {}),
      resultHash: sha256(stableStringify(listed.map((tool) => tool.name))),
      durationMs: Date.now() - started,
    });
    tools.push(
      ...listed.map((tool) => ({
        name: namespaceTool(upstream, tool.name),
        ...(tool.description !== undefined ? { description: tool.description } : {}),
        ...(tool.title !== undefined ? { title: tool.title } : {}),
        inputSchema: tool.inputSchema,
        ...(tool.outputSchema !== undefined ? { outputSchema: tool.outputSchema } : {}),
        ...(tool.annotations !== undefined ? { annotations: tool.annotations } : {}),
      })),
    );
  }
  return { tools };
}

/**
 * Forward one namespaced tools/call.
 * Order: route, policy, durable intent, forward, post-result, durable outcome.
 * The intent record is fsynced before the upstream is contacted. If that
 * write fails the call is not forwarded.
 */
export async function handleToolCall(
  deps: GatewayDeps,
  input: { name: string; args: Record<string, unknown>; client: PolicyClient },
  ctx: ToolCallContext = {},
): Promise<CallToolResult> {
  const stripped = stripClientCredentials(input.args);
  const note = credentialNote(stripped.paths);
  const forward = { ...input, args: stripped.args };
  await syncPause(deps);
  if (deps.approvals.paused) {
    return denyPaused(deps, input, note);
  }
  let pool: UpstreamPool;
  try {
    pool = await deps.pool();
  } catch (error) {
    return deny(deps, {
      client: input.client,
      upstream: UNROUTED,
      tool: input.name,
      args: input.args,
      decision: "deny",
      ruleId: "upstream:unavailable",
      reason: `upstreams unavailable: ${message(error)}`,
      ...(note ? { credentialNote: note } : {}),
    });
  }

  const routed = parseNamespacedTool(input.name, new Set(pool.names()));
  if (!routed) {
    return deny(deps, {
      client: input.client,
      upstream: UNROUTED,
      tool: input.name,
      args: input.args,
      decision: "deny",
      ruleId: "router:unknown-tool",
      reason: `Unknown tool "${input.name}". Tools are named <upstream>__<tool>.`,
      ...(note ? { credentialNote: note } : {}),
    });
  }

  const echoed = deps.approvals.verify(ctx.approvalState);
  if (echoed) {
    return resumeApproval(deps, pool, echoed, routed, forward, ctx);
  }

  let catalog: "ready" | "unavailable" = "ready";
  let definition: CatalogTool | undefined;
  try {
    const listed = await pool.listTools(routed.upstream);
    definition = listed.find((tool) => tool.name === routed.tool);
  } catch {
    catalog = "unavailable";
  }
  const pre = await safePreCall(deps.policy, {
    sessionId: deps.sessionId,
    method: "tools/call",
    upstream: routed.upstream,
    tool: input.name,
    args: forward.args,
    client: input.client,
    trusted: pool.trusted(routed.upstream),
    annotations: definition?.annotations ?? pool.annotations(routed.upstream, routed.tool),
    catalog,
    definition,
  });
  const baseFields = {
    client: input.client,
    upstream: routed.upstream,
    method: "tools/call" as const,
    tool: input.name,
    args: input.args,
    ruleId: pre.ruleId,
    reason: pre.reason,
    taint: pre.taint,
    ...(note ? { credentialNote: note } : {}),
  };
  if (pre.decision === "approve") {
    return holdForApproval(deps, pool, eventBase(deps, { ...baseFields, decision: "approve_pending" }), pre, forward, ctx);
  }
  const base = eventBase(deps, { ...baseFields, decision: pre.decision });
  if (!decisionForwards(pre.decision)) {
    const recorded = await appendQuiet(deps.audit, base);
    if (!recorded.ok) {
      return textError(`audit log write failed; call denied (${recorded.error})`);
    }
    return textError(pre.reason ?? `Call denied (${pre.decision})`);
  }

  const recorded = await appendQuiet(deps.audit, base);
  if (!recorded.ok) {
    return textError(`audit log write failed; call denied (${recorded.error})`);
  }
  await syncPause(deps);
  if (deps.approvals.paused) {
    await appendQuiet(deps.audit, {
      ...base,
      intentId: recorded.event.id,
      decision: "deny",
      ruleId: "kill:paused",
      reason: "All calls paused",
    });
    return textError("All calls paused");
  }

  const started = Date.now();
  let result: CallToolResult;
  try {
    result = await pool.callTool(routed.upstream, routed.tool, forward.args);
  } catch (error) {
    result = textError(`upstream "${routed.upstream}" error: ${message(error)}`);
  }

  let finalResult = result;
  let scanner = undefined;
  let taintAfter: AuditTaint | undefined;
  try {
    const post = await deps.policy.postResult({
      sessionId: deps.sessionId,
      method: "tools/call",
      upstream: routed.upstream,
      tool: input.name,
      result,
      trusted: pool.trusted(routed.upstream),
      client: input.client,
    });
    finalResult = asToolResult(post.result, result);
    if (post.taint) taintAfter = taintAfterIfChanged(base.taint, post.taint);
    if (post.scanner) scanner = post.scanner;
  } catch (error) {
    finalResult = textError(`post-result hook failed; result withheld (${message(error)})`);
  }

  // resultHash covers the result returned to the client. In wrap mode (milestone 3)
  // that is the wrapped result, and scanner spans index that same text.
  const outcome = await appendQuiet(deps.audit, {
    ...base,
    intentId: recorded.event.id,
    ...(taintAfter ? { taintAfter } : {}),
    ...(scanner ? { scanner } : {}),
    resultHash: sha256(stableStringify(finalResult)),
    durationMs: Date.now() - started,
  });
  if (!outcome.ok) {
    return textError(`audit log write failed after the upstream responded; result withheld (${outcome.error})`);
  }
  return finalResult;
}

export function createDefaultPolicy(): PolicyEngine {
  return new AllowAllPolicy();
}

/**
 * Record approve_pending and wait. A human decision links with
 * approval.pendingId and does not copy scanner hits. Approving once does
 * not allow the next identical call. High-risk sends skip in-client
 * elicitation when highRisk is dashboard-only.
 */
async function holdForApproval(
  deps: GatewayDeps,
  pool: UpstreamPool,
  base: NewAuditEvent,
  pre: { ruleId?: string; reason?: string; expiresAt?: string; taint?: AuditTaint; scanner?: AuditScanner },
  input: { name: string; args: Record<string, unknown>; client: PolicyClient },
  ctx: ToolCallContext,
): Promise<CallToolResult> {
  const expiresAt = pre.expiresAt ?? new Date(Date.now() + deps.approval.timeoutSeconds * 1000).toISOString();
  const pending = await appendQuiet(deps.audit, {
    ...base,
    decision: "approve_pending",
    ...(pre.ruleId !== undefined ? { ruleId: pre.ruleId } : {}),
    ...(pre.reason !== undefined ? { reason: pre.reason } : {}),
    ...(pre.taint !== undefined ? { taint: pre.taint } : {}),
    ...(pre.scanner ? { scanner: pre.scanner } : {}),
    expiresAt,
  });
  if (!pending.ok) {
    return textError(`audit log write failed; call denied (${pending.error})`);
  }
  const view = pendingView(pending.event);
  const elicit = canElicit(deps, input.name, ctx);
  deps.approvals.open(view, elicit ? "retry" : "inline", (resolution) => commitDecision(deps, base, pending.event, resolution));
  if (elicit) {
    return elicitAgain(deps, view, pre.reason);
  }
  const resolution = await deps.approvals.wait(view.id);
  if (resolution.action !== "approve") return textError(resolution.cause === "pause" ? "All calls paused" : BLOCKED);
  await syncPause(deps);
  if (deps.approvals.paused) return textError("All calls paused");
  if (!deps.approvals.claim(view.id)) return textError(BLOCKED);
  return forwardApproved(deps, pool, base, resolution.eventId ?? view.id, input);
}

async function resumeApproval(
  deps: GatewayDeps,
  pool: UpstreamPool,
  id: string,
  routed: { upstream: string; tool: string },
  input: { name: string; args: Record<string, unknown>; client: PolicyClient },
  ctx: ToolCallContext,
): Promise<CallToolResult> {
  const view = deps.approvals.peek(id);
  if (!view || view.tool !== input.name) return textError("This approval is no longer open");
  let resolution = deps.approvals.resolution(id);
  if (!resolution) {
    const choice = elicitationChoice(ctx.inputResponses);
    if (choice === "approve" || choice === "deny") {
      await deps.approvals.decide(id, {
        action: choice,
        channel: "elicitation",
        ...(input.client.name ? { by: input.client.name } : {}),
      });
      resolution = deps.approvals.resolution(id);
    }
  }
  if (!resolution) return elicitAgain(deps, view, view.reason);
  if (resolution.action !== "approve") return textError(resolution.cause === "pause" ? "All calls paused" : BLOCKED);
  await syncPause(deps);
  if (deps.approvals.paused) return textError("All calls paused");
  if (!deps.approvals.claim(id)) return textError(BLOCKED);
  const base = eventBase(deps, {
    client: input.client,
    upstream: routed.upstream,
    method: "tools/call",
    tool: input.name,
    args: input.args,
    decision: "allow",
    ...(view.ruleId !== undefined ? { ruleId: view.ruleId } : {}),
    reason: view.reason,
    taint: view.taint,
  });
  return forwardApproved(deps, pool, base, resolution.eventId ?? id, input);
}

function elicitAgain(deps: GatewayDeps, view: PendingView, reason: string | undefined): CallToolResult {
  const message = `${view.tool} is held. ${reason ?? "Approval is required."} Approve this one call? The next send asks again.`;
  return inputRequired({
    requestState: deps.approvals.sign(view.id),
    inputRequests: {
      approval: inputRequired.elicit({
        message,
        requestedSchema: CONFIRM,
      }),
    },
  }) as unknown as CallToolResult;
}

function canElicit(deps: GatewayDeps, tool: string, ctx: ToolCallContext): boolean {
  if (!ctx.elicitation || !deps.approval.channels.includes("elicitation")) return false;
  if (deps.approval.highRisk === "dashboard-only" && isOutboundTool(tool)) return false;
  return true;
}

function elicitationChoice(responses: Record<string, unknown> | undefined): "approve" | "deny" | undefined {
  const parsed = inputResponse(responses, "approval");
  if (parsed.kind !== "elicit") return undefined;
  if (parsed.action !== "accept") return "deny";
  const content = CONFIRM.safeParse(parsed.content);
  if (!content.success) return "deny";
  return content.data.approve ? "approve" : "deny";
}

async function commitDecision(
  deps: GatewayDeps,
  base: NewAuditEvent,
  pending: AuditEvent,
  resolution: {
    action: "approve" | "deny" | "timeout";
    channel?: "elicitation" | "dashboard" | "cli";
    by?: string;
    cause?: "pause";
  },
): Promise<string | undefined> {
  const decision = resolution.action === "approve" ? "approved" : resolution.action === "deny" ? "denied_by_human" : "timeout";
  const reason =
    decision === "approved"
      ? "Approved once"
      : decision === "timeout"
        ? "Timed out, so Drawbridge denied it"
        : resolution.cause === "pause"
      ? "All calls paused, so Drawbridge denied it"
      : resolution.channel === "cli"
        ? "Denied from the CLI"
        : resolution.channel === "elicitation"
          ? "Denied in the client"
          : "Denied by you on the dashboard";
  const latencyMs = Math.max(0, Date.now() - Date.parse(pending.ts));
  const written = await appendQuiet(deps.audit, {
    ...base,
    decision,
    reason,
    taint: pending.taint,
    approval: {
      pendingId: pending.id,
      ...(resolution.channel ? { channel: resolution.channel } : {}),
      ...(resolution.by ? { by: resolution.by } : {}),
      latencyMs,
    },
  });
  if (!written.ok) throw new Error(written.error);
  return written.event.id;
}

async function forwardApproved(
  deps: GatewayDeps,
  pool: UpstreamPool,
  base: NewAuditEvent,
  intentId: string,
  input: { name: string; args: Record<string, unknown>; client: PolicyClient },
): Promise<CallToolResult> {
  await syncPause(deps);
  if (deps.approvals.paused) return textError("All calls paused");
  const routed = parseNamespacedTool(input.name, new Set(pool.names()));
  if (!routed) return textError(BLOCKED);
  const started = Date.now();
  let result: CallToolResult;
  try {
    result = await pool.callTool(routed.upstream, routed.tool, input.args);
  } catch (error) {
    result = textError(`upstream "${routed.upstream}" error: ${message(error)}`);
  }
  let finalResult = result;
  let scanner = undefined;
  let taintAfter: AuditTaint | undefined;
  try {
    const post = await deps.policy.postResult({
      sessionId: deps.sessionId,
      method: "tools/call",
      upstream: routed.upstream,
      tool: input.name,
      result,
      trusted: pool.trusted(routed.upstream),
      client: input.client,
    });
    finalResult = asToolResult(post.result, result);
    if (post.taint) taintAfter = taintAfterIfChanged(base.taint, post.taint);
    if (post.scanner) scanner = post.scanner;
  } catch (error) {
    finalResult = textError(`post-result hook failed; result withheld (${message(error)})`);
  }
  const outcome = await appendQuiet(deps.audit, {
    ...base,
    decision: "allow",
    intentId,
    ...(taintAfter ? { taintAfter } : {}),
    ...(scanner ? { scanner } : {}),
    resultHash: sha256(stableStringify(finalResult)),
    durationMs: Date.now() - started,
  });
  if (!outcome.ok) {
    return textError(`audit log write failed after the upstream responded; result withheld (${outcome.error})`);
  }
  return finalResult;
}

function pendingView(event: AuditEvent): PendingView {
  return {
    id: event.id,
    tool: event.tool ?? event.method,
    upstream: event.upstream,
    sessionId: event.sessionId,
    reason: event.reason ?? "Approval is required.",
    ...(event.ruleId !== undefined ? { ruleId: event.ruleId } : {}),
    taint: event.taint,
    argsRedacted: event.argsRedacted,
    argsHash: event.argsHash,
    expiresAt: event.expiresAt ?? new Date(Date.now() + 120_000).toISOString(),
    ts: event.ts,
    client: event.client,
    ...(event.scanner ? { scanner: event.scanner } : {}),
  };
}

async function syncPause(deps: GatewayDeps): Promise<void> {
  if (!deps.refreshPause) return;
  try {
    await deps.refreshPause();
  } catch {
    deps.approvals.paused = true;
  }
}

function denyPaused(
  deps: GatewayDeps,
  input: { name: string; args: Record<string, unknown>; client: PolicyClient },
  note: string | undefined,
): Promise<CallToolResult> {
  return deny(deps, {
    client: input.client,
    upstream: UNROUTED,
    tool: input.name,
    args: input.args,
    decision: "deny",
    ruleId: "kill:paused",
    reason: "All calls paused",
    ...(note ? { credentialNote: note } : {}),
  });
}

async function deny(
  deps: GatewayDeps,
  fields: {
    client: PolicyClient;
    upstream: string;
    tool: string;
    args: Record<string, unknown>;
    decision: NewAuditEvent["decision"];
    ruleId?: string;
    reason?: string;
    credentialNote?: string;
  },
): Promise<CallToolResult> {
  const recorded = await appendQuiet(
    deps.audit,
    eventBase(deps, { ...fields, method: "tools/call" }),
  );
  if (!recorded.ok) {
    return textError(`audit log write failed; call denied (${recorded.error})`);
  }
  return textError(fields.reason ?? `Call denied (${fields.decision})`);
}

function eventBase(
  deps: GatewayDeps,
  fields: {
    client: PolicyClient;
    upstream: string;
    method: NewAuditEvent["method"];
    tool?: string;
    args: unknown;
    decision: NewAuditEvent["decision"];
    ruleId?: string;
    reason?: string;
    credentialNote?: string;
    taint?: AuditTaint;
  },
): NewAuditEvent {
  const reason = joinReason(fields.reason, fields.credentialNote);
  return {
    sessionId: deps.sessionId,
    client: fields.client,
    upstream: fields.upstream,
    method: fields.method,
    ...(fields.tool !== undefined ? { tool: fields.tool } : {}),
    argsRedacted: redact(fields.args),
    argsHash: sha256(stableStringify(fields.args)),
    decision: fields.decision,
    ...(fields.ruleId !== undefined ? { ruleId: fields.ruleId } : {}),
    ...(reason !== undefined ? { reason } : {}),
    taint: fields.taint ?? deps.policy.sessionTaint?.() ?? UNTAINTED_SESSION,
  };
}

function joinReason(reason: string | undefined, note: string | undefined): string | undefined {
  if (!note) return reason;
  return reason ? `${reason}. ${note}` : note;
}

async function safePreCall(
  policy: PolicyEngine,
  input: Parameters<PolicyEngine["preCall"]>[0],
): Promise<{
  decision: PolicyCallDecision;
  ruleId?: string;
  reason?: string;
  taint?: AuditTaint;
  expiresAt?: string;
}> {
  try {
    return await policy.preCall(input);
  } catch (error) {
    return {
      decision: "deny",
      ruleId: "hook:pre-call",
      reason: `policy hook failed; call denied (${message(error)})`,
    };
  }
}

async function appendOrThrow(audit: AuditSink, event: NewAuditEvent): Promise<AuditEvent> {
  const recorded = await appendQuiet(audit, event);
  if (!recorded.ok) throw new Error(`audit log write failed; request denied (${recorded.error})`);
  return recorded.event;
}

async function appendQuiet(
  audit: AuditSink,
  event: NewAuditEvent,
): Promise<{ ok: true; event: AuditEvent } | { ok: false; error: string }> {
  try {
    return { ok: true, event: await audit.append(event) };
  } catch (error) {
    return { ok: false, error: message(error) };
  }
}

function isToolCatalog(value: unknown): value is { tools: CatalogTool[] } {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  return Array.isArray((value as { tools?: unknown }).tools);
}

function asToolResult(value: unknown, fallback: CallToolResult): CallToolResult {
  if (value !== null && typeof value === "object" && "content" in value && Array.isArray(value.content)) {
    return value as CallToolResult;
  }
  return fallback;
}

function textError(text: string): CallToolResult {
  return { content: [{ type: "text", text }], isError: true };
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
