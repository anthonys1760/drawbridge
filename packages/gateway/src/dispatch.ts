import {
  AllowAllPolicy,
  UNTAINTED_SESSION,
  decisionForwards,
  namespaceTool,
  parseNamespacedTool,
  redact,
  sha256,
  stableStringify,
  taintAfterIfChanged,
  type AuditSink,
  type AuditTaint,
  type NewAuditEvent,
  type PolicyClient,
  type PolicyEngine,
} from "@drawbridge/core";
import type { CallToolResult } from "@modelcontextprotocol/server";
import type { CatalogTool, JsonObjectSchema, UpstreamPool } from "./upstreams.js";

const UNROUTED = "_unrouted";

export interface GatewayDeps {
  sessionId: string;
  policy: PolicyEngine;
  audit: AuditSink;
  pool: () => Promise<UpstreamPool>;
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
      decision: pre.decision,
      ruleId: pre.ruleId,
      reason: pre.reason,
    });
    if (!decisionForwards(pre.decision)) {
      await appendOrThrow(deps.audit, base);
      continue;
    }
    await appendOrThrow(deps.audit, base);
    const started = Date.now();
    let listed: CatalogTool[];
    try {
      listed = await pool.listTools(upstream);
    } catch (error) {
      const failure = `tools/list failed for upstream "${upstream}": ${message(error)}`;
      await appendOrThrow(deps.audit, {
        ...base,
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
        result: listed,
        trusted: pool.trusted(upstream),
        client: input.client,
      });
      if (post.taint) taintAfter = taintAfterIfChanged(base.taint, post.taint);
      if (post.scanner) scanner = post.scanner;
    } catch (error) {
      const failure = `post-result hook failed for upstream "${upstream}": ${message(error)}`;
      await appendOrThrow(deps.audit, {
        ...base,
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
): Promise<CallToolResult> {
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
    });
  }

  const pre = await safePreCall(deps.policy, {
    sessionId: deps.sessionId,
    method: "tools/call",
    upstream: routed.upstream,
    tool: input.name,
    args: input.args,
    client: input.client,
    trusted: pool.trusted(routed.upstream),
    annotations: pool.annotations(routed.upstream, routed.tool),
  });
  const base = eventBase(deps, {
    client: input.client,
    upstream: routed.upstream,
    method: "tools/call",
    tool: input.name,
    args: input.args,
    decision: pre.decision,
    ruleId: pre.ruleId,
    reason: pre.reason,
  });
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
  },
): NewAuditEvent {
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
    ...(fields.reason !== undefined ? { reason: fields.reason } : {}),
    taint: UNTAINTED_SESSION,
  };
}

async function safePreCall(
  policy: PolicyEngine,
  input: Parameters<PolicyEngine["preCall"]>[0],
): Promise<{ decision: NewAuditEvent["decision"]; ruleId?: string; reason?: string }> {
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

async function appendOrThrow(audit: AuditSink, event: NewAuditEvent): Promise<void> {
  const recorded = await appendQuiet(audit, event);
  if (!recorded.ok) throw new Error(`audit log write failed; request denied (${recorded.error})`);
}

async function appendQuiet(
  audit: AuditSink,
  event: NewAuditEvent,
): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    await audit.append(event);
    return { ok: true };
  } catch (error) {
    return { ok: false, error: message(error) };
  }
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
