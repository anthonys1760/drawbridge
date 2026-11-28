import { CLIENT_CAPABILITIES_META_KEY, Server } from "@modelcontextprotocol/server";
import type { GatewayDeps } from "./dispatch.js";
import { handleToolCall, handleToolsList } from "./dispatch.js";
import { readClientInfo, type RequestContext } from "./client-info.js";
import { VERSION } from "./version.js";

export function createGatewayServer(deps: GatewayDeps): Server {
  const server = new Server(
    { name: "drawbridge", version: VERSION },
    {
      capabilities: { tools: { listChanged: false } },
      instructions:
        "Drawbridge is an MCP gateway. Tool names are <upstream>__<tool>. " +
        "tools/list and tools/call are forwarded to the configured upstreams. " +
        "Tool calls are gated by drawbridge.yaml. Descriptions and results are scanned. " +
        "An approve rule waits for one person. Approving once does not allow the next call.",
    },
  );

  server.setRequestHandler("tools/list", async (request, ctx) => {
    void request;
    return handleToolsList(deps, { client: readClientInfo(ctx as RequestContext) });
  });

  server.setRequestHandler("tools/call", async (request, ctx) => {
    const context = ctx as RequestContext & {
      mcpReq?: { inputResponses?: Record<string, unknown>; requestState?: () => unknown; envelope?: object };
    };
    const args = request.params.arguments ?? {};
    const state = context.mcpReq?.requestState?.();
    return handleToolCall(
      deps,
      {
        name: request.params.name,
        args,
        client: readClientInfo(context),
      },
      {
        ...(typeof state === "string" ? { approvalState: state } : {}),
        ...(context.mcpReq?.inputResponses ? { inputResponses: context.mcpReq.inputResponses } : {}),
        ...(supportsElicitation(context) ? { elicitation: true } : {}),
      },
    );
  });

  return server;
}

function supportsElicitation(ctx: { mcpReq?: { envelope?: object } }): boolean {
  const envelope = ctx.mcpReq?.envelope as Record<string, unknown> | undefined;
  const caps = envelope?.[CLIENT_CAPABILITIES_META_KEY];
  if (caps === null || typeof caps !== "object") return false;
  return "elicitation" in caps && Boolean((caps as { elicitation?: unknown }).elicitation);
}
