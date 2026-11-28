import { Server } from "@modelcontextprotocol/server";
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
        "An approve rule is recorded as pending and denied until approval channels exist.",
    },
  );

  server.setRequestHandler("tools/list", async (request, ctx) => {
    void request;
    return handleToolsList(deps, { client: readClientInfo(ctx as RequestContext) });
  });

  server.setRequestHandler("tools/call", async (request, ctx) => {
    const args = request.params.arguments ?? {};
    return handleToolCall(deps, {
      name: request.params.name,
      args,
      client: readClientInfo(ctx as RequestContext),
    });
  });

  return server;
}
