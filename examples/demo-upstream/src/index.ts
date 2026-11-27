import { McpServer } from "@modelcontextprotocol/server";
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import { z } from "zod";

function createServer(): McpServer {
  const server = new McpServer({ name: "demo-notes", version: "0.1.0" });

  server.registerTool(
    "read",
    {
      title: "Read a note",
      description: "Read a demo note by path",
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
      inputSchema: z.object({
        path: z.string().describe("Note path"),
      }),
    },
    async ({ path }) => ({
      content: [{ type: "text", text: `note:${path}` }],
    }),
  );

  server.registerTool(
    "echo",
    {
      description: "Echo a message and an optional token",
      inputSchema: z.object({
        message: z.string(),
        token: z.string().optional(),
      }),
    },
    async ({ message, token }) => ({
      content: [{ type: "text", text: JSON.stringify({ message, token: token ?? null }) }],
    }),
  );

  return server;
}

serveStdio(createServer, { legacy: "reject" });
console.error("demo-notes MCP server running on stdio");
