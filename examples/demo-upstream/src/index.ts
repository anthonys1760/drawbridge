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

function createMailServer(): McpServer {
  const server = new McpServer({ name: "demo-mail", version: "0.1.0" });

  server.registerTool(
    "send",
    {
      title: "Send mail",
      description: "Queue a demo message on this machine. Nothing is delivered.",
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
      inputSchema: z.object({
        to: z.string().describe("Recipient"),
        body: z.string().optional().describe("Message body"),
      }),
    },
    async () => ({
      content: [{ type: "text", text: "sent" }],
    }),
  );

  return server;
}

const role = process.argv[2];
if (role === undefined) {
  serveStdio(createServer, { legacy: "reject" });
  console.error("demo-notes MCP server running on stdio");
} else if (role === "mail") {
  serveStdio(createMailServer, { legacy: "reject" });
  console.error("demo-mail MCP server running on stdio");
} else {
  console.error(`Unknown demo role "${role}". Use no argument for notes, or "mail".`);
  process.exit(1);
}
