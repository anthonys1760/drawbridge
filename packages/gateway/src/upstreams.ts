import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { StdioClientTransport, getDefaultEnvironment } from "@modelcontextprotocol/client/stdio";
import type { CallToolResult, Tool } from "@modelcontextprotocol/server";
import {
  createScrubber,
  envForStdio,
  headersForHttp,
  resolveUpstreamSecrets,
  type DrawbridgeConfig,
  type ToolAnnotationHints,
  type UpstreamConfig,
} from "@drawbridge/core";
import { VERSION } from "./version.js";

export interface JsonObjectSchema {
  type: "object";
  [key: string]: unknown;
}

export interface CatalogTool {
  name: string;
  description?: string;
  title?: string;
  inputSchema: JsonObjectSchema;
  outputSchema?: Record<string, unknown>;
  annotations?: ToolAnnotationHints;
}

export interface UpstreamPool {
  names(): string[];
  trusted(name: string): boolean;
  listTools(name: string): Promise<CatalogTool[]>;
  callTool(name: string, tool: string, args: Record<string, unknown>): Promise<CallToolResult>;
  annotations(name: string, tool: string): ToolAnnotationHints | undefined;
  close(): Promise<void>;
}

interface ConnectedUpstream {
  client: Client;
  trusted: boolean;
  tools: Map<string, CatalogTool>;
}

const CLIENT_INFO = { name: "drawbridge", version: VERSION };

/**
 * Connections Drawbridge opens to upstream MCP servers.
 * The client identity on these connections is Drawbridge itself. The
 * end-user client's credentials are never forwarded.
 */
export class SdkUpstreamPool implements UpstreamPool {
  private constructor(private readonly clients: Map<string, ConnectedUpstream>) {}

  static async connect(
    upstreams: { name: string; upstream: UpstreamConfig }[],
    options: {
      secrets?: Map<string, Record<string, string>>;
      scrub?: (text: string) => string;
    } = {},
  ): Promise<SdkUpstreamPool> {
    const clients = new Map<string, ConnectedUpstream>();
    const scrub = options.scrub ?? ((text: string) => text);
    try {
      for (const entry of upstreams) {
        const client = new Client(CLIENT_INFO, {
          versionNegotiation: { mode: "auto", probe: { timeoutMs: 10_000 } },
        });
        await client.connect(await transportFor(entry.name, entry.upstream, options.secrets?.get(entry.name) ?? {}, scrub));
        clients.set(entry.name, { client, trusted: entry.upstream.trusted, tools: new Map() });
      }
    } catch (error) {
      await closeAll(clients);
      throw new Error(scrub(error instanceof Error ? error.message : String(error)));
    }
    return new SdkUpstreamPool(clients);
  }

  names(): string[] {
    return [...this.clients.keys()];
  }

  trusted(name: string): boolean {
    return this.require(name).trusted;
  }

  annotations(name: string, tool: string): ToolAnnotationHints | undefined {
    return this.clients.get(name)?.tools.get(tool)?.annotations;
  }

  async listTools(name: string): Promise<CatalogTool[]> {
    const connected = this.require(name);
    const listed = await connected.client.listTools();
    const tools = listed.tools.map(toCatalog);
    connected.tools = new Map(tools.map((tool) => [tool.name, tool]));
    return tools;
  }

  async callTool(name: string, tool: string, args: Record<string, unknown>): Promise<CallToolResult> {
    const connected = this.require(name);
    return connected.client.callTool({ name: tool, arguments: args });
  }

  async close(): Promise<void> {
    await closeAll(this.clients);
    this.clients.clear();
  }

  private require(name: string): ConnectedUpstream {
    const connected = this.clients.get(name);
    if (!connected) throw new Error(`Unknown upstream "${name}"`);
    return connected;
  }
}

async function transportFor(
  name: string,
  upstream: UpstreamConfig,
  secrets: Record<string, string>,
  scrub: (text: string) => string,
) {
  if (upstream.transport === "stdio") {
    const [command, ...args] = upstream.command;
    if (!command) throw new Error(`Upstream "${name}" is missing a command`);
    const env = envForStdio(getDefaultEnvironment(), upstream.env, secrets);
    const transport = new StdioClientTransport({
      command,
      args,
      env,
      ...(upstream.cwd ? { cwd: upstream.cwd } : {}),
      stderr: "pipe",
    });
    // Drain stderr. A full pipe would stall the upstream, and an unread
    // probe sibling would leak that stall into the next connect. Scrub
    // before writing so an upstream cannot echo a secret into our log.
    transport.stderr?.on("data", (chunk: Buffer | string) => {
      const text = scrub(typeof chunk === "string" ? chunk : chunk.toString());
      process.stderr.write(`[${name}] ${text}`);
    });
    return transport;
  }
  const headers = headersForHttp(upstream.headers, secrets);
  return new StreamableHTTPClientTransport(new URL(upstream.url), {
    ...(Object.keys(headers).length > 0 ? { requestInit: { headers } } : {}),
  });
}

/**
 * Resolve this config's secrets and connect. One upstream's values are passed
 * only into that upstream's env or headers. Connection errors are scrubbed.
 */
export async function openUpstreamPool(config: DrawbridgeConfig): Promise<{
  pool: SdkUpstreamPool;
  scrub: (text: string) => string;
}> {
  const secrets = await resolveUpstreamSecrets(config.upstreams);
  const values: string[] = [];
  for (const record of secrets.values()) values.push(...Object.values(record));
  const scrub = createScrubber(values);
  const pool = await SdkUpstreamPool.connect(config.upstreams, { secrets, scrub });
  return { pool, scrub };
}

async function closeAll(clients: Map<string, ConnectedUpstream>): Promise<void> {
  await Promise.all(
    [...clients.values()].map(async (connected) => {
      await connected.client.close().catch(() => undefined);
    }),
  );
}

function asObjectSchema(value: unknown): JsonObjectSchema {
  if (value !== null && typeof value === "object" && (value as { type?: unknown }).type === "object") {
    return value as JsonObjectSchema;
  }
  return { type: "object" };
}

function toCatalog(tool: Tool): CatalogTool {
  const { name, description, title, inputSchema, outputSchema, annotations } = tool as Tool & { title?: string };
  return {
    name,
    ...(description !== undefined ? { description } : {}),
    ...(title !== undefined ? { title } : {}),
    inputSchema: asObjectSchema(inputSchema),
    ...(outputSchema !== undefined ? { outputSchema: outputSchema as Record<string, unknown> } : {}),
    ...(annotations !== undefined ? { annotations } : {}),
  };
}
