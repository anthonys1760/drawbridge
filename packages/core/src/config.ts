import { parse as parseYaml } from "yaml";
import { z } from "zod";
import { ConfigError } from "./errors.js";
import { assertUpstreamName } from "./namespace.js";

const RESERVED_SECTIONS = ["defaults", "rules", "flows", "scanner", "approval"] as const;

const stdioUpstream = z.strictObject({
  transport: z.literal("stdio"),
  command: z.array(z.string().min(1)).min(1),
  env: z.record(z.string(), z.string()).optional(),
  cwd: z.string().min(1).optional(),
  trusted: z.boolean().optional().default(false),
  pinTools: z.boolean().optional().default(false),
});

const httpUpstream = z.strictObject({
  transport: z.literal("http"),
  url: z.string().min(1),
  headers: z.record(z.string(), z.string()).optional(),
  trusted: z.boolean().optional().default(false),
  pinTools: z.boolean().optional().default(false),
});

const upstreamSchema = z.discriminatedUnion("transport", [stdioUpstream, httpUpstream]);

const configSchema = z.strictObject({
  version: z.literal(1),
  audit: z
    .strictObject({
      path: z.string().min(1),
    })
    .optional()
    .default({ path: "drawbridge-audit.jsonl" }),
  upstreams: z.record(z.string(), upstreamSchema),
});

export type StdioUpstreamConfig = z.infer<typeof stdioUpstream>;
export type HttpUpstreamConfig = z.infer<typeof httpUpstream>;
export type UpstreamConfig = z.infer<typeof upstreamSchema>;
export type DrawbridgeConfig = Omit<z.infer<typeof configSchema>, "upstreams"> & {
  upstreams: { name: string; upstream: UpstreamConfig }[];
};

export function loadConfig(text: string, env: NodeJS.ProcessEnv = process.env): DrawbridgeConfig {
  let raw: unknown;
  try {
    raw = parseYaml(text);
  } catch (error) {
    throw new ConfigError(`Config is not valid YAML: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new ConfigError("Config must be a YAML mapping");
  }
  const record = raw as Record<string, unknown>;
  for (const section of RESERVED_SECTIONS) {
    if (section in record) {
      throw new ConfigError(
        `Config section \`${section}\` is not enforced yet. Milestone 1 would ignore it and allow every routed call, so Drawbridge refuses to start. Policy enforcement is milestone 2.`,
      );
    }
  }
  rejectUnimplementedUpstreamSecurity(record.upstreams);

  const parsed = configSchema.safeParse(raw);
  if (!parsed.success) {
    throw new ConfigError(formatZodError(parsed.error));
  }
  const names = Object.keys(parsed.data.upstreams);
  if (names.length === 0) throw new ConfigError("Config must list at least one upstream");
  for (const name of names) {
    try {
      assertUpstreamName(name);
    } catch (error) {
      throw new ConfigError(error instanceof Error ? error.message : String(error));
    }
  }

  const upstreams = names.sort().map((name) => {
    const upstream = parsed.data.upstreams[name];
    if (!upstream) throw new ConfigError(`Missing upstream "${name}"`);
    if (upstream.pinTools) {
      throw new ConfigError(
        `Upstream "${name}" sets pinTools: true, which is not enforced until milestone 2. Refusing to start.`,
      );
    }
    return { name, upstream: interpolateUpstream(upstream, env) };
  });

  let auditPath: string;
  try {
    auditPath = interpolate(parsed.data.audit.path, env);
  } catch (error) {
    throw new ConfigError(error instanceof Error ? error.message : String(error));
  }
  if (auditPath.length === 0) throw new ConfigError("audit.path is empty");

  return {
    version: 1,
    audit: { path: auditPath },
    upstreams,
  };
}

function rejectUnimplementedUpstreamSecurity(upstreams: unknown): void {
  if (upstreams === null || typeof upstreams !== "object" || Array.isArray(upstreams)) return;
  for (const [name, value] of Object.entries(upstreams)) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) continue;
    const upstream = value as Record<string, unknown>;
    if ("auth" in upstream || "secretRef" in upstream) {
      throw new ConfigError(
        `Upstream "${name}" uses secretRef/auth, which is not implemented. Milestone 1 will not start with an unresolved credential. Put headers or env values in the environment (\${VAR}) or wait for milestone 5.`,
      );
    }
  }
}

function interpolateUpstream(upstream: UpstreamConfig, env: NodeJS.ProcessEnv): UpstreamConfig {
  if (upstream.transport === "stdio") {
    return {
      ...upstream,
      command: upstream.command.map((part) => interpolate(part, env)),
      ...(upstream.env
        ? { env: Object.fromEntries(Object.entries(upstream.env).map(([key, value]) => [key, interpolate(value, env)])) }
        : {}),
      ...(upstream.cwd ? { cwd: interpolate(upstream.cwd, env) } : {}),
    };
  }
  const url = interpolate(upstream.url, env);
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new ConfigError(`Upstream URL is not absolute after interpolation: ${url}`);
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new ConfigError(`Upstream URL must be http or https, got ${parsed.protocol}`);
  }
  return {
    ...upstream,
    url,
    ...(upstream.headers
      ? {
          headers: Object.fromEntries(
            Object.entries(upstream.headers).map(([key, value]) => [key, interpolate(value, env)]),
          ),
        }
      : {}),
  };
}

export function interpolate(value: string, env: NodeJS.ProcessEnv): string {
  const missing: string[] = [];
  const rendered = value.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g, (_match, name: string) => {
    const found = env[name];
    if (found === undefined) {
      missing.push(name);
      return "";
    }
    return found;
  });
  if (missing.length > 0) {
    throw new ConfigError(`Unset environment variable ${missing.join(", ")} referenced in config`);
  }
  return rendered;
}

function formatZodError(error: z.ZodError): string {
  return error.issues
    .map((issue) => `${issue.path.join(".") || "(root)"}: ${issue.message}`)
    .join("; ");
}
