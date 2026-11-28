import { parse as parseYaml } from "yaml";
import { z } from "zod";
import { ConfigError } from "./errors.js";
import { assertUpstreamName } from "./namespace.js";

const actionSchema = z.enum(["allow", "deny", "approve"]);

const rateLimitSchema = z
  .strictObject({
    perMinute: z.number().int().positive().optional(),
    perSession: z.number().int().positive().optional(),
  })
  .refine((value) => value.perMinute !== undefined || value.perSession !== undefined, {
    message: "rateLimit needs perMinute or perSession",
  });

const argConstraintSchema = z
  .strictObject({
    pattern: z.string().min(1).optional(),
    enum: z.array(z.string()).min(1).optional(),
    allowDomains: z.array(z.string().min(1)).min(1).optional(),
    maxLength: z.number().int().nonnegative().optional(),
  })
  .refine(
    (value) =>
      value.pattern !== undefined ||
      value.enum !== undefined ||
      value.allowDomains !== undefined ||
      value.maxLength !== undefined,
    { message: "argument constraint needs pattern, enum, allowDomains, or maxLength" },
  );

const ruleSchema = z.strictObject({
  tool: z.string().min(1),
  action: actionSchema,
  args: z.record(z.string(), argConstraintSchema).optional(),
  rateLimit: rateLimitSchema.optional(),
});

const flowSchema = z.strictObject({
  name: z.string().min(1),
  when: z.strictObject({ sessionTainted: z.boolean() }),
  tools: z.array(z.string().min(1)).min(1),
  action: actionSchema,
  reason: z.string().min(1).optional(),
});

const defaultsSchema = z.strictObject({
  action: actionSchema.optional().default("deny"),
  fromAnnotations: z.boolean().optional().default(true),
  rateLimit: rateLimitSchema.optional(),
});

const scannerSchema = z.strictObject({
  mode: z.enum(["block", "warn", "wrap"]).optional().default("block"),
  scanDescriptions: z.boolean().optional().default(true),
  classifier: z.enum(["off", "local", "api"]).optional().default("off"),
  allowlist: z
    .array(
      z.strictObject({
        match: z.string().min(1),
        upstream: z.string().min(1),
        expires: z.string().min(1),
      }),
    )
    .optional()
    .default([]),
});

const approvalSchema = z.strictObject({
  channels: z
    .array(z.enum(["elicitation", "dashboard", "cli"]))
    .optional()
    .default(["elicitation", "dashboard", "cli"]),
  highRisk: z.literal("dashboard-only").optional().default("dashboard-only"),
  timeoutSeconds: z.number().int().positive().optional().default(120),
});

const upstreamSecurity = {
  trusted: z.boolean().optional().default(false),
  pinTools: z.boolean().optional().default(false),
  /** A changed or missing pin is denied, or held (`approve`) until a person resolves it. */
  onPinMismatch: z.enum(["deny", "approve"]).optional().default("deny"),
};

const stdioUpstream = z.strictObject({
  transport: z.literal("stdio"),
  command: z.array(z.string().min(1)).min(1),
  env: z.record(z.string(), z.string()).optional(),
  cwd: z.string().min(1).optional(),
  ...upstreamSecurity,
});

const httpUpstream = z.strictObject({
  transport: z.literal("http"),
  url: z.string().min(1),
  headers: z.record(z.string(), z.string()).optional(),
  ...upstreamSecurity,
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
  pins: z
    .strictObject({
      path: z.string().min(1),
    })
    .optional()
    .default({ path: "drawbridge.pins.json" }),
  defaults: defaultsSchema.optional().default({ action: "deny", fromAnnotations: true }),
  rules: z.array(ruleSchema).optional().default([]),
  flows: z.array(flowSchema).optional().default([]),
  scanner: scannerSchema.optional().default({ mode: "block", scanDescriptions: true, classifier: "off", allowlist: [] }),
  approval: approvalSchema.optional().default({
    channels: ["elicitation", "dashboard", "cli"],
    highRisk: "dashboard-only",
    timeoutSeconds: 120,
  }),
  upstreams: z.record(z.string(), upstreamSchema),
});

export type PolicyAction = z.infer<typeof actionSchema>;
export type RateLimitConfig = z.infer<typeof rateLimitSchema>;
export type ArgConstraint = z.infer<typeof argConstraintSchema>;
export type PolicyRule = z.infer<typeof ruleSchema>;
export type PolicyFlow = z.infer<typeof flowSchema>;

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

  validateRulePatterns(parsed.data.rules);
  if (parsed.data.scanner.classifier !== "off") {
    throw new ConfigError(
      `scanner.classifier "${parsed.data.scanner.classifier}" is not implemented. Milestone 3 runs heuristics only; set classifier: off.`,
    );
  }

  const upstreams = names.sort().map((name) => {
    const upstream = parsed.data.upstreams[name];
    if (!upstream) throw new ConfigError(`Missing upstream "${name}"`);
    return { name, upstream: interpolateUpstream(upstream, env) };
  });

  let auditPath: string;
  try {
    auditPath = interpolate(parsed.data.audit.path, env);
  } catch (error) {
    throw new ConfigError(error instanceof Error ? error.message : String(error));
  }
  if (auditPath.length === 0) throw new ConfigError("audit.path is empty");

  let pinsPath: string;
  try {
    pinsPath = interpolate(parsed.data.pins.path, env);
  } catch (error) {
    throw new ConfigError(error instanceof Error ? error.message : String(error));
  }
  if (pinsPath.length === 0) throw new ConfigError("pins.path is empty");

  return {
    version: 1,
    audit: { path: auditPath },
    pins: { path: pinsPath },
    defaults: parsed.data.defaults,
    rules: parsed.data.rules,
    flows: parsed.data.flows,
    scanner: parsed.data.scanner,
    approval: parsed.data.approval,
    upstreams,
  };
}

function validateRulePatterns(rules: { args?: Record<string, { pattern?: string }> }[]): void {
  for (const [index, rule] of rules.entries()) {
    for (const [key, constraint] of Object.entries(rule.args ?? {})) {
      if (constraint.pattern === undefined) continue;
      try {
        new RegExp(constraint.pattern);
      } catch (error) {
        throw new ConfigError(
          `rules.${index}.args.${key}.pattern is not a valid regular expression: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }
  }
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
