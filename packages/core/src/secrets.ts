import { readFile } from "node:fs/promises";
import type { UpstreamConfig } from "./config.js";
import { ConfigError } from "./errors.js";

const ENV_REF = /^env:[A-Za-z_][A-Za-z0-9_]*$/;
const FILE_REF = /^file:\S+$/;
const SECRET_NAME = /^[A-Za-z0-9][A-Za-z0-9_-]*$/;
const CREDENTIAL_KEY = /(?:^|[_-])(?:token|key|secret|password|passwd|bearer)$|authorization|api[-_]?key/i;
const BEARER_VALUE = /^Bearer\s+\S+/i;

/**
 * A secret value in drawbridge.yaml is a reference, never the secret itself.
 * `env:NAME` reads the gateway environment. `file:PATH` reads a file.
 */
export function assertSecretRef(upstream: string, key: string, value: string): void {
  if (!SECRET_NAME.test(key) || (!ENV_REF.test(value) && !FILE_REF.test(value))) {
    throw new ConfigError(
      `Upstream "${upstream}" secret "${key}" must be an env:NAME or file:PATH reference. Inline values are refused.`,
    );
  }
}

/**
 * `env` and `headers` still accept a literal. Startup warns when one looks
 * like a credential. The message names the key and never includes the value.
 * `secrets` is the supported path and is not warned about.
 */
export function credentialLiteralWarnings(upstreams: { name: string; upstream: UpstreamConfig }[]): string[] {
  const warnings: string[] = [];
  for (const entry of upstreams) {
    const upstream = entry.upstream;
    if (upstream.transport === "stdio") collect(warnings, entry.name, "env", upstream.env);
    if (upstream.transport === "http") collect(warnings, entry.name, "headers", upstream.headers);
  }
  return warnings;
}

function collect(
  warnings: string[],
  upstream: string,
  where: "env" | "headers",
  values: Record<string, string> | undefined,
): void {
  for (const [key, value] of Object.entries(values ?? {})) {
    if (value.length === 0) continue;
    if (!CREDENTIAL_KEY.test(key) && !BEARER_VALUE.test(value)) continue;
    warnings.push(
      `drawbridge: upstream "${upstream}" ${where}.${key} looks like a credential. Use secrets with an env: or file: reference. The value was not logged.`,
    );
  }
}

export async function resolveUpstreamSecrets(
  upstreams: { name: string; upstream: UpstreamConfig }[],
  env: NodeJS.ProcessEnv = process.env,
  read: (path: string) => Promise<string> = (path) => readFile(path, "utf8"),
): Promise<Map<string, Record<string, string>>> {
  const resolved = new Map<string, Record<string, string>>();
  for (const entry of upstreams) {
    const secrets = entry.upstream.secrets;
    if (!secrets) continue;
    const values: Record<string, string> = {};
    for (const [key, ref] of Object.entries(secrets)) {
      assertSecretRef(entry.name, key, ref);
      values[key] = await resolveOne(entry.name, key, ref, env, read);
    }
    resolved.set(entry.name, values);
  }
  return resolved;
}

async function resolveOne(
  upstream: string,
  key: string,
  ref: string,
  env: NodeJS.ProcessEnv,
  read: (path: string) => Promise<string>,
): Promise<string> {
  if (ref.startsWith("env:")) {
    const name = ref.slice("env:".length);
    const value = env[name];
    if (value === undefined || value.length === 0) {
      throw new ConfigError(`Unset environment variable ${name} referenced by upstream "${upstream}" secret "${key}"`);
    }
    return value;
  }
  const path = ref.slice("file:".length);
  let text: string;
  try {
    text = await read(path);
  } catch {
    throw new ConfigError(`Cannot read secret file ${path} for upstream "${upstream}" secret "${key}"`);
  }
  if (text.endsWith("\r\n")) text = text.slice(0, -2);
  else if (text.endsWith("\n")) text = text.slice(0, -1);
  if (text.length === 0) {
    throw new ConfigError(`Secret file ${path} for upstream "${upstream}" secret "${key}" is empty`);
  }
  return text;
}

/** Replace known secret values. Short values are left alone so a one-letter secret cannot blank the log. */
export function createScrubber(secrets: Iterable<string>): (text: string) => string {
  const needles = [...new Set(secrets)].filter((value) => value.length >= 4).sort((left, right) => right.length - left.length);
  return (text: string) => {
    let out = text;
    for (const needle of needles) {
      if (out.includes(needle)) out = out.split(needle).join("[REDACTED]");
    }
    return out;
  };
}

/**
 * Environment for one stdio upstream. Starts from the SDK's safe default,
 * then this upstream's env, then this upstream's secrets. Nothing is copied
 * back onto the source objects.
 */
export function envForStdio(
  base: Record<string, string | undefined>,
  configured: Record<string, string> | undefined,
  secrets: Record<string, string>,
): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries(base)) {
    if (typeof value === "string") env[key] = value;
  }
  for (const [key, value] of Object.entries(configured ?? {})) env[key] = value;
  for (const [key, value] of Object.entries(secrets)) env[key] = value;
  return env;
}

/** Headers for one HTTP upstream. Secrets overlay configured headers and are not shared. */
export function headersForHttp(
  configured: Record<string, string> | undefined,
  secrets: Record<string, string>,
): Record<string, string> {
  return { ...(configured ?? {}), ...secrets };
}
