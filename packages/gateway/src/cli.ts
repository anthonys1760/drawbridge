#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { parseArgs } from "node:util";
import { ConfigError, loadConfig, verifyAuditJsonl } from "@drawbridge/core";
import { serveConfig } from "./serve.js";

const HELP = `Drawbridge — MCP security gateway

Usage:
  drawbridge serve --config <file>
  drawbridge audit verify [--log <file>] [--config <file>]

serve
  Stdio MCP server for 2026-07-28 clients. Connects to the upstreams in the
  config and forwards tools/list and tools/call under <upstream>__<tool> names.

audit verify
  Recompute the hash chain in the JSONL audit log. Exits 0 when every event
  links to the previous hash, and 1 when a line was altered, reordered, or
  truncated out of the middle of the chain.
`;

async function main(): Promise<void> {
  const { values, positionals } = parseArgs({
    args: process.argv.slice(2),
    options: {
      config: { type: "string", short: "c" },
      log: { type: "string" },
      help: { type: "boolean", short: "h" },
    },
    allowPositionals: true,
  });

  if (values.help) {
    process.stdout.write(HELP);
    return;
  }

  const command = positionals[0] ?? "serve";
  try {
    if (command === "serve") {
      const config = await readConfig(required(values.config, "serve requires --config <file>"));
      await serveConfig(config);
      return;
    }
    if (command === "audit" && positionals[1] === "verify") {
      const logPath = await resolveLogPath(values.log, positionals[2], values.config);
      const text = await readFile(logPath, "utf8").catch((error: unknown) => {
        throw new Error(`Cannot read audit log ${logPath}: ${error instanceof Error ? error.message : String(error)}`);
      });
      const result = verifyAuditJsonl(text);
      if (!result.ok) {
        const where = result.line === undefined ? "" : ` (line ${result.line})`;
        process.stderr.write(`audit verify failed: ${result.error}${where}\n`);
        process.exitCode = 1;
        return;
      }
      process.stdout.write(`audit verify ok: ${result.events} event${result.events === 1 ? "" : "s"}\n`);
      return;
    }
  } catch (error) {
    if (error instanceof ConfigError) {
      process.stderr.write(`drawbridge: ${error.message}\n`);
      process.exitCode = 1;
      return;
    }
    process.stderr.write(`drawbridge: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
    return;
  }

  process.stderr.write(HELP);
  process.exitCode = 1;
}

async function resolveLogPath(
  log: string | undefined,
  positional: string | undefined,
  configPath: string | undefined,
): Promise<string> {
  if (log) return resolve(log);
  if (positional) return resolve(positional);
  if (configPath) {
    const config = await readConfig(configPath);
    return resolve(config.audit.path);
  }
  throw new Error("audit verify requires --log <file> or --config <file>");
}

async function readConfig(path: string) {
  const text = await readFile(path, "utf8").catch((error: unknown) => {
    throw new ConfigError(`Cannot read config ${path}: ${error instanceof Error ? error.message : String(error)}`);
  });
  return loadConfig(text);
}

function required(value: string | undefined, message: string): string {
  if (!value) throw new Error(message);
  return value;
}

main().catch((error: unknown) => {
  process.stderr.write(`drawbridge: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
