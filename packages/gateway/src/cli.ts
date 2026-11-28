#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { parseArgs } from "node:util";
import { ConfigError, loadConfig, verifyAuditJsonl } from "@drawbridge/core";
import { approvalRequest, readApprovalState, writePaused } from "./approvals.js";
import { pinUpstreams } from "./pin.js";
import { serveConfig } from "./serve.js";

const HELP = `Drawbridge — MCP security gateway

Usage:
  drawbridge serve --config <file>
  drawbridge audit verify [--log <file>] [--config <file>]
  drawbridge pin --config <file>
  drawbridge pin update --config <file>
  drawbridge approvals list --config <file>
  drawbridge approvals approve <id> --config <file>
  drawbridge approvals deny <id> --config <file>
  drawbridge approvals url --config <file>
  drawbridge pause --config <file>
  drawbridge resume --config <file>

serve
  Stdio MCP server for 2026-07-28 clients. Connects to the upstreams in the
  config and forwards tools/list and tools/call under <upstream>__<tool> names.
  Tool rules, argument checks, rate limits, flows, and pins are enforced.

audit verify
  Recompute the hash chain in the JSONL audit log. Exits 0 when every event
  links to the previous hash, and 1 when a line was altered, reordered, or
  truncated out of the middle of the chain.

pin
  Connect to the configured upstreams and write definition hashes to pins.path.
  \`pin update\` replaces an existing pin file. A later definition change is
  denied, or held, according to onPinMismatch.

approvals
  Talk to a running gateway's local dashboard. \`list\` prints held calls.
  \`approve\` and \`deny\` resolve one pending id. Approving once does not
  allow the next identical call. \`url\` prints the dashboard address with
  its per-run token.

pause, resume
  Deny every new tool call, and auto-deny calls that are already waiting.
  The choice is written to drawbridge-pause.json beside the audit log, so a
  restart stays paused until \`drawbridge resume\`. If the gateway is not
  running, the command only writes that file.
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
    if (command === "pin") {
      const configPath = required(values.config, "pin requires --config <file>");
      const config = await readConfig(configPath);
      const update = positionals[1] === "update";
      if (positionals[1] !== undefined && !update) {
        throw new Error(`Unknown pin command "${positionals[1]}". Use \`drawbridge pin update\`.`);
      }
      const pinPath = resolve(config.pins.path);
      const count = await pinUpstreams(config, pinPath, update);
      process.stdout.write(`${update ? "updated" : "pinned"} ${count} tool${count === 1 ? "" : "s"} in ${pinPath}\n`);
      return;
    }
    if (command === "pause" || command === "resume") {
      const config = await readConfig(required(values.config, `${command} requires --config <file>`));
      await pauseCommand(command === "pause", config.audit.path);
      return;
    }
    if (command === "approvals") {
      const config = await readConfig(required(values.config, "approvals requires --config <file>"));
      await approvalsCommand(positionals[1], positionals[2], config.audit.path);
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

async function pauseCommand(paused: boolean, auditPath: string): Promise<void> {
  const verb = paused ? "paused" : "resumed";
  try {
    await readApprovalState(auditPath);
  } catch {
    await writePaused(auditPath, paused);
    process.stdout.write(`${verb} (gateway is not running; the next start keeps this)\n`);
    return;
  }
  try {
    const { status, body } = await approvalRequest(auditPath, "/api/pause", {
      method: "POST",
      body: { paused, channel: "cli" },
    });
    if (status !== 200) {
      throw new Error(`${verb} failed (${status}) ${(body as { error?: string }).error ?? ""}`.trim());
    }
  } catch (error) {
    await writePaused(auditPath, paused);
    const detail = error instanceof Error ? error.message : String(error);
    if (/failed \(/.test(detail)) throw error;
    process.stdout.write(`${verb} (gateway is not running; the next start keeps this)\n`);
    return;
  }
  process.stdout.write(`${verb}\n`);
}

async function approvalsCommand(sub: string | undefined, id: string | undefined, auditPath: string): Promise<void> {
  if (sub === "url") {
    const state = await readApprovalState(auditPath);
    process.stdout.write(`${state.url}?token=${state.token}\n`);
    return;
  }
  if (sub === "list") {
    const { status, body } = await approvalRequest(auditPath, "/api/state");
    if (status !== 200) throw new Error(`approvals list failed (${status})`);
    const pending = (body as { pending?: { id: string; tool?: string; expiresAt?: string; reason?: string }[] }).pending ?? [];
    if (pending.length === 0) {
      process.stdout.write("No calls waiting\n");
      return;
    }
    for (const call of pending) {
      process.stdout.write(`${call.id}\t${call.tool ?? ""}\t${call.expiresAt ?? ""}\t${call.reason ?? ""}\n`);
    }
    return;
  }
  if ((sub === "approve" || sub === "deny") && id) {
    const { status, body } = await approvalRequest(auditPath, "/api/decide", {
      method: "POST",
      body: { id, action: sub === "approve" ? "approve" : "deny", channel: "cli" },
    });
    if (status === 409) throw new Error("That call is no longer waiting");
    if (status !== 200) throw new Error(`approvals ${sub} failed (${status}) ${(body as { error?: string }).error ?? ""}`);
    process.stdout.write(`${sub === "approve" ? "approved" : "denied"} ${id}\n`);
    return;
  }
  throw new Error("Use approvals list, approvals approve <id>, approvals deny <id>, or approvals url");
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
