import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const root = fileURLToPath(new URL("..", import.meta.url));
export const cli = join(root, "packages/gateway/dist/cli.js");
export const demo = join(root, "examples/demo-upstream/dist/index.js");

const gatewayRequire = createRequire(new URL("../packages/gateway/package.json", import.meta.url));

let sdk;

export async function loadSdk() {
  if (sdk) return sdk;
  const client = await import(pathToFileURL(gatewayRequire.resolve("@modelcontextprotocol/client")).href);
  const stdio = await import(pathToFileURL(gatewayRequire.resolve("@modelcontextprotocol/client/stdio")).href);
  sdk = {
    Client: client.Client,
    StdioClientTransport: stdio.StdioClientTransport,
    getDefaultEnvironment: stdio.getDefaultEnvironment,
  };
  return sdk;
}

export function quote(value) {
  return JSON.stringify(value);
}

export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function resultText(result) {
  const content = result && Array.isArray(result.content) ? result.content : [];
  return content.map((block) => (typeof block?.text === "string" ? block.text : "")).join("\n");
}

export async function readEvents(auditPath) {
  const text = await readFile(auditPath, "utf8").catch(() => "");
  if (text.length === 0) return [];
  const lines = text.split("\n");
  if (lines.at(-1) === "") lines.pop();
  return lines.filter((line) => line.length > 0).map((line) => JSON.parse(line));
}

export async function waitForEvents(auditPath, pred, ms = 12_000) {
  const start = Date.now();
  let events = [];
  while (Date.now() - start < ms) {
    events = await readEvents(auditPath);
    if (pred(events)) return events;
    await sleep(40);
  }
  events = await readEvents(auditPath);
  const summary = events.map((event) => `${event.decision}:${event.tool ?? event.method}`).join(", ");
  throw new Error(`timed out waiting for the audit log (${summary || "empty"})`);
}

export function runCli(args, env = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [cli, ...args], {
      cwd: root,
      env: { ...process.env, ...env },
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    child.on("close", (code) => resolve({ code: code ?? 1, stdout, stderr }));
  });
}

async function waitForExit(pid) {
  const started = Date.now();
  while (Date.now() - started < 5_000) {
    try {
      process.kill(pid, 0);
    } catch {
      return;
    }
    await sleep(50);
  }
}

/**
 * Start a gateway on a fresh temp config. `__AUDIT__` in the yaml is replaced
 * with the audit path. `beforeServe` runs after the file is written and before
 * the client connects (used to pin tools).
 */
export async function withGateway(yaml, fn, options = {}) {
  const dir = await mkdtemp(join(tmpdir(), "drawbridge-attack-"));
  const auditPath = join(dir, "audit.jsonl");
  const configPath = join(dir, "drawbridge.yaml");
  const rendered = yaml.replaceAll("__AUDIT__", quote(auditPath)).replaceAll("__DIR__", dir);
  await writeFile(configPath, rendered);
  if (options.beforeServe) await options.beforeServe({ dir, auditPath, configPath });
  const { Client, StdioClientTransport, getDefaultEnvironment } = await loadSdk();
  const stderr = [];
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [cli, "serve", "--config", configPath],
    env: { ...getDefaultEnvironment(), ...(options.env ?? {}) },
    stderr: "pipe",
  });
  transport.stderr?.on("data", (chunk) => {
    stderr.push(typeof chunk === "string" ? chunk : chunk.toString());
  });
  const client = new Client(
    { name: "attack-client", version: "0.1.0" },
    { versionNegotiation: { mode: { pin: "2026-07-28" } } },
  );
  try {
    await client.connect(transport);
    return await fn({
      client,
      auditPath,
      configPath,
      dir,
      stderr: () => stderr.join(""),
    });
  } catch (error) {
    const detail = stderr.join("");
    const message = error instanceof Error ? error.message : String(error);
    if (detail && !message.includes(detail.slice(0, 80))) {
      throw new Error(`${message}\n${detail}`);
    }
    throw error;
  } finally {
    const pid = transport.pid ?? undefined;
    await client.close().catch(() => undefined);
    if (pid !== undefined) await waitForExit(pid);
    await rm(dir, { recursive: true, force: true });
  }
}

export async function dashboardText(auditPath) {
  const state = JSON.parse(await readFile(join(dirname(auditPath), "drawbridge-approvals.json"), "utf8"));
  const response = await fetch(`${state.url}api/state`, {
    headers: {
      Authorization: `Bearer ${state.token}`,
      "X-Drawbridge-Request": "1",
    },
  });
  return response.text();
}

export async function denyPending(auditPath, configPath, tool) {
  const events = await waitForEvents(
    auditPath,
    (rows) => rows.some((row) => row.decision === "approve_pending" && row.tool === tool),
  );
  const pending = events.find((row) => row.decision === "approve_pending" && row.tool === tool);
  const denied = await runCli(["approvals", "deny", pending.id, "--config", configPath]);
  if (denied.code !== 0) throw new Error(denied.stderr || denied.stdout || "deny failed");
  return pending.id;
}

export function stdioUpstream(name, args, options = {}) {
  const command = [process.execPath, demo, ...args].map((part) => quote(part)).join(", ");
  const trusted = options.trusted === true;
  return `  ${name}:
    transport: stdio
    command: [${command}]
    trusted: ${trusted}
${options.extra ?? ""}`;
}
