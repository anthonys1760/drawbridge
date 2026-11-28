import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { createReadStream } from "node:fs";
import { readFile, rm, stat, writeFile } from "node:fs/promises";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { dirname, extname, join, normalize, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { AuditApproval, AuditEvent, AuditScanner, AuditTaint } from "@drawbridge/core";

export type ApprovalChannel = "elicitation" | "dashboard" | "cli";
export type ApprovalAction = "approve" | "deny" | "timeout";

export interface PendingView {
  id: string;
  tool: string;
  upstream: string;
  sessionId: string;
  reason: string;
  ruleId?: string;
  taint: AuditTaint;
  argsRedacted: unknown;
  argsHash: string;
  expiresAt: string;
  ts: string;
  client: { name?: string; version?: string };
  scanner?: AuditScanner;
}

export interface ApprovalResolution {
  action: ApprovalAction;
  channel?: ApprovalChannel;
  by?: string;
  eventId?: string;
}

interface Slot {
  view: PendingView;
  mode: "inline" | "retry";
  resolution?: ApprovalResolution;
  waiters: Array<(value: ApprovalResolution) => void>;
  timer: ReturnType<typeof setTimeout>;
  commit: (resolution: ApprovalResolution) => Promise<string | undefined>;
  committing?: Promise<void>;
  claimed: boolean;
}

export function approvalStatePath(auditPath: string): string {
  return join(dirname(auditPath), "drawbridge-approvals.json");
}

export class ApprovalHub {
  readonly token: string;
  paused = false;
  private readonly slots = new Map<string, Slot>();

  constructor(token = randomBytes(32).toString("hex")) {
    this.token = token;
  }

  sign(id: string): string {
    const mac = createHmac("sha256", this.token).update(id).digest("hex");
    return `${id}.${mac}`;
  }

  verify(state: string | undefined): string | undefined {
    if (!state) return undefined;
    const dot = state.lastIndexOf(".");
    if (dot <= 0) return undefined;
    const id = state.slice(0, dot);
    const mac = state.slice(dot + 1);
    const expected = createHmac("sha256", this.token).update(id).digest("hex");
    const left = Buffer.from(mac);
    const right = Buffer.from(expected);
    if (left.length !== right.length || !timingSafeEqual(left, right)) return undefined;
    return this.slots.has(id) ? id : undefined;
  }

  open(
    view: PendingView,
    mode: "inline" | "retry",
    commit: (resolution: ApprovalResolution) => Promise<string | undefined>,
  ): void {
    const rawDelay = Date.parse(view.expiresAt) - Date.now();
    const delay = Number.isFinite(rawDelay) ? Math.min(Math.max(0, rawDelay), 2_147_483_647) : 0;
    const timer = setTimeout(() => {
      void this.finish(view.id, { action: "timeout" });
    }, delay);
    this.slots.set(view.id, { view, mode, waiters: [], timer, commit, claimed: false });
  }

  list(): PendingView[] {
    return [...this.slots.values()].filter((slot) => !slot.resolution).map((slot) => slot.view);
  }

  peek(id: string): PendingView | undefined {
    return this.slots.get(id)?.view;
  }

  resolution(id: string): ApprovalResolution | undefined {
    return this.slots.get(id)?.resolution;
  }

  mode(id: string): "inline" | "retry" | undefined {
    return this.slots.get(id)?.mode;
  }

  async decide(id: string, resolution: ApprovalResolution): Promise<boolean> {
    if (resolution.action === "timeout") return false;
    return this.finish(id, resolution);
  }

  /**
   * One caller forwards an approved call. A second identical approval does
   * not forward again, and the next tool call is a new pending id.
   */
  claim(id: string): boolean {
    const slot = this.slots.get(id);
    if (!slot || slot.resolution?.action !== "approve" || slot.claimed) return false;
    slot.claimed = true;
    return true;
  }

  wait(id: string): Promise<ApprovalResolution> {
    const slot = this.slots.get(id);
    if (!slot) return Promise.reject(new Error(`Unknown approval ${id}`));
    if (slot.resolution) {
      return (slot.committing ?? Promise.resolve()).then(() => slot.resolution as ApprovalResolution);
    }
    return new Promise((resolve) => slot.waiters.push(resolve));
  }

  close(): void {
    for (const slot of this.slots.values()) clearTimeout(slot.timer);
  }

  private async finish(id: string, resolution: ApprovalResolution): Promise<boolean> {
    const slot = this.slots.get(id);
    if (!slot || slot.resolution) return false;
    slot.resolution = resolution;
    clearTimeout(slot.timer);
    slot.committing = slot
      .commit(resolution)
      .then((eventId) => {
        if (!eventId) resolution.action = "deny";
        else resolution.eventId = eventId;
      })
      .catch(() => {
        resolution.action = "deny";
      });
    await slot.committing;
    for (const waiter of slot.waiters.splice(0)) waiter(resolution);
    this.forgetSettled();
    return true;
  }

  private forgetSettled(): void {
    const settled = [...this.slots.entries()].filter(([, slot]) => slot.resolution);
    if (settled.length <= 100) return;
    const oldest = settled.slice(0, settled.length - 100);
    for (const [id] of oldest) this.slots.delete(id);
  }
}

export interface ApprovalServer {
  port: number;
  token: string;
  url: string;
  close: () => Promise<void>;
}

const COOKIE = "db_token";

export async function startApprovalServer(options: {
  hub: ApprovalHub;
  auditPath: string;
  sessionId: string;
  channels: ApprovalChannel[];
}): Promise<ApprovalServer> {
  const dashboardDir = resolve(fileURLToPath(new URL("../../dashboard/dist", import.meta.url)));
  const fontsDir = resolve(fileURLToPath(new URL("../../../site/fonts", import.meta.url)));
  const statePath = approvalStatePath(options.auditPath);

  const server = createServer((req, res) => {
    void handle(req, res, { ...options, dashboardDir, fontsDir }).catch((error: unknown) => {
      const message = error instanceof Error ? error.message : String(error);
      sendJson(res, 500, { error: message });
    });
  });

  await new Promise<void>((resolveListen, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolveListen());
  });
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("approval server failed to bind");
  const port = address.port;
  const url = `http://127.0.0.1:${port}/`;
  await writeFile(
    statePath,
    `${JSON.stringify({ port, token: options.hub.token, pid: process.pid, url })}\n`,
    { mode: 0o600 },
  );

  return {
    port,
    token: options.hub.token,
    url,
    close: async () => {
      options.hub.close();
      await rm(statePath, { force: true });
      await new Promise<void>((resolveClose, reject) => {
        server.close((error) => (error ? reject(error) : resolveClose()));
      });
    },
  };
}

async function handle(
  req: IncomingMessage,
  res: ServerResponse,
  options: {
    hub: ApprovalHub;
    auditPath: string;
    sessionId: string;
    channels: ApprovalChannel[];
    dashboardDir: string;
    fontsDir: string;
  },
): Promise<void> {
  const remote = req.socket.remoteAddress;
  if (remote !== "127.0.0.1" && remote !== "::ffff:127.0.0.1") {
    sendJson(res, 403, { error: "Dashboard is local only" });
    return;
  }
  const port = localPort(req);
  const host = req.headers.host ?? "";
  if (host !== `127.0.0.1:${port}` && host !== `localhost:${port}`) {
    sendJson(res, 403, { error: "Host is not the local dashboard" });
    return;
  }

  const url = new URL(req.url ?? "/", `http://127.0.0.1:${port}`);
  if (url.pathname === "/" && url.searchParams.has("token")) {
    if (!safeEqual(url.searchParams.get("token") ?? "", options.hub.token)) {
      sendJson(res, 401, { error: "Bad token" });
      return;
    }
    res.writeHead(302, {
      Location: "/",
      "Set-Cookie": `${COOKIE}=${options.hub.token}; HttpOnly; SameSite=Strict; Path=/`,
      "Cache-Control": "no-store",
    });
    res.end();
    return;
  }

  if (url.pathname === "/now" && req.method === "GET") {
    sendJson(res, 200, { now: new Date().toISOString() });
    return;
  }

  if (url.pathname.startsWith("/api/")) {
    if (!authorized(req, options.hub.token)) {
      sendJson(res, 401, { error: "Unauthorized" });
      return;
    }
    if (!sameOrigin(req, port) || req.headers["x-drawbridge-request"] !== "1") {
      sendJson(res, 403, { error: "Cross-site request blocked" });
      return;
    }
    await api(req, res, url, options);
    return;
  }

  if (req.method !== "GET" && req.method !== "HEAD") {
    sendJson(res, 405, { error: "Method not allowed" });
    return;
  }
  if (url.pathname.startsWith("/fonts/")) {
    await sendFile(res, options.fontsDir, url.pathname.slice("/fonts/".length));
    return;
  }
  const relative = url.pathname === "/" ? "index.html" : url.pathname.slice(1);
  await sendFile(res, options.dashboardDir, relative);
}

async function api(
  req: IncomingMessage,
  res: ServerResponse,
  url: URL,
  options: {
    hub: ApprovalHub;
    auditPath: string;
    sessionId: string;
    channels: ApprovalChannel[];
  },
): Promise<void> {
  if (url.pathname === "/api/state" && req.method === "GET") {
    const recent = await readRecent(options.auditPath);
    sendJson(res, 200, {
      now: new Date().toISOString(),
      paused: options.hub.paused,
      sessionId: options.sessionId,
      pending: options.hub.list(),
      recent,
    });
    return;
  }
  if (url.pathname === "/api/now" && req.method === "GET") {
    sendJson(res, 200, { now: new Date().toISOString() });
    return;
  }
  if (url.pathname === "/api/pause" && req.method === "POST") {
    const body = await readBody(req);
    const paused = Boolean(body && typeof body === "object" && (body as { paused?: unknown }).paused === true);
    options.hub.paused = paused;
    sendJson(res, 200, { paused });
    return;
  }
  if (url.pathname === "/api/decide" && req.method === "POST") {
    const body = await readBody(req);
    const record = body && typeof body === "object" ? (body as { id?: unknown; action?: unknown; channel?: unknown }) : {};
    const id = record.id;
    const action = record.action;
    const bearer = typeof req.headers.authorization === "string" && req.headers.authorization.startsWith("Bearer ");
    const channel: ApprovalChannel = bearer && record.channel === "cli" ? "cli" : "dashboard";
    if (!options.channels.includes(channel)) {
      sendJson(res, 403, { error: `${channel} approvals are disabled` });
      return;
    }
    if (typeof id !== "string" || (action !== "approve" && action !== "deny")) {
      sendJson(res, 400, { error: "Expected id and action approve or deny" });
      return;
    }
    const ok = await options.hub.decide(id, { action, channel, by: channel });
    if (!ok) {
      sendJson(res, 409, { error: "That call is no longer waiting" });
      return;
    }
    sendJson(res, 200, { ok: true });
    return;
  }
  sendJson(res, 404, { error: "Not found" });
}

export async function readApprovalState(auditPath: string): Promise<{ port: number; token: string; url: string }> {
  const text = await readFile(approvalStatePath(auditPath), "utf8");
  const parsed = JSON.parse(text) as { port?: unknown; token?: unknown; url?: unknown };
  if (typeof parsed.port !== "number" || typeof parsed.token !== "string" || typeof parsed.url !== "string") {
    throw new Error("Approval state file is unreadable");
  }
  return { port: parsed.port, token: parsed.token, url: parsed.url };
}

export async function approvalRequest(
  auditPath: string,
  path: string,
  init: { method?: string; body?: unknown } = {},
): Promise<{ status: number; body: unknown }> {
  const state = await readApprovalState(auditPath);
  const response = await fetch(new URL(path, state.url), {
    method: init.method ?? "GET",
    headers: {
      Authorization: `Bearer ${state.token}`,
      "X-Drawbridge-Request": "1",
      ...(init.body !== undefined ? { "Content-Type": "application/json" } : {}),
    },
    body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
  });
  const text = await response.text();
  return { status: response.status, body: text ? (JSON.parse(text) as unknown) : {} };
}

function authorized(req: IncomingMessage, token: string): boolean {
  const header = req.headers.authorization;
  if (typeof header === "string" && header.startsWith("Bearer ") && safeEqual(header.slice(7), token)) return true;
  const cookie = req.headers.cookie ?? "";
  const match = cookie.split(";").map((part) => part.trim()).find((part) => part.startsWith(`${COOKIE}=`));
  return match !== undefined && safeEqual(decodeURIComponent(match.slice(COOKIE.length + 1)), token);
}

function sameOrigin(req: IncomingMessage, port: number): boolean {
  const origin = req.headers.origin;
  if (origin === undefined) return true;
  return origin === `http://127.0.0.1:${port}` || origin === `http://localhost:${port}`;
}

function localPort(req: IncomingMessage): number {
  const address = req.socket.localPort;
  return typeof address === "number" ? address : 0;
}

function safeEqual(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

async function readBody(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  if (chunks.length === 0) return {};
  return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
}

async function readRecent(auditPath: string): Promise<AuditEvent[]> {
  const text = await readFile(auditPath, "utf8").catch(() => "");
  const lines = text.split("\n").filter((line) => line.length > 0).slice(-40);
  const events: AuditEvent[] = [];
  for (const line of lines) {
    try {
      events.push(JSON.parse(line) as AuditEvent);
    } catch {
      // A partial last line is ignored. verify still owns integrity.
    }
  }
  return events;
}

async function sendFile(res: ServerResponse, root: string, relative: string): Promise<void> {
  const cleaned = normalize(relative).replace(/^(\.\.(\/|\\|$))+/, "");
  const path = resolve(root, cleaned);
  if (!path.startsWith(resolve(root))) {
    sendJson(res, 403, { error: "Forbidden" });
    return;
  }
  const info = await stat(path).catch(() => undefined);
  if (!info?.isFile()) {
    sendJson(res, 404, { error: "Not found" });
    return;
  }
  res.writeHead(200, { "Content-Type": contentType(path), "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" });
  createReadStream(path).pipe(res);
}

function contentType(path: string): string {
  switch (extname(path)) {
    case ".html":
      return "text/html; charset=utf-8";
    case ".css":
      return "text/css; charset=utf-8";
    case ".js":
      return "text/javascript; charset=utf-8";
    case ".woff2":
      return "font/woff2";
    case ".svg":
      return "image/svg+xml";
    default:
      return "application/octet-stream";
  }
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(payload),
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  });
  res.end(payload);
}

export type { AuditApproval };
