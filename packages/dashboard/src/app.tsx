import { useEffect, useRef, useState } from "preact/hooks";
import { scale } from "../../../docs/design/tokens";
import {
  chainSteps,
  countdownLabel,
  crossedMarks,
  defaultSelection,
  hitNote,
  noteId,
  renderArgs,
  timeoutAnnouncements,
  type ViewHit,
} from "./view";

interface Taint {
  tainted: boolean;
  sources: string[];
}
interface Call {
  id: string;
  tool?: string;
  method?: string;
  upstream?: string;
  sessionId?: string;
  reason?: string;
  ruleId?: string;
  ts?: string;
  expiresAt?: string;
  argsRedacted?: unknown;
  argsHash?: string;
  taint?: Taint;
  scanner?: { verdict?: string; hits?: ViewHit[] };
  decision?: string;
  approval?: { pendingId?: string; channel?: string; by?: string; latencyMs?: number };
  taintAfter?: Taint;
  client?: { name?: string; version?: string };
}
interface State {
  now: string;
  paused: boolean;
  sessionId: string;
  timeoutSeconds?: number;
  pending: Call[];
  recent: Call[];
}

const DECISIONS: Record<string, string> = {
  allow: "Allowed",
  deny: "Denied by policy",
  approve_pending: "Held for a person",
  approved: "Approved",
  denied_by_human: "Denied by you",
  timeout: "Timed out · denied",
};

export function App() {
  const [state, setState] = useState<State | null>(null);
  const [offline, setOffline] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const [tab, setTab] = useState<"call" | "history">("call");
  const [mobileDetail, setMobileDetail] = useState(false);
  const [armed, setArmed] = useState(false);
  const [busy, setBusy] = useState<"approve" | "deny" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [clockOffset, setClockOffset] = useState(0);
  const [now, setNow] = useState(Date.now());
  const [live, setLive] = useState("");
  const [theme, setTheme] = useState(localStorage.getItem("db-theme") ?? "dark");
  const [shortcuts, setShortcuts] = useState(localStorage.getItem("db-shortcuts") !== "off");
  const seen = useRef(new Set<string>());
  const announced = useRef(new Set<string>());
  const taintedSeen = useRef(false);
  const filterRef = useRef<HTMLInputElement>(null);
  const denyRef = useRef<HTMLButtonElement>(null);
  const pauseRef = useRef<HTMLDialogElement>(null);
  const helpRef = useRef<HTMLDialogElement>(null);
  const armedTimer = useRef<number | undefined>(undefined);
  const liveTimer = useRef<number | undefined>(undefined);
  const prevLeft = useRef(new Map<string, number>());
  const sayRef = useRef<(message: string) => void>(() => undefined);

  sayRef.current = (message: string) => {
    window.clearTimeout(liveTimer.current);
    setLive("");
    liveTimer.current = window.setTimeout(() => setLive(message), 40);
  };

  useEffect(() => {
    const root = document.documentElement;
    const query = window.matchMedia("(prefers-color-scheme: light)");
    const apply = () => {
      const resolved = theme === "system" ? (query.matches ? "light" : "dark") : theme;
      root.dataset.theme = resolved;
    };
    apply();
    localStorage.setItem("db-theme", theme);
    if (theme !== "system") return;
    query.addEventListener("change", apply);
    return () => query.removeEventListener("change", apply);
  }, [theme]);

  useEffect(() => {
    void fetch("/now")
      .then((response) => response.json())
      .then((body: { now?: string }) => {
        if (body.now) setClockOffset(Date.parse(body.now) - Date.now());
      })
      .catch(() => undefined);
  }, []);

  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    let stop = false;
    async function poll() {
      while (!stop) {
        try {
          const response = await fetch("/api/state", { headers: apiHeaders() });
          if (!response.ok) throw new Error(String(response.status));
          const body = (await response.json()) as State;
          setState(body);
          setOffline(false);
          const timeouts = timeoutAnnouncements(body.recent, announced.current);
          for (const event of body.recent) {
            if (event.decision === "timeout") announced.current.add(event.id);
          }
          const fresh = body.pending.filter((call) => !seen.current.has(call.id));
          for (const call of body.pending) seen.current.add(call.id);
          if (timeouts[0]) sayRef.current(timeouts[0]);
          else if (fresh[0] && (seen.current.size > fresh.length || document.hasFocus())) {
            sayRef.current(`New call waiting: ${fresh[0].tool ?? fresh[0].method ?? "tool"}`);
          }
          const flip = body.recent.find((event) => event.taintAfter?.tainted && event.tool);
          if (flip?.tool && !taintedSeen.current) {
            taintedSeen.current = true;
            if (!timeouts[0] && fresh.length === 0) sayRef.current(`Untrusted content entered this session from ${flip.tool}`);
          }
        } catch {
          setOffline(true);
        }
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }
    }
    void poll();
    return () => {
      stop = true;
    };
  }, []);

  const gatewayNow = now + clockOffset;
  const timeoutSeconds = state?.timeoutSeconds ?? 120;
  const allPending = state?.pending ?? [];
  const pending = allPending.filter((call) =>
    `${call.tool ?? ""} ${call.reason ?? ""}`.toLowerCase().includes(filter.toLowerCase()),
  );
  const keepIds = (state?.recent ?? []).flatMap((event) => {
    const ids = event.decision === "approve_pending" ? [event.id] : [];
    return event.approval?.pendingId ? [...ids, event.approval.pendingId] : ids;
  });
  const current = allPending.find((call) => call.id === selected)
    ?? state?.recent.find((event) => event.id === selected)
    ?? null;
  const waiting = allPending.length;

  useEffect(() => {
    const next = defaultSelection(selected, allPending.map((call) => call.id), keepIds);
    if (next !== selected) setSelected(next);
  });

  useEffect(() => {
    document.title = waiting > 0 ? `(${waiting}) Drawbridge` : "Drawbridge";
  }, [waiting]);

  const recentDecision = state?.recent.find((event) => event.approval?.pendingId === selected);

  useEffect(() => {
    if (!current?.expiresAt || !current.tool || recentDecision) return;
    const left = secondsLeft(current.expiresAt, gatewayNow);
    const previous = prevLeft.current.get(current.id);
    prevLeft.current.set(current.id, left);
    for (const mark of crossedMarks(previous, left)) {
      const key = `${current.id}:${mark}`;
      if (announced.current.has(key)) continue;
      announced.current.add(key);
      sayRef.current(`${current.tool} auto-deny in ${mark} seconds`);
    }
  });

  function disarm() {
    setArmed(false);
    window.clearTimeout(armedTimer.current);
  }

  async function decide(action: "approve" | "deny") {
    if (!current || busy) return;
    setBusy(action);
    setError(null);
    disarm();
    try {
      const response = await fetch("/api/decide", {
        method: "POST",
        headers: { ...apiHeaders(), "content-type": "application/json" },
        body: JSON.stringify({ id: current.id, action }),
      });
      if (!response.ok) throw new Error("record");
    } catch {
      setError("Couldn't record the decision. The call stays held.");
    } finally {
      setBusy(null);
    }
  }

  function armOrApprove() {
    if (!current) return;
    if (armed) {
      void decide("approve");
      return;
    }
    setArmed(true);
    sayRef.current("Press A again to approve");
    armedTimer.current = window.setTimeout(() => setArmed(false), 2000);
  }

  function openShortcuts() {
    helpRef.current?.showModal();
  }

  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      const target = event.target as HTMLElement | null;
      const typing = target?.tagName === "INPUT" || target?.tagName === "TEXTAREA";
      if (event.key === "Escape") {
        pauseRef.current?.close();
        helpRef.current?.close();
        disarm();
        return;
      }
      if (event.key === "Enter" && target?.tagName === "BUTTON") return;
      if (event.key === "?" && !typing) {
        openShortcuts();
        return;
      }
      if (!shortcuts || typing) return;
      if (event.key === "P" && event.shiftKey) {
        pauseRef.current?.showModal();
        return;
      }
      if (event.key === "/") {
        event.preventDefault();
        filterRef.current?.focus();
        return;
      }
      if (event.key === "j" || event.key === "J" || event.key === "ArrowDown") {
        event.preventDefault();
        move(1);
      } else if (event.key === "k" || event.key === "K" || event.key === "ArrowUp") {
        event.preventDefault();
        move(-1);
      } else if (event.key === "d" || event.key === "D") {
        void decide("deny");
      } else if (event.key === "a" || event.key === "A") {
        armOrApprove();
      } else if (event.key === "c" || event.key === "C") {
        if (current?.argsHash) void navigator.clipboard.writeText(current.argsHash);
      } else if (event.key === "h" || event.key === "H") {
        setTab("history");
        document.getElementById("session-history")?.focus();
      }
    }
    function move(delta: number) {
      if (pending.length === 0) return;
      const index = pending.findIndex((call) => call.id === selected);
      const next = index < 0 ? pending[delta > 0 ? 0 : pending.length - 1] : pending[(index + delta + pending.length) % pending.length];
      if (next) {
        setSelected(next.id);
        setMobileDetail(true);
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  async function pause(next: boolean) {
    await fetch("/api/pause", {
      method: "POST",
      headers: { ...apiHeaders(), "content-type": "application/json" },
      body: JSON.stringify({ paused: next }),
    });
    pauseRef.current?.close();
  }

  const decided = (state?.recent ?? []).filter((event) => event.approval?.pendingId).slice(-6);
  const steps = current ? chainSteps(current, state?.recent ?? []) : [];
  const left = secondsLeft(current?.expiresAt, gatewayNow);
  const expired = current?.expiresAt ? left === 0 : false;
  const waitingTimeout = expired && !recentDecision && current?.expiresAt !== undefined && gatewayNow - Date.parse(current.expiresAt) >= 5_000;

  useEffect(() => {
    if (current && !recentDecision) denyRef.current?.focus({ preventScroll: true, focusVisible: true } as FocusOptions);
  }, [current?.id, recentDecision?.id]);

  return (
    <div class="app">
      <a class="skip" href="#call-detail">Skip to call detail</a>
      <header class="topbar" style={{ minHeight: scale.topbarH }}>
        <svg class="mark" viewBox="0 0 18 18" aria-hidden="true">
          <rect width="18" height="18" rx="4" fill="var(--db-accent)" />
        </svg>
        <span class="word">Drawbridge</span>
        {offline ? (
          <span class="pill danger">Gateway not reachable</span>
        ) : state?.paused ? (
          <span class="pill warn">All calls paused</span>
        ) : (
          <span class="pill">Gateway running</span>
        )}
        <div class="top-actions">
          <details class="more">
            <summary class="ghost">Menu</summary>
          </details>
          <div class="more-actions">
            <button class="ghost" type="button" onClick={() => setTheme(theme === "dark" ? "light" : theme === "light" ? "system" : "dark")}>
              {theme === "dark" ? "Dark" : theme === "light" ? "Light" : "System"}
            </button>
            <button class="ghost" type="button" onClick={openShortcuts}>Shortcuts</button>
            <button class="ghost" type="button" onClick={() => pauseRef.current?.showModal()} disabled={offline}>
              Pause all calls
            </button>
          </div>
        </div>
      </header>
      <div class={mobileDetail ? "body detail-open" : "body"}>
        <section class="pane queue">
          <h2>Waiting for a decision</h2>
          <input
            ref={filterRef}
            class="filter"
            aria-label="Filter queue"
            placeholder="Filter queue"
            value={filter}
            onInput={(event) => setFilter((event.target as HTMLInputElement).value)}
          />
          {pending.length === 0 ? (
            <div class="empty">
              <strong>No calls waiting</strong>
              <p>Calls that need a person show up here as they happen. If no one answers within {timeoutSeconds} s, Drawbridge denies the call.</p>
            </div>
          ) : (
            <div class="list" role="listbox" aria-label="Pending calls">
              {pending.map((call) => (
                <button
                  key={call.id}
                  class="item"
                  role="option"
                  aria-selected={call.id === selected}
                  onClick={() => {
                    setSelected(call.id);
                    setMobileDetail(true);
                    disarm();
                  }}
                >
                  <div class="tool">{call.tool ?? call.method}</div>
                  <div class="meta">{call.reason}</div>
                  <div class="meta">{shortId(call.sessionId)} · {age(call.ts, gatewayNow)} · {countdownLabel(secondsLeft(call.expiresAt, gatewayNow))}</div>
                  {call.taint?.tainted ? <span class="badge warn">Session tainted</span> : null}
                  <div class={secondsLeft(call.expiresAt, gatewayNow) < 10 ? "bar danger" : "bar"}><span style={{ width: `${bar(call, gatewayNow)}%` }} /></div>
                </button>
              ))}
            </div>
          )}
          {decided.length > 0 ? (
            <>
              <h2>Recently decided</h2>
              <div class="list">
                {decided.map((event) => (
                  <button key={event.id} class="item" type="button" onClick={() => event.approval?.pendingId && setSelected(event.approval.pendingId)}>
                    <div class="tool">{event.tool ?? "call"}</div>
                    <div class="meta">{DECISIONS[event.decision ?? ""] ?? event.decision}</div>
                  </button>
                ))}
              </div>
            </>
          ) : null}
        </section>
        <section class="pane detail" id="call-detail" tabIndex={-1}>
          <div class="tabs" role="tablist" aria-label="Call detail">
            <button type="button" role="tab" class="ghost" aria-selected={tab === "call"} aria-controls="call-detail" onClick={() => setTab("call")}>Call</button>
            <button type="button" role="tab" class="ghost" aria-selected={tab === "history"} aria-controls="session-history" onClick={() => setTab("history")}>Session history</button>
          </div>
          {tab === "history" ? <History events={state?.recent ?? []} current={current?.id} embedded /> : null}
          {tab === "call" && !current ? (
            <div class="empty">
              <strong>{state?.paused ? "All calls paused" : "No calls waiting"}</strong>
              <p>Select a held call to review its arguments. Deny is the safe default.</p>
            </div>
          ) : null}
          {tab === "call" && current ? (
            <>
              <div class="detail-scroll">
                <button class="back" type="button" onClick={() => setMobileDetail(false)}>‹ Queue</button>
                <div class="header">
                  <h1>{current.tool ?? current.method}</h1>
                  {current.upstream ? <span class="badge">{current.upstream}</span> : null}
                  {current.sessionId ? <span class="badge mono" title={current.sessionId}>{shortId(current.sessionId)}</span> : null}
                  {current.client?.name ? <span class="badge">{current.client.name} {current.client.version ?? ""}</span> : null}
                  <span class={recentDecision ? (recentDecision.decision === "approved" ? "badge accent" : "badge danger") : "badge warn"}>
                    {recentDecision ? (DECISIONS[recentDecision.decision ?? ""] ?? recentDecision.decision) : DECISIONS.approve_pending}
                  </span>
                  {recentDecision ? null : (
                    <span role="timer" class={left < 10 ? "timer danger" : "timer"}>Auto-deny in {countdownLabel(left)}</span>
                  )}
                </div>
                <section class="panel">
                  <h2>Why Drawbridge held this call</h2>
                  <p>{current.reason}</p>
                  <p class="meta">{current.ruleId}</p>
                  <p class="badge warn">Policy saw: {current.taint?.tainted ? "tainted" : "not tainted"}</p>
                  <ol class="chain" aria-label="Why this call was held">
                    {steps.map((step, index) => (
                      <li key={step}>
                        {step}
                        {index < steps.length - 1 ? <span class="arrow" aria-hidden="true"> →</span> : null}
                      </li>
                    ))}
                  </ol>
                  <p>The flow rule {current.ruleId} asks a person before any send once a session has read untrusted content. Unanswered calls are denied after {timeoutSeconds} s.</p>
                </section>
                <section class="panel">
                  <h2>Arguments</h2>
                  <p class="meta">argsRedacted · secrets masked</p>
                  <Args value={current.argsRedacted} hits={current.scanner?.hits ?? []} />
                  <button class="ghost" type="button" onClick={() => current.argsHash && navigator.clipboard.writeText(current.argsHash)}>
                    Copy argsHash
                  </button>
                  <p class="meta mono" title={current.argsHash}>{current.argsHash}</p>
                </section>
              </div>
              <div class={recentDecision ? `actions ${recentDecision.decision === "approved" ? "approved" : "denied"}` : "actions"}>
                {recentDecision ? (
                  <p>
                    {outcomeCopy(recentDecision)}
                    {recentDecision.decision === "approved" ? null : ". Agent received a tool error: Blocked by policy"}
                  </p>
                ) : (
                  <>
                    <button ref={denyRef} class="danger-btn" type="button" aria-keyshortcuts="D" disabled={offline || busy !== null} onClick={() => void decide("deny")}>
                      {busy === "deny" ? <span class="spin" aria-hidden="true" /> : null}
                      Deny
                    </button>
                    <button class="primary" type="button" aria-keyshortcuts="A" disabled={offline || busy !== null} onClick={() => void decide("approve")}>
                      {busy === "approve" ? <span class="spin" aria-hidden="true" /> : null}
                      {armed ? "Press A again to approve" : "Approve once"}
                    </button>
                    <p class="hint">
                      {error ?? (waitingTimeout ? "Waiting for the gateway to record the timeout" : "Deny is the safe default. Approving lets this one call through; the next send asks again.")}
                    </p>
                  </>
                )}
              </div>
            </>
          ) : null}
        </section>
        <History events={state?.recent ?? []} current={current?.id} />
      </div>
      <dialog ref={pauseRef}>
        <h2>Pause all calls</h2>
        <p>Pause every tool call until you resume? Agents get a tool error in the meantime.</p>
        <div class="row">
          <button class="ghost" type="button" onClick={() => pauseRef.current?.close()}>Cancel</button>
          <button class="primary" type="button" autoFocus onClick={() => void pause(!state?.paused)}>{state?.paused ? "Resume" : "Pause"}</button>
        </div>
      </dialog>
      <dialog ref={helpRef}>
        <h2>Shortcuts</h2>
        <p>J and K move the queue. D denies. A then A approves once. Enter activates the focused button, which starts on Deny. Question mark opens this sheet.</p>
        <label><input type="checkbox" checked={shortcuts} onChange={(event) => { const on = (event.target as HTMLInputElement).checked; setShortcuts(on); localStorage.setItem("db-shortcuts", on ? "on" : "off"); }} /> Single-key shortcuts</label>
        <div class="row"><button class="ghost" type="button" onClick={() => helpRef.current?.close()}>Close</button></div>
      </dialog>
      <div class="live" aria-live="polite">{live}</div>
    </div>
  );
}

function History({ events, current, embedded }: { events: Call[]; current?: string; embedded?: boolean }) {
  const listRef = useRef<HTMLOListElement>(null);
  useEffect(() => {
    listRef.current?.lastElementChild?.scrollIntoView({ block: "nearest" });
  }, [events.length, current]);
  return (
    <section class={embedded ? "embedded" : "pane history"} id={embedded ? undefined : "session-history"} tabIndex={0} aria-label="Session history">
      <h2>Session history</h2>
      <ol ref={listRef}>
        {events.map((event) => (
          <li key={event.id} class={tone(event, current)}>
            <div class="mono">{event.tool ?? event.method ?? event.decision}</div>
            <div class="meta">{DECISIONS[event.decision ?? ""] ?? event.decision} · {event.reason}</div>
            {event.taintAfter?.tainted ? <div>Untrusted content entered · {event.scanner?.hits?.length ?? 0} scanner hits · wrapped as data</div> : null}
          </li>
        ))}
      </ol>
    </section>
  );
}

function Args({ value, hits }: { value: unknown; hits: ViewHit[] }) {
  const recipient = typeof value === "object" && value && "to" in value ? String((value as { to?: unknown }).to) : "";
  const recipientHit = hits.some((hit) => hit.path === "to" || hit.path.endsWith(".to"));
  const shown = !recipientHit && recipient
    ? [...hits, { rule: "review", path: "to", span: [0, recipient.length] as [number, number] }]
    : hits;
  const pieces = renderArgs(value ?? {}, shown);
  const notes = shown.filter((hit, index) => shown.findIndex((other) => noteKey(other) === noteKey(hit)) === index);
  return (
    <>
      <pre class="args">
        {pieces.map((piece, index) =>
          piece.hit ? (
            <mark key={index} class={piece.hit.rule === "review" ? "review" : "hit"} aria-describedby={piece.hit.noteId}>{piece.text}</mark>
          ) : (
            piece.text
          ),
        )}
      </pre>
      {notes.map((hit) => (
        <p key={noteKey(hit)} id={noteId(hit)}>
          {hit.rule === "review"
            ? `Review the recipient ${recipient}. This is a review highlight, not a scanner hit.`
            : hitNote(hit)}
        </p>
      ))}
    </>
  );
}

function noteKey(hit: ViewHit): string {
  return `${hit.rule}:${hit.path}:${hit.span[0]}:${hit.span[1]}`;
}

function apiHeaders(): Record<string, string> {
  return { "x-drawbridge-request": "1" };
}

function shortId(id?: string): string {
  if (!id) return "";
  return id.length > 10 ? `${id.slice(0, 6)}…${id.slice(-4)}` : id;
}

function age(ts: string | undefined, now: number): string {
  if (!ts) return "";
  const seconds = Math.max(0, Math.round((now - Date.parse(ts)) / 1000));
  return `${seconds}s ago`;
}

function secondsLeft(expiresAt: string | undefined, now: number): number {
  if (!expiresAt) return 0;
  return Math.max(0, Math.ceil((Date.parse(expiresAt) - now) / 1000));
}

function bar(call: Call, now: number): number {
  if (!call.ts || !call.expiresAt) return 100;
  const total = Date.parse(call.expiresAt) - Date.parse(call.ts);
  const left = Date.parse(call.expiresAt) - now;
  if (total <= 0) return 0;
  return Math.max(0, Math.min(100, (left / total) * 100));
}

function tone(event: Call, current?: string): string {
  if (event.id === current || event.decision === "approve_pending") return "warn";
  if (event.decision === "deny" || event.decision === "denied_by_human" || event.decision === "timeout") return "danger";
  if (event.taintAfter?.tainted) return "warn";
  return "accent";
}

function outcomeCopy(event: Call): string {
  if (event.decision === "approved") return "Approved once on the dashboard";
  if (event.decision === "timeout") return "Timed out, so Drawbridge denied it";
  return "Denied by you on the dashboard";
}
