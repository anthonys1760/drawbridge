import { useEffect, useRef, useState } from "preact/hooks";
import { scale } from "../../../docs/design/tokens";

interface Taint {
  tainted: boolean;
  sources: string[];
}
interface Hit {
  rule: string;
  path: string;
  span: [number, number];
  note?: string;
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
  scanner?: { verdict?: string; hits?: Hit[] };
  decision?: string;
  approval?: { pendingId?: string; channel?: string; by?: string; latencyMs?: number };
  taintAfter?: Taint;
  client?: { name?: string; version?: string };
}
interface State {
  now: string;
  paused: boolean;
  sessionId: string;
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
  const [announce, setAnnounce] = useState("");
  const [timerNote, setTimerNote] = useState("");
  const [toast, setToast] = useState("");
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

  useEffect(() => {
    if (theme === "system") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.dataset.theme = theme;
    localStorage.setItem("db-theme", theme);
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
          for (const call of body.pending) {
            if (!seen.current.has(call.id)) {
              seen.current.add(call.id);
              if (seen.current.size > 1 || document.hasFocus()) {
                setAnnounce(`New call waiting: ${call.tool ?? call.method ?? "tool"}`);
              }
            }
          }
          const flip = body.recent.find((event) => event.taintAfter?.tainted && event.tool);
          if (flip?.tool && !taintedSeen.current) {
            taintedSeen.current = true;
            setToast(`Untrusted content entered this session from ${flip.tool}`);
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
  const pending = (state?.pending ?? []).filter((call) =>
    `${call.tool ?? ""} ${call.reason ?? ""}`.toLowerCase().includes(filter.toLowerCase()),
  );
  const current = pending.find((call) => call.id === selected)
    ?? state?.recent.find((event) => event.id === selected)
    ?? null;
  const waiting = pending.length;

  useEffect(() => {
    document.title = waiting > 0 ? `(${waiting}) Drawbridge` : "Drawbridge";
  }, [waiting]);

  useEffect(() => {
    if (!current?.expiresAt || !current.tool) return;
    const left = Math.ceil((Date.parse(current.expiresAt) - gatewayNow) / 1000);
    for (const mark of [60, 30, 10]) {
      const key = `${current.id}:${mark}`;
      if (left === mark && !announced.current.has(key)) {
        announced.current.add(key);
        setTimerNote(`${current.tool} auto-deny in ${mark} seconds`);
      }
    }
  }, [current, gatewayNow]);

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
    setAnnounce("Press A again to approve");
    armedTimer.current = window.setTimeout(() => setArmed(false), 2000);
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
      if (!shortcuts || typing) return;
      if (event.key === "?" ) {
        helpRef.current?.showModal();
        return;
      }
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

  const recentDecision = state?.recent.find((event) => event.approval?.pendingId === selected);
  const decided = (state?.recent ?? []).filter((event) => event.approval?.pendingId);

  useEffect(() => {
    if (current && !recentDecision) denyRef.current?.focus();
  }, [current?.id, recentDecision?.id]);
  const expired = current?.expiresAt ? Date.parse(current.expiresAt) <= gatewayNow : false;
  const waitingTimeout = expired && !recentDecision;

  return (
    <div class="app">
      <a class="skip" href="#call-detail">Skip to call detail</a>
      <header class="topbar" style={{ height: scale.topbarH }}>
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
        <span class="grow" />
        <button class="ghost" type="button" onClick={() => setTheme(theme === "dark" ? "light" : theme === "light" ? "system" : "dark")}>
          {theme === "dark" ? "Dark" : theme === "light" ? "Light" : "System"}
        </button>
        <button class="ghost" type="button" onClick={() => pauseRef.current?.showModal()} disabled={offline}>
          Pause all calls
        </button>
      </header>
      <div class={mobileDetail ? "body detail-open" : "body"}>
        <section class="pane queue">
          <h2>Waiting for a decision</h2>
          <input ref={filterRef} class="filter" placeholder="Filter queue" value={filter} onInput={(event) => setFilter((event.target as HTMLInputElement).value)} />
          {pending.length === 0 ? (
            <div class="empty">
              <strong>No calls waiting</strong>
              <p>Calls that need a person show up here as they happen. If no one answers within 120 s, Drawbridge denies the call.</p>
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
                  <div class="meta">{shortId(call.sessionId)} · {age(call.ts, gatewayNow)} · {countdown(call.expiresAt, gatewayNow)}</div>
                  {call.taint?.tainted ? <span class="badge warn">Session tainted</span> : null}
                  <div class={secondsLeft(call.expiresAt, gatewayNow) < 10 ? "bar danger" : "bar"}><span style={{ width: `${bar(call)}%` }} /></div>
                </button>
              ))}
            </div>
          )}
          {decided.length > 0 ? (
            <>
              <h2>Recently decided</h2>
              <div class="list">
                {decided.slice(0, 6).map((event) => (
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
          <div class="tabs">
            <button type="button" class="ghost" onClick={() => setTab("call")}>Call</button>
            <button type="button" class="ghost" onClick={() => setTab("history")}>Session history</button>
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
                  {recentDecision ? null : <span role="timer">Auto-deny in {countdown(current.expiresAt, gatewayNow)}</span>}
                </div>
                <section class="panel">
                  <h2>Why Drawbridge held this call</h2>
                  <p>{current.reason}</p>
                  <p class="meta">{current.ruleId}</p>
                  <p class="badge warn">Policy saw: {current.taint?.tainted ? "tainted" : "not tainted"}</p>
                  <ol class="chain" aria-label="Why this call was held">
                    <li>Untrusted read · {(current.taint?.sources ?? []).join(", ") || "session"}</li>
                    <span class="arrow" aria-hidden="true">→</span>
                    <li>Scanner · {current.scanner?.verdict ?? "–"}</li>
                    <span class="arrow" aria-hidden="true">→</span>
                    <li>Session tainted</li>
                    <span class="arrow" aria-hidden="true">→</span>
                    <li>This call · {current.tool}</li>
                  </ol>
                  <p>The flow rule {current.ruleId} asks a person before any send once a session has read untrusted content. Unanswered calls are denied after 120 s.</p>
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
                  <p>{outcomeCopy(recentDecision)}</p>
                ) : (
                  <>
                    <button ref={denyRef} class="danger-btn" type="button" aria-keyshortcuts="D" disabled={offline || busy !== null} onClick={() => void decide("deny")}>
                      {busy === "deny" ? "Deny" : "Deny"}
                    </button>
                    <button class="primary" type="button" aria-keyshortcuts="A" disabled={offline || busy !== null} onClick={() => void decide("approve")}>
                      {busy === "approve" ? "Approve once" : armed ? "Press A again to approve" : "Approve once"}
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
        <p>J and K move the queue. D denies. A then A approves once. Enter activates the focused button, which starts on Deny.</p>
        <label><input type="checkbox" checked={shortcuts} onChange={(event) => { const on = (event.target as HTMLInputElement).checked; setShortcuts(on); localStorage.setItem("db-shortcuts", on ? "on" : "off"); }} /> Single-key shortcuts</label>
        <div class="row"><button class="ghost" type="button" onClick={() => helpRef.current?.close()}>Close</button></div>
      </dialog>
      <div class="live" aria-live="polite">{announce} {timerNote} {toast}</div>
    </div>
  );
}

function History({ events, current, embedded }: { events: Call[]; current?: string; embedded?: boolean }) {
  const ordered = [...events].reverse();
  return (
    <section class={embedded ? "embedded" : "pane history"} id={embedded ? undefined : "session-history"} tabIndex={-1} aria-label="Session history">
      <h2>Session history</h2>
      <ol>
        {ordered.map((event) => (
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

function Args({ value, hits }: { value: unknown; hits: Hit[] }) {
  const json = JSON.stringify(value ?? {}, null, 2);
  const recipient = typeof value === "object" && value && "to" in value ? String((value as { to?: unknown }).to) : "";
  return (
    <>
      <pre class="args">{recipient ? json.replace(recipient, `⟦${recipient}⟧`) : json}</pre>
      {recipient ? <p id="recipient-note">Review the recipient {recipient}. This is a review highlight, not a scanner hit.</p> : null}
      {hits.map((hit) => (
        <p key={`${hit.rule}:${hit.path}`}>Scanner hit {hit.rule}: {hit.note ?? hit.path}</p>
      ))}
    </>
  );
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

function countdown(expiresAt: string | undefined, now: number): string {
  const left = secondsLeft(expiresAt, now);
  const minutes = Math.floor(left / 60);
  const seconds = left % 60;
  return minutes > 0 ? `${minutes}m ${seconds}s` : `${seconds}s`;
}

function bar(call: Call): number {
  if (!call.ts || !call.expiresAt) return 100;
  const total = Date.parse(call.expiresAt) - Date.parse(call.ts);
  const left = Date.parse(call.expiresAt) - Date.now();
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
