import { resultFixture, sampleFile, tamperedLog, verifiedLog } from "./sample.js";
import { sha256, stableStringify } from "./verify.js";

const CHAPTERS = [
  { id: "setup", label: "0:00 Setup", start: 0, end: 3 },
  { id: "read", label: "0:20 Poisoned read", start: 4, end: 7 },
  { id: "exfil", label: "0:50 Exfiltration attempt", start: 8, end: 8 },
  { id: "decision", label: "1:15 Human decision", start: 9, end: 9 },
  { id: "audit", label: "1:35 Audit replay", start: 9, end: 9, chain: true },
];

const DECISIONS = {
  allow: "Allowed",
  deny: "Denied by policy",
  approve_pending: "Held for a person",
  approved: "Approved",
  denied_by_human: "Denied by you",
  timeout: "Timed out · denied",
};
const ICONS = {
  allow: "✓",
  deny: "✕",
  approve_pending: "…",
  approved: "✓",
  denied_by_human: "✕",
  timeout: "✕",
};

const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
const params = new URLSearchParams(window.location.search);

const state = {
  name: sampleFile,
  text: verifiedLog,
  events: parseLog(verifiedLog),
  selected: 8,
  chainFocus: false,
  playing: false,
  speed: 1,
  timer: 0,
  verification: { status: "verifying", done: 0, total: 0 },
  fixtureHash: "",
};

const chainEl = document.querySelector("#chain");
const rowsEl = document.querySelector("#rows");
const inspectorEl = document.querySelector("#inspector");
const chaptersEl = document.querySelector("#chapters");
const noteEl = document.querySelector("#sample-note");
const playEl = document.querySelector("#play");
const speedEl = document.querySelector("#speed");
const themeEl = document.querySelector("#theme");

chaptersEl.replaceChildren(
  ...CHAPTERS.map((chapter, index) => {
    const button = document.createElement("button");
    button.type = "button";
    button.id = `chapter-${chapter.id}`;
    button.setAttribute("role", "tab");
    button.setAttribute("aria-selected", "false");
    button.dataset.chapter = String(index);
    button.textContent = chapter.label;
    button.addEventListener("click", () => jumpChapter(index));
    return button;
  }),
);

document.querySelector("#sample-verified").addEventListener("click", () => loadText(verifiedLog, sampleFile, "sample"));
document.querySelector("#sample-tampered").addEventListener("click", () => loadText(tamperedLog, "audit.sample.tampered.jsonl", "tampered"));
document.querySelector("#file").addEventListener("change", (event) => {
  const file = event.target.files && event.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => loadText(String(reader.result ?? ""), file.name, "file");
  reader.readAsText(file);
});
playEl.addEventListener("click", () => setPlaying(!state.playing));
speedEl.addEventListener("click", () => {
  state.speed = state.speed === 1 ? 2 : 1;
  speedEl.textContent = `${state.speed}×`;
  if (state.playing) setPlaying(true);
});
themeEl.addEventListener("click", () => {
  const next = document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light";
  document.documentElement.setAttribute("data-theme", next);
  themeEl.textContent = next === "light" ? "Dark" : "Light";
  try {
    localStorage.setItem("drawbridge-theme", next);
  } catch {
    /* the page still switches for this view */
  }
});
themeEl.textContent = document.documentElement.getAttribute("data-theme") === "light" ? "Dark" : "Light";

window.addEventListener("keydown", (event) => {
  const tag = event.target instanceof Element ? event.target.tagName : "";
  if (tag === "INPUT" || tag === "TEXTAREA") return;
  if (event.key === "ArrowRight") {
    event.preventDefault();
    select(state.selected + 1, false);
  } else if (event.key === "ArrowLeft") {
    event.preventDefault();
    select(state.selected - 1, false);
  } else if (event.key === " ") {
    event.preventDefault();
    setPlaying(!state.playing);
  } else if (event.key >= "1" && event.key <= "5") {
    jumpChapter(Number(event.key) - 1);
  } else if (event.key === "Home") {
    event.preventDefault();
    select(0, false);
  } else if (event.key === "End") {
    event.preventDefault();
    select(state.events.length - 1, false);
  } else if (event.key === "v" || event.key === "V") {
    void verify(state.text);
  }
});

function parseLog(text) {
  const lines = text.split("\n");
  if (lines.at(-1) === "") lines.pop();
  return lines.map((line, index) => {
    try {
      const event = JSON.parse(line);
      return event && typeof event === "object" ? event : { id: `line-${index + 1}`, parseError: true };
    } catch {
      return { id: `line-${index + 1}`, parseError: true };
    }
  });
}

function loadText(text, name, kind) {
  state.text = text;
  state.name = name;
  state.events = parseLog(text);
  state.chainFocus = false;
  const requested = Number(params.get("entry"));
  if (kind === "tampered") select(Number.isFinite(requested) && requested > 0 ? requested - 1 : 4, false);
  else if (kind === "sample") select(Number.isFinite(requested) && requested > 0 ? requested - 1 : 8, false);
  else select(0, false);
  void verify(text);
}

function select(index, chain) {
  const last = Math.max(0, state.events.length - 1);
  state.selected = Math.min(last, Math.max(0, index));
  state.chainFocus = chain;
  render();
  const row = rowsEl.querySelector('[aria-current="true"]');
  row?.scrollIntoView({ block: "nearest" });
  if (chain) chainEl.focus();
}

function jumpChapter(index) {
  const chapter = CHAPTERS[index];
  if (!chapter) return;
  setPlaying(false);
  select(Math.min(chapter.start, Math.max(0, state.events.length - 1)), Boolean(chapter.chain));
}

function setPlaying(playing) {
  state.playing = playing && state.events.length > 0;
  playEl.textContent = state.playing ? "Pause" : "Play";
  playEl.setAttribute("aria-pressed", state.playing ? "true" : "false");
  window.clearInterval(state.timer);
  if (!state.playing) return;
  const interval = 2500 / state.speed;
  state.timer = window.setInterval(() => {
    if (state.chainFocus) {
      setPlaying(false);
      return;
    }
    if (state.selected >= state.events.length - 1) {
      select(state.selected, true);
      setPlaying(false);
      return;
    }
    select(state.selected + 1, false);
  }, interval);
}

function chapterIndex() {
  if (state.chainFocus) return 4;
  const found = CHAPTERS.findIndex((chapter, index) => index < 4 && state.selected >= chapter.start && state.selected <= chapter.end);
  return found === -1 ? 0 : found;
}

function decisionLabel(decision) {
  return DECISIONS[decision] ?? decision ?? "—";
}

function recordKind(event) {
  if (event.approval?.pendingId) return "decision";
  if (event.expiresAt) return "pending";
  if (event.resultHash && event.intentId) return "outcome";
  if (!event.resultHash && !event.intentId) return "intent";
  return "record";
}

function chainMark(index) {
  const verification = state.verification;
  if (verification.status === "verifying") return "…";
  if (verification.status === "broken" && index + 1 >= verification.line) return "✗";
  if (verification.status === "verified") return "✓";
  if (verification.status === "broken" && index + 1 < verification.line) return "✓";
  return "—";
}

function render() {
  noteEl.textContent = `Sample session for the demo. Each row is one AuditEvent from ${state.name}.`;
  const currentChapter = chapterIndex();
  for (const button of chaptersEl.querySelectorAll("[role=tab]")) {
    button.setAttribute("aria-selected", button.dataset.chapter === String(currentChapter) ? "true" : "false");
  }
  renderChain();
  renderRows();
  renderInspector();
}

function renderChain() {
  const verification = state.verification;
  const count = state.events.length;
  chainEl.className = "chain";
  chainEl.replaceChildren();
  if (verification.status === "verifying") {
    chainEl.setAttribute("role", "status");
    chainEl.append(text(`Checking ${verification.done} of ${verification.total || count}`));
    return;
  }
  if (verification.status === "verified") {
    chainEl.classList.add("verified");
    chainEl.setAttribute("role", "status");
    chainEl.append(text(`Hash chain verified. All ${verification.events} entries match their hashes and link to the entry before.`));
    return;
  }
  if (verification.status === "broken") {
    chainEl.classList.add("broken");
    chainEl.setAttribute("role", "alert");
    const k = verification.line;
    const n = count;
    const before = Math.max(0, k - 1);
    chainEl.append(
      text(
        `Chain broken at entry ${k} of ${n}. Entry ${k} no longer matches its recorded hash, so it changed after it was written. Entries 1–${before} verify; ${k}–${n} can't be trusted.`,
      ),
    );
    const jump = document.createElement("button");
    jump.type = "button";
    jump.textContent = `Jump to entry ${k}`;
    jump.addEventListener("click", () => select(k - 1, false));
    chainEl.append(jump);
    return;
  }
  chainEl.setAttribute("role", "status");
  chainEl.append(text(verification.error || "This log can't be verified"));
}

function renderRows() {
  const verification = state.verification;
  rowsEl.replaceChildren(
    ...state.events.map((event, index) => {
      const row = document.createElement("tr");
      if (index === state.selected) row.setAttribute("aria-current", "true");
      const broken = verification.status === "broken" && index + 1 >= verification.line;
      if (broken) row.classList.add("broken");
      row.append(
        cell(String(index + 1)),
        cell(event.tool || event.method || "unreadable", `${recordKind(event)} · ${event.upstream ?? ""}`),
        cell(decisionLabel(event.decision), event.ruleId || ""),
        scannerCell(event),
        cell(chainMark(index), broken ? "unverified" : ""),
      );
      row.addEventListener("click", () => {
        setPlaying(false);
        select(index, false);
      });
      return row;
    }),
  );
}

function scannerCell(event) {
  const node = document.createElement("td");
  node.className = "col-scanner";
  const verdict = event.scanner?.verdict;
  node.textContent = verdict ? verdict[0].toUpperCase() + verdict.slice(1) : "–";
  if (event.taintAfter?.tainted) node.title = "Session tainted after this call";
  return node;
}

function cell(primary, secondary) {
  const node = document.createElement("td");
  const main = document.createElement("div");
  main.className = "mono";
  main.textContent = primary;
  node.append(main);
  if (secondary) {
    const sub = document.createElement("div");
    sub.className = "subtle";
    sub.textContent = secondary;
    node.append(sub);
  }
  return node;
}

function renderInspector() {
  const event = state.events[state.selected];
  inspectorEl.replaceChildren();
  if (!event || event.parseError) {
    inspectorEl.append(card("Event", "This line is not a JSON object."));
    return;
  }
  inspectorEl.append(policyCard(event), scannerCard(event), taintCard(event), integrityCard(event));
  const evidence = resultCard(event);
  if (evidence) inspectorEl.append(evidence);
  if (state.verification.status === "broken" && state.selected + 1 === state.verification.line) {
    inspectorEl.append(card("Tamper note", "The log can show that something changed, not what it was. Compare against another copy of the log."));
  }
}

function policyCard(event) {
  const node = card("Policy verdict");
  node.append(badge(decisionLabel(event.decision), event.decision));
  node.append(line(`Rule ${event.ruleId || "—"}`));
  if (event.reason) node.append(line(event.reason));
  if (event.expiresAt) node.append(line(`expiresAt ${localTime(event.expiresAt)}`));
  if (event.approval) {
    const approval = event.approval;
    const bits = [approval.channel, approval.by, approval.latencyMs !== undefined ? `${approval.latencyMs} ms` : ""]
      .filter(Boolean)
      .join(" · ");
    node.append(line(bits));
    if (approval.pendingId) node.append(line(`Resolves ${shortId(approval.pendingId)}`));
  }
  node.append(heading("Arguments"));
  node.append(line("argsRedacted · secrets masked"));
  const pre = document.createElement("pre");
  pre.textContent = JSON.stringify(event.argsRedacted, null, 2);
  node.append(pre);
  return node;
}

function scannerCard(event) {
  const node = card("Scanner verdict");
  if (!event.scanner) {
    node.append(line("–"));
    return node;
  }
  node.append(badge(event.scanner.verdict[0].toUpperCase() + event.scanner.verdict.slice(1), event.scanner.verdict));
  for (const hit of event.scanner.hits ?? []) {
    node.append(line(`${hit.rule} · ${hit.target} · ${hit.path}`));
  }
  return node;
}

function taintCard(event) {
  const node = card("Taint");
  const saw = event.taint?.tainted ? "Policy saw: tainted" : "Policy saw: not tainted";
  node.append(line(saw));
  const sources = event.taint?.sources?.length ? event.taint.sources.join(", ") : "none";
  node.append(line(`Sources ${sources}`));
  if (event.taintAfter) {
    node.append(line("Session tainted after this call"));
    node.append(line(`After this entry: ${event.taintAfter.tainted ? "Tainted" : "Not tainted"} — introduced here`));
  }
  return node;
}

function integrityCard(event) {
  const node = card("Integrity");
  const index = state.selected + 1;
  const verification = state.verification;
  if (verification.status === "verified") node.append(line("Hash matches. Linked to the previous entry."));
  else if (verification.status === "broken" && index === verification.line) node.append(line(verification.error));
  else if (verification.status === "broken" && index > verification.line) node.append(line("Not checked. The chain broke earlier."));
  else if (verification.status === "broken") node.append(line("Hash matches. Linked to the previous entry."));
  else node.append(line("Checking this entry."));
  node.append(hashRow("prevHash", event.prevHash));
  node.append(hashRow("hash", event.hash));
  return node;
}

function resultCard(event) {
  const hit = event.scanner?.hits?.some((item) => item.target === "result");
  if (!hit || !event.resultHash) return null;
  const node = card("Result evidence");
  if (state.fixtureHash && state.fixtureHash === event.resultHash) node.append(line("matches resultHash"));
  else node.append(line("Fixture doesn't match this entry"));
  return node;
}

function hashRow(label, value) {
  const row = document.createElement("div");
  row.className = "hash";
  const name = document.createElement("span");
  name.className = "subtle";
  name.textContent = label;
  const code = document.createElement("code");
  code.textContent = value ? `${value.slice(0, 12)}…` : "—";
  code.title = value || "";
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = "Copy";
  button.addEventListener("click", () => {
    if (value && navigator.clipboard) void navigator.clipboard.writeText(value).catch(() => undefined);
  });
  row.append(name, code, button);
  return row;
}

function card(title, body) {
  const node = document.createElement("section");
  node.className = "card";
  const headingNode = document.createElement("h2");
  headingNode.textContent = title;
  node.append(headingNode);
  if (body) node.append(line(body));
  return node;
}

function heading(text) {
  const node = document.createElement("h2");
  node.textContent = text;
  return node;
}

function line(value) {
  const node = document.createElement("p");
  node.textContent = value;
  return node;
}

function badge(label, kind) {
  const node = document.createElement("p");
  const icon = document.createElement("span");
  icon.setAttribute("aria-hidden", "true");
  icon.textContent = `${ICONS[kind] ?? ""} `;
  const textNode = document.createElement("span");
  textNode.className = `badge ${kind || ""}`;
  textNode.append(icon, document.createTextNode(label));
  node.append(textNode);
  return node;
}

function text(value) {
  const node = document.createElement("p");
  node.textContent = value;
  return node;
}

function shortId(id) {
  if (typeof id !== "string" || id.length < 12) return id || "";
  return `${id.slice(0, 6)}…${id.slice(-4)}`;
}

function localTime(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString(undefined, { hour: "numeric", minute: "2-digit", second: "2-digit", timeZoneName: "short" });
}

function verify(text) {
  state.verification = { status: "verifying", done: 0, total: state.events.length };
  render();
  return new Promise((resolve) => {
    let worker;
    try {
      worker = new Worker(new URL("./verify-worker.js", import.meta.url), { type: "module" });
    } catch (error) {
      state.verification = { status: "unverifiable", error: error instanceof Error ? error.message : String(error) };
      render();
      resolve();
      return;
    }
    worker.onmessage = (event) => {
      if (event.data?.progress) {
        state.verification = { status: "verifying", done: event.data.progress.done, total: event.data.progress.total };
        renderChain();
        return;
      }
      if (event.data?.error) {
        state.verification = { status: "unverifiable", error: event.data.error };
      } else if (event.data?.result?.ok) {
        state.verification = { status: "verified", events: event.data.result.events };
      } else if (event.data?.result) {
        state.verification = {
          status: "broken",
          line: event.data.result.line,
          error: event.data.result.error,
          events: event.data.result.events,
        };
      }
      worker.terminate();
      render();
      resolve();
    };
    worker.onerror = () => {
      state.verification = { status: "unverifiable", error: "The verifier worker failed to start." };
      worker.terminate();
      render();
      resolve();
    };
    worker.postMessage(text);
  });
}

const initial = params.get("sample") === "tampered" ? "tampered" : "sample";
sha256(stableStringify(resultFixture)).then((hash) => {
  state.fixtureHash = hash;
  render();
});
loadText(initial === "tampered" ? tamperedLog : verifiedLog, initial === "tampered" ? "audit.sample.tampered.jsonl" : sampleFile, initial);
if (!reducedMotion && params.get("play") !== "0") setPlaying(true);
