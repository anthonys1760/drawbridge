> **Decisions (Anthony, Nov 27, 2026 6:47 PM ET, relayed by Ultron):**
> 1. Direction A "Keep" is final.
> 2. Approvals are **once-only** in v0.1 ("Approve once"; no session allow).
> 3. Demo policy drops `allowDomains` on `mail__send`; rule order unchanged, the no-send-after-untrusted flow rule holds the send for approval at the 0:50 beat.
> 4. Hosted read-only replay **ships in v0.1** as a static page on anthonysdigital.net with fixture files (mocks: m6_replay_verified / m6_replay_broken).
> 5. **Schema:** Drawbridge PR #1 landed on `main` at `a27415c`. Milestone 2 is PR #5 (`eaf5516`). Milestone 3 is PR #7, head `aec688b`, unmerged. The source of truth is [`docs/audit-schema.md`](https://github.com/anthonys1760/drawbridge/blob/aec688b/docs/audit-schema.md) in that PR (`packages/core/src/audit.ts` implements it).
> 6. **Taint:** `taint` is the session state **before** the event (what the policy saw). `taintAfter` is `{ tainted: boolean, sources: string[] }`, the same shape as `taint`, written only when this event changes that state. A bare boolean is rejected. The UI marks the flip on the introducing event from `taintAfter` (§7a).
> 7. **Hash:** `sha256(prevHash + stableStringify(event without hash))`, lowercase hex with no separator, from a genesis of 64 zeros. `taintAfter` and `intentId` are part of the hashed JSON when present. See §3a.
> 8. **Recipient redaction** is in `packages/core/src/redact.ts`: keep the domain and mask only the local part as the first character plus `•••` (U+2022), e.g. `j•••@outsidecorp.com`. In the sample, `q4-sync@outside-sample.example` is logged as `q•••@outside-sample.example`. Secret keys, Bearer tokens and `sk-` keys stay `[REDACTED]`.

*Aligned to Milestone 3 PR #7 (head `aec688b`, unmerged) and `docs/audit-schema.md` on Nov 27, 2026, 7:17 PM ET. §8 lists what that PR closed and the remaining mismatches.*

# Drawbridge UI spec: M4 approval dashboard and M6 hosted replay

Direction A, "Keep" (see DIRECTION.md). Stack: React + Vite in `packages/dashboard`, per the canvas, styled with `tokens.css` custom properties. `tokens.ts` mirrors them for tests and SVG. No Tailwind is assumed, because the canvas doesn't list it. If Ultron adds Tailwind, map `theme.extend.colors` to `var(--db-*)`.

All data in the mocks is **SAMPLE**, shaped to `docs/audit-schema.md` in PR #7.
- `sample/generate.mjs` writes `sample/audit.sample.jsonl`, 10 entries. Allowed calls are an intent plus an outcome with `intentId`. The pending call has `expiresAt` and no `scanner` (arguments are not scanned). The decision links with `approval.pendingId` and does not repeat `scanner`. Entry 6 (the poisoned read's outcome) sets `taintAfter: { tainted: true, sources: ["notes"] }`. Sources are upstream names. `tools/list` does not taint.
- `sample/canonical.mjs` is a verbatim port of the repo's `stableStringify` and `eventHash`. The generator's `redact()` / `maskEmail()` match `packages/core/src/redact.ts` in PR #7.
- `fixtures/notes__read.q4-notes.result.json` is produced by PR #7's `applyScanner` in wrap mode. The whole `content[0].text` is wrapped with `<<untrusted>>\n` … `\n<<end untrusted>>`. `resultHash` is `sha256(stableStringify)` of that object, and spans are the original matches shifted by 14 UTF-16 units, indexing the text the client receives. `fixtures/q4-notes.md` is the unwrapped upstream doc.
- `sample/audit.sample.tampered.jsonl` has entry 5 rewritten, so it breaks there. `sample/audit.sample.taintAfter.jsonl` is the same clean log (taintAfter is in the main sample now) so crosscheck can name it.
- `node sample/verify.mjs` proves all of this. `node sample/crosscheck-repo.mjs <built core dist/index.js>` runs PR #7's `verifyAuditJsonl` (schema plus hash) on the same files. Default core build: `/tmp/db-pr7/packages/core/dist/index.js`.
- The demo upstream is `notes` (`notes__read`), matching `examples/demo-upstream`. `mail` is still the future demo send server.

| Mock | File |
|---|---|
| M4 pending (desktop, 1440×900 @2x) | `mocks/m4_pending.png` |
| M4 decided (denied) | `mocks/m4_decided.png` |
| M4 empty | `mocks/m4_empty.png` |
| M4 mobile approval card (390 wide, viewport and full scroll) | `mocks/m4_mobile.png`, `mocks/m4_mobile_full.png` |
| M6 replay, chain verified, step 3 | `mocks/m6_replay_verified.png` |
| M6 replay, chain broken at entry 5 | `mocks/m6_replay_broken.png` |
| Direction B, same screen | `mocks/dirB_pending.png` |
| README hero 1280×640 (+@2x), mark, wordmark | `brand/` |

To rebuild: `node sample/generate.mjs && cd src && python3 build.py && node render.mjs '[["m4_pending",1440,900,2,0]]'`. The HTML is the source of truth for spacing.

---

## 1. Layout grid

Base unit 4px. All spacing uses `--db-space-*`. Radii: 6 for controls, 10 for panels.

### M4 dashboard (desktop-primary)
| Breakpoint | Columns | Notes |
|---|---|---|
| ≥1200px | `340px queue │ 1fr detail │ 360px history` | Top bar is 56px. The detail pane scrolls on its own, and the action bar (72px) sticks to its bottom. |
| 768–1199 | `300px queue │ 1fr detail` | History becomes a "Session history" tab inside the detail pane, beside "Call". |
| <768 | One column | Queue is a list; tapping opens the detail as its own view with a "‹ Queue" back link. The action bar is fixed to the viewport bottom with 48px buttons in a 2-col grid. The chain stacks vertically and history collapses into a `<details>`. Because the dashboard binds to 127.0.0.1, this layout serves narrow desktop windows and the hosted demo. A phone can't reach the local dashboard. |

Detail pane order, top to bottom: header (tool, chips, timer) → **Why Drawbridge held this call** (flow rule and taint source chain) → **Arguments** (no scanner hits; a neutral review highlight on the recipient is optional) → action bar. The detail pane has 28px side padding on desktop and 16px on mobile.

### M6 replay (static, read-only)
Rows: top bar 56 → chain status bar (≈56) → stepper + chapter track (≈96) → body `600px event table │ 1fr inspector`. Below 1024 the inspector stacks under the table. Below 768 the table drops the Scanner column and keeps # / Call / Policy / Chain.

## 2. Components and states

| Component | States | Notes |
|---|---|---|
| **TopBar** | default · paused (kill switch on) · disconnected | On pause, the "Gateway running" pill turns to warn "All calls paused". On disconnect it shows danger "Gateway not reachable" and every action button is disabled with the reason. The SAMPLE pill appears only in demo/fixture mode. |
| **QueueItem** | default · hover (`raised`) · selected (raised + 2px warn bar) · focus (2px `focus` ring, 2px offset) · expiring (<10 s: countdown in danger) · decided (moves to "Recently decided") | Shows tool (mono), Tainted badge if `taint.tainted`, reason, sessionId, age, countdown and a 3px bar. |
| **DecisionBadge** | allow · deny · approve_pending · approved · denied_by_human · timeout | Always icon + text, never color alone. Copy is in §5. |
| **ScannerBadge** | clean / omitted (neutral) · flagged (`mode: warn`) · wrapped (`mode: wrap`) · blocked (`mode: block`, danger) | In block mode the client gets an error and no payload. `resultHash` covers that error; spans index the withheld upstream text. |
| **CountdownTimer** | running · <30 s · <10 s (danger) · expired | `role="timer"`. See §4 for announcements. |
| **WhyPanel** | flow rule (taint chain shown) · arg rule (shows the failed constraint, e.g. `to` outside `allowDomains`) · rate limit · tool-definition changed (shows a diff of the old and new description, the one place a real *diff* makes sense) | The chain nodes are: untrusted read → scanner verdict → session tainted → this call. |
| **ArgsViewer** | default · has hits (line gutter bar plus `<mark>` on the span, with the rule id and plain-language note under the line) · truncated (>200 lines: "Show all") · masked values (`[REDACTED:secret]` stays verbatim) | Pretty JSON, line numbers, monospace. A copy button copies `argsHash`, never raw args. |
| **ActionBar** | pending · arming approve (keyboard, see §3) · submitting (buttons disabled, spinner in pressed button) · decided (approved: accent-soft bar; denied: danger-soft bar with what the agent was told) · error ("Couldn't record the decision. The call stays held." + Retry) | |
| **HistoryTimeline** | Node styles: allowed (accent ring) · untrusted entered (warn fill, with excerpt) · held now (solid warn) · denied (danger) | Oldest first, newest at the bottom, auto-scrolled to the current call. |
| **EmptyState** | no pending · gateway paused · policy invalid (the gateway refuses to start, so the dashboard shows only that error) | |
| **ChainStatusBar** (M6) | verifying (neutral, progress "Checking 3 of 6") · verified (accent-soft) · broken at N (danger-soft, `role="alert"`, "Jump to entry N") · unverifiable (log has no hashes: neutral "This log can't be verified") | |
| **Stepper + ChapterTrack** (M6) | playing · paused · at start · at end · chapter selected | 5 chapters mapped to the demo script (§3). Chapters are a `tablist`. Playback is 1×/2× and advances one event every 2.5 s at 1×. |
| **EventTable** (M6) | current row (raised + 2px accent left bar) · untrusted rows after a break (diagonal danger hatch + ✗ in Chain column) | |
| **Inspector** (M6) | per event: Policy verdict · Scanner verdict · Taint · Integrity · Result evidence (only when a fixture matches `resultHash`) · Tamper note (at the break entry) | |

Buttons: height 36 on desktop and 44 on touch (`--db-target-min`). Primary is Approve (accent fill). Deny is danger outline on danger-soft. Ghost is for tertiary actions. Destructive and safe actions never sit in the same visual weight slot across screens: Deny is always left of Approve.

## 3. Interactions and keyboard

**Principles:** the safe action is the easy one, nothing steals focus, and approval is deliberate.

### M4 dashboard
| Key | Action |
|---|---|
| `J` / `↓` | Next pending call |
| `K` / `↑` | Previous pending call |
| `D` | **Deny** the selected call immediately. Deny is safe and reversible in practice, since the agent can retry. |
| `A` then `A` within 2 s | **Approve once.** The first press arms it: the button label changes to "Press A again to approve" and a polite live region says the same. A second press confirms, and anything else disarms it. A mouse or touch click on Approve once confirms directly, since it's already deliberate. |
| `Enter` | Activates the focused button. **Initial focus in the action bar is Deny**, so a stray Enter never approves. |
| `C` | Copy `argsHash` |
| `H` | Move focus to the session history |
| `/` | Filter queue |
| `Shift+P` | Pause all calls (kill switch). A confirm dialog opens, focus goes to "Pause", and Esc cancels. Pausing fails closed, so it's safe. |
| `?` | Shortcut sheet (dialog) |

- Single-key shortcuts can be turned off or remapped in Settings, as WCAG 2.1.4 requires. They're ignored while focus is in an input.
- A new pending call never moves focus or the selection. It's added to the queue, the tab title changes to `(3) Drawbridge`, and a polite live region says "New call waiting: tracker__create_issue".
- When a decision is recorded, the item moves to "Recently decided", the bar shows the outcome, and `J` jumps to the next call. Selection doesn't auto-advance, so you see what happened.
- **Timeout:** the countdown is driven only by `expiresAt` on the `approve_pending` record, compared with the gateway clock (`GET /now` on connect, to avoid local clock skew). There's no fallback to `ts + timeoutSeconds`. The `timeout` record arrives with `approval.pendingId`, and the item then becomes "Timed out · denied". If `expiresAt` passes and no record arrives within 5 s, show "Waiting for the gateway to record the timeout" rather than inventing one.
- **Pairing:** a decision (`approved`, `denied_by_human`, `timeout`) is matched to its pending call **only** by `approval.pendingId`. Approvals are once-only, so a retry is a new pending record with a new countdown.
- **Flagged reads (demo 0:20):** a read that's allowed but wrapped doesn't create a queue item, but the history panel and a polite toast ("Untrusted content entered this session from notes__read") make it visible. This covers the demo's "dashboard lights up" beat without a fake approval.
- **High risk:** the dashboard is the out-of-band channel. It never offers in-client elicitation for the same item, and it never shows secrets (`argsRedacted` only).

### M6 replay
| Key | Action |
|---|---|
| `←` / `→` | Previous / next event |
| `Space` | Play / pause |
| `1`–`5` | Jump to a chapter |
| `Home` / `End` | First / last event |
| `V` | Re-run verification |

Chapters map the demo script to event ranges: **0:00 Setup** (entries 1–4: tools/list intent + outcome for `notes` and `mail`) · **0:20 Poisoned read** (entries 5–8: notes__read q4-notes, where the outcome record 6 carries the scanner hits and introduces taint; then notes__read q4-roadmap, which the policy sees as tainted) · **0:50 Exfiltration attempt** (entry 9: mail__send `approve_pending` with `expiresAt`, held by `flows.no-send-after-untrusted-content`; there's no `allowDomains` on `mail__send` any more) · **1:15 Human decision** (entry 10: `denied_by_human`, `approval.pendingId` = entry 9) · **1:35 Audit replay** (the chain check, where focus goes to the ChainStatusBar). The timestamps are *video* cues, not log times. The replay is driven by events, not by the clock.

### 3a. Replay verification algorithm (matches PR #7 `verifyAuditJsonl`)
This runs client-side on load in a Web Worker, so the UI stays responsive, and it uses WebCrypto `SHA-256`.
```
prev = "0" × 64                                   // GENESIS_HASH
for line, n = 1..N (split on "\n", drop one trailing empty line):
  blank line            → broken at n ("blank line in audit log")
  JSON.parse fails      → broken at n ("line is not valid JSON")
  schema fails          → broken at n ("line is not an audit event")   // strict: unknown keys fail
  event.prevHash ≠ prev → broken at n ("prevHash does not match the previous event")
  { hash, ...rest } = event
  sha256hex(rest.prevHash + stableStringify(rest)) ≠ hash → broken at n ("hash does not match the event contents")
  prev = hash
verified, head = prev
```
- **`stableStringify`:** no whitespace. Keys are sorted with plain `Array#sort` (UTF-16 code units), `undefined` object entries are dropped, and `undefined` array entries become `null`. Primitives go through `JSON.stringify`. `prevHash` is both the prefix and a field inside the JSON. Only `hash` is removed. Output is lowercase hex.
- **Port it verbatim.** Don't use a library. `sample/canonical.mjs` is the reference port, and `sample/verify.mjs` is the test. `taintAfter` and `intentId` are part of the hashed JSON when present, and part of the schema: a present field must have the right shape (for `taintAfter`, `{ tainted, sources }`, not a boolean).
- **Re-canonicalize every line.** Key order in the file doesn't matter, so the UI must never hash the raw line text.
- **What a failure means:** at line *k*, entries 1…k−1 are verified and k…N are unverified. The banner says "Chain broken at entry k of N" and the error string goes in the Integrity card. A broken entry never "explains" what changed; the log can only prove that it changed.
- **Result evidence:** for a hit with `target: "result"`, the page loads the matching fixture (`fixtures/<tool>.<name>.result.json`). It shows "matches resultHash" only when `sha256(stableStringify(fixture)) === resultHash`, and otherwise "Fixture doesn't match this entry" with no excerpt.

## 4. Accessibility
- **Contrast:** see §6. Every text pair is AA in both themes. Controls and focus rings are ≥3:1.
- **Focus:** `outline: 2px solid var(--db-focus); outline-offset: 2px` on every interactive element, including queue items (`role="option"`). Never remove outline without a replacement.
- **Focus order:** skip link "Skip to call detail" → top bar → queue (listbox; arrow keys move within it, Tab leaves) → detail header → Why → Arguments → action bar (Deny, then Approve once) → history.
- **Screen readers:**
  - Queue: `role="listbox"` `aria-label="Pending calls"`. Each option reads, for example, "mail__send, tainted session, Untrusted content entered this session, auto-deny in 1 minute 24 seconds".
  - Timer: `role="timer"` with no live region on the ticking value. A separate `aria-live="polite"` region announces at 60, 30 and 10 seconds, and on expiry: "mail__send timed out and was denied."
  - JSON highlights: each `<mark>` gets `aria-describedby` pointing at its note, for example "Scanner hit exfil.unexpected-recipient: recipient is outside this session's known contacts."
  - Taint chain: `<ol aria-label="Why this call was held">`, with arrows `aria-hidden`.
  - Badges: the text is the label. Icons are `aria-hidden`.
  - Chain status: `role="status"` when verified, `role="alert"` when broken, announced once.
  - Approve/Deny: `aria-keyshortcuts="A"` / `"D"`.
- **Color independence:** status always has an icon and words. Broken rows add a hatch and ✗, and tainted values get a gutter bar plus an underline as well as the fill.
- **Reduced motion:** `prefers-reduced-motion` zeroes `--db-dur-*`. Countdown bars step once a second with no tweening, autoplay is off in the replay, and there's no pulsing on new items, only the count changes.
- **Zoom/reflow:** works at 400% (320 CSS px) using the <768 layout. Mono values wrap with `word-break: break-word` instead of truncating important ids. Truncation with an ellipsis is only for hashes, which come with a copy button and the full value in `title`.
- **Touch:** targets are ≥44px on <768.

## 5. Copy strings
| Key | String |
|---|---|
| queue.title | Waiting for a decision |
| queue.empty.title | No calls waiting |
| queue.empty.body | Calls that need a person show up here as they happen. If no one answers within {timeoutSeconds} s, Drawbridge denies the call. |
| queue.recent | Recently decided |
| detail.why.title | Why Drawbridge held this call |
| detail.why.flowFooter | The flow rule {flowName} asks a person before any send once a session has read untrusted content. Unanswered calls are denied after {timeoutSeconds} s. |
| detail.args.title | Arguments |
| detail.args.sub | argsRedacted · secrets masked |
| timer.label | Auto-deny in |
| action.deny | Deny |
| action.approve | Approve once |
| action.approve.armed | Press A again to approve |
| action.hint | Deny is the safe default. Approving lets this one call through; the next send asks again. |
| decided.denied | Denied by you on the dashboard |
| decided.approved | Approved once on the dashboard |
| decided.timeout | Timed out, so Drawbridge denied it |
| decided.agentSaw | Agent received a tool error: Blocked by policy |
| decided.error | Couldn't record the decision. The call stays held. |
| decision.allow / deny / approve_pending / approved / denied_by_human / timeout | Allowed / Denied by policy / Held for a person / Approved / Denied by you / Timed out · denied |
| scanner.clean / flagged / wrapped | Clean / Flagged / Wrapped |
| taint.badge | Session tainted |
| history.untrusted | Untrusted content entered · {n} scanner hits · wrapped as data |
| killswitch.button | Pause all calls |
| killswitch.confirm | Pause every tool call until you resume? Agents get a tool error in the meantime. |
| chain.verified | Hash chain verified. All {n} entries match their hashes and link to the entry before. |
| chain.broken | Chain broken at entry {k} of {n}. Entry {k} no longer matches its recorded hash, so it changed after it was written. Entries 1–{k-1} verify; {k}–{n} can't be trusted. |
| chain.brokenDetail | The log can show that something changed, not what it was. Compare against another copy of the log. |
| replay.sample | Sample session for the demo. Each row is one AuditEvent from {file}. |

Voice: plain and specific, no exclamation marks, no "attack detected!" alarm copy. Name the rule and what happens next.

## 6. Contrast (computed, WCAG 2.x relative luminance)
| Pair (fg on bg) | Use | Dark | Light |
|---|---|---|---|
| `text` on `surface` | AA text 4.5 | 15.18 ✓ | 18.61 ✓ |
| `text-muted` on `surface` | AA text 4.5 | 7.78 ✓ | 7.21 ✓ |
| `text-subtle` on `surface` | AA text 4.5 | 5.22 ✓ | 5.24 ✓ |
| `text-subtle` on `raised` | AA text 4.5 | 4.89 ✓ | 4.59 ✓ |
| `accent` on `surface` | AA text 4.5 | 11.75 ✓ | 5.60 ✓ |
| `warn` on `surface` | AA text 4.5 | 10.32 ✓ | 6.16 ✓ |
| `danger` on `surface` | AA text 4.5 | 7.01 ✓ | 6.54 ✓ |
| `info` on `surface` | AA text 4.5 | 8.50 ✓ | 5.81 ✓ |
| `accent` on `accent-soft` | badge text | 9.74 ✓ | 4.91 ✓ |
| `warn` on `warn-soft` | badge text | 8.87 ✓ | 5.58 ✓ |
| `danger` on `danger-soft` | badge/deny button | 6.59 ✓ | 5.50 ✓ |
| `info` on `info-soft` | badge text | 7.46 ✓ | 4.98 ✓ |
| `text` on `taint-mark` | highlighted JSON | 10.93 ✓ | 15.50 ✓ |
| `text-on-accent` on `accent` | Approve button | 12.38 ✓ | 5.60 ✓ |
| `border-control` on `surface` | UI 3:1 | 3.27 ✓ | 3.33 ✓ |
| `border-control` on `bg` | UI 3:1 | 3.44 ✓ | 3.10 ✓ |
| `focus` on `surface` | focus ring 3:1 | 8.50 ✓ | 5.81 ✓ |
| `focus` on `bg` | focus ring 3:1 | 8.96 ✓ | 5.41 ✓ |
| `warn` on `bg` | countdown bar 3:1 | 10.87 ✓ | 5.74 ✓ |


Direction B checked too: text 17.12, muted 7.19, cobalt 6.59, warn 6.05, danger 7.14, ok-green 6.13 on its surface (`src/contrast.py`). Don't drop `kbd` opacity below .85.

## 7. UI element → AuditEvent field (`docs/audit-schema.md` in PR #7)
| UI element | Field(s) | Notes |
|---|---|---|
| Queue item / detail title | `tool` (fallback `method`) | Mono |
| "server" chip | `upstream` | |
| "session" chip, history header | `sessionId` | A ULID. Shown as `01M8F6…KWRZ` with the full value in `title` and copy. |
| "client" chip | `client.name`, `client.version` | Hide when both are missing |
| "held / decided {time}" | `ts` | Shown in local time with a zone label. Stored in UTC. |
| Decision badge | `decision` | Mapping in §5 |
| Why panel headline | `reason` | |
| Why panel rule id | `ruleId` | e.g. `flows.no-send-after-untrusted-content`, `rules[0]` |
| "Policy saw: session tainted" badge | `taint.tainted` | `taint` is the state **before** this event, so it's labelled as what the policy saw |
| Taint chain node 1 (untrusted read) | The event whose `id` ∈ `taint.sources`: its `tool`, `argsRedacted.path`, `ts` | In the sample that's entry 6, the outcome record |
| Taint chain node 3, "taints" marker, "Session tainted after this call" | `taintAfter` (requested), else derived (§7a) | |
| Scanner badge, chain node 2 | `scanner.verdict`, `scanner.hits[].rule` | `scanner` is optional, so show "–" when it's missing |
| JSON in Arguments | `argsRedacted` only. Arguments are not scanned, so there are no `target: "args"` hits | A neutral (info, not warn) highlight on `to` is a review affordance, labeled as such, not a scanner hit |
| Result excerpt (history, replay) | `hits[]` where `target === "result"` and the verdict is `flagged` or `wrapped`: `path` is `content[0].text`; `span` is the original match shifted by 14, indexing the client-visible wrapped string | In `blocked`, spans index the withheld upstream text, which is not in the returned result. Show a wrap excerpt only after the fixture hash matches `resultHash` |
| Description hits (tool-pin view, later) | `hits[]` where `target === "description"` | Spans index the description string the gateway holds. Descriptions are not passed through `redact()`. |
| JSON body | `argsRedacted` | Never raw args. Key order comes from the file. Emails keep the domain; only the local part is masked (§7b). |
| argsHash footer | `argsHash` | `sha256(stableStringify(rawArgs))` |
| Countdown, "expiresAt 2:06:51 PM EST" | `expiresAt` (on `approve_pending`) | |
| Decided bar "after 41.2 s", "by you on the dashboard", "entry 10 resolves entry 9" | `approval.latencyMs`, `approval.channel`, `approval.by`, `approval.pendingId` | |
| Call grouping (history: one row per call) | Intent + outcome: pair by the outcome's `intentId`. Pending + decision: `approval.pendingId`. | Fall back to adjacency plus `argsHash` only if `intentId` is missing (older logs) |
| Replay "Call · record" column | intent (no `resultHash` / no `intentId`), outcome (`resultHash` + `intentId`), pending (`expiresAt`), decision (`approval.pendingId`, no `scanner`), single (deny) | |
| Duration chip | `durationMs` (outcome records only) | |
| Integrity card, ChainStatusBar, Chain column | `prevHash`, `hash` | §3a |

### 7a. Taint semantics in the UI
- **`taint`** means the state the policy saw when it decided this event. The label is always "Policy saw: tainted / not tainted", never just "Tainted".
- **`taintAfter`** is optional and must be `{ tainted: boolean, sources: string[] }` (the same shape as `taint`). It is written only when this event changes the session state. Replay uses it to mark the flip on the introducing event: "Session tainted after this call", "taints" in the table, and "After this entry: Tainted — introduced here".
- If a log is missing `taintAfter`, derive the flip from the next event whose `taint` differs. Do not treat `taint.sources` as event ids — in Milestone 3 they are upstream names.
- The first untrusted `tools/call` result taints the session, and so does any scanner hit. `tools/list` does not taint. Trusted results with no hit do not taint. `markTainted` appends the upstream name to `sources`.
- In the sample, entry 6 (the `notes__read` outcome from untrusted `notes`) has `taint: { tainted: false, sources: [] }` and `taintAfter: { tainted: true, sources: ["notes"] }`. Entries 7–10 carry that state as `taint` and omit `taintAfter`.

### 7b. Email redaction in `argsRedacted`
Anthony's rule, now in `packages/core/src/redact.ts` (`maskEmail`) and `docs/audit-schema.md`. Apply it to every email in stored argument strings.

- Keep the domain as written, including the `@`.
- Mask the local part as the first character of the local part plus three U+2022 bullets (`•••`). A one-character local part still becomes `j•••@domain`.
- Examples: `john@outsidecorp.com` → `j•••@outsidecorp.com`; `q@outside-sample.example` → `q•••@outside-sample.example`; the sample's `q4-sync@outside-sample.example` → `q•••@outside-sample.example`.
- Do not mask the domain, the `@`, or non-email text. Secret-looking keys, `Bearer` tokens and `sk-` tokens stay as in `packages/core` (`[REDACTED]` / `Bearer [REDACTED]`).
- Scanner `span`s on `target: "args"` index the **redacted** string, so a hit on `to` covers all of `q•••@outside-sample.example` (`[0, 27]` in the sample).
- The wrap-mode result fixture keeps the attacker address in full inside the delimiters (`<<untrusted>>…<<end untrusted>>`). That text is result content, not a logged recipient.

### 7c. Wrap-mode result fixture

The wrap delimiters are pinned in `packages/core/src/scanner.ts` and `docs/audit-schema.md`:

- prefix `<<untrusted>>` + newline (14 UTF-16 units)
- suffix newline + `<<end untrusted>>` (18 UTF-16 units)

`applyScanner` wraps the entire string at a hit path once, not each hit. Result spans are the original match plus 14 so they index the inner text the client receives, not the delimiters. `resultHash` is `sha256(stableStringify)` of that wrapped result. The sample fixture and hits are generated with the PR #7 `applyScanner` build, not by hand.

### 7d. Scanner verdicts, block mode, and arguments

- Verdicts: `blocked` (`mode: block`), `flagged` (`mode: warn`), `wrapped` (`mode: wrap`). A clean or un-run scan omits `scanner`.
- In block mode the client receives an error (`blockedToolResult`) and does not receive the payload. `resultHash` covers that error. Hit spans still index the withheld upstream text, because that text is not in the returned result.
- Arguments are not scanned. The approval mock does not style argument values as scanner hits. Why the call was held is the flow rule plus the taint source chain (here: untrusted `notes` read, then `flow:no-send-after-untrusted-content`). A neutral highlight on the `to` field is a review affordance only, labeled as such, not a scanner hit. The flow rule looks at session taint and the tool name, not the recipient.

## 8. Schema notes

`docs/audit-schema.md` on PR #7 (`aec688b`) is the source of truth. The design follows it:

- Allowed calls are an `intent` plus an `outcome` with `intentId`. Held calls are an `approve_pending` plus a `decision` linked by `approval.pendingId`. Decision lines do not repeat `scanner`.
- `taintAfter` is optional `{ tainted: boolean, sources: string[] }` (a bare boolean is rejected) and is hashed when present. `sources` are upstream names, not event ids. The first untrusted `tools/call` result taints the session and writes `taintAfter` on that outcome; `tools/list` does not taint.
- Result spans in wrap mode index the client-visible wrapped text (shift by 14). Description spans index the held description, not a redacted copy. Arguments are not scanned.
- Email masking is first character + `•••` + `@` + domain (U+2022). The redacted form is what is logged and hashed as `argsRedacted`.
- `ruleId` values in the sample match the example policy: `default:tools/list`, `rule:0`, `flow:no-send-after-untrusted-content`.
- `examples/drawbridge.yaml` on PR #7 uses `scanner.mode: wrap` and defines a trusted local `mail` fixture (`stdio`, `@modelcontextprotocol/server-memory`, `trusted: true`) plus untrusted `notes`. The sample uses those upstream names and that policy.

Remaining mismatches between PR #7 and this design (file:line on the PR #7 tree at `aec688b`):

1. **The sample is an M3+M4 session, not a live Milestone 3 log.** Until Milestone 4, `holdForApproval` in `packages/gateway/src/dispatch.ts:22` and `:279-320` writes `approve_pending` and then an immediate `deny` with `APPROVAL_UNAVAILABLE` (`README.md` still documents that until M4). The sample's entry 10 is `denied_by_human` with `approval.channel: "dashboard"` and `latencyMs: 41200`, which is what the M4 dashboard and the 1:15 demo chapter show. A live M3 log of the same session would end in an automatic deny.

2. **`docs/audit-schema.md:57` still says "Milestone 2 does not mark a session tainted; the scanner in milestone 3 does."** The M3 policy taints on any untrusted `tools/call` result, even when the scan is clean (`packages/core/src/policy.ts:150-151, 199-211`; `README.md:104, 177`). The design and the sample follow the policy, not that leftover sentence.

3. **The sample notes fixture is richer than the example demo-upstream.** `examples/drawbridge.yaml` points `notes` at `node examples/demo-upstream.mjs`, which replies with `note:${path}` (`examples/demo-upstream.mjs`). The design's `fixtures/q4-notes.md` is a scripted Q4 note used so the 0:20 wrap beat has real heuristic hits (`instruction-override`, `role-hijack`). A live run of the example config would wrap a shorter, different result and would not produce those spans.

## 9. Open questions for Anthony
None. The earlier decisions, including recipient redaction, still stand. The wrap delimiter (§7c, §8.1) can wait for Milestone 3 unless Anthony wants it pinned sooner.
