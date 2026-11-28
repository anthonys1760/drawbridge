# Audit schema

Each line of the JSONL audit log is one event. `audit verify` and gateway startup both check that line with `auditEventSchema` (`verifyAuditJsonl`, called by the `drawbridge audit verify` command and by `JsonlAuditLog.open`). A line that does not match is reported as `line is not an audit event`, and the gateway refuses to start.

Optional fields are part of that schema. A present `taintAfter` or `intentId` is valid. The line fails when a field is missing, the wrong type, or unknown. `taintAfter` is `{ tainted: boolean, sources: string[] }`, the same shape as `taint`. A bare boolean is rejected.

```ts
interface AuditEvent {
  id: string;                 // ULID
  ts: string;                 // ISO 8601 UTC
  sessionId: string;
  client: { name?: string; version?: string };
  upstream: string;
  method: "tools/call" | "tools/list" | "resources/read" | "prompts/get";
  tool?: string;
  argsRedacted: unknown;
  argsHash: string;           // sha256 of the raw arguments
  decision: "allow" | "deny" | "approve_pending" | "approved" | "denied_by_human" | "timeout";
  ruleId?: string;
  reason?: string;
  taint: { tainted: boolean; sources: string[] }; // session state before this event
  taintAfter?: { tainted: boolean; sources: string[] }; // only when it differs from taint
  scanner?: {
    verdict: "clean" | "flagged" | "wrapped" | "blocked";
    hits: {
      rule: string;
      span: [number, number]; // half-open [start, end) indexes into the text below
      target: "args" | "result" | "description";
      path: string;           // HIT_PATH, e.g. content[0].text
    }[];
  };
  approval?: {
    channel?: "elicitation" | "dashboard" | "cli";
    by?: string;
    latencyMs?: number;
    pendingId?: string;       // id of the approve_pending event this decision resolves
  };
  expiresAt?: string;         // ISO 8601 UTC, set on approve_pending
  intentId?: string;          // id of the intent line this outcome completes
  resultHash?: string;        // sha256 of the result returned to the client
  durationMs?: number;
  prevHash: string;
  hash: string;
}
```

## Hash

`hash = sha256(prevHash + canonicalJson)`, hex-encoded, with no separator between the prefix and the JSON. `canonicalJson` is the canonical JSON of the event with only the `hash` field removed. `prevHash` is that raw prefix and is also a field inside the JSON. The first event's `prevHash` is 64 zero characters (`"0".repeat(64)`). Each later event's `prevHash` is the previous event's `hash`.

Canonical JSON (`stableStringify`) has no whitespace. Object keys are sorted by UTF-16 code unit (`Array#sort`). `undefined` object entries are dropped. `undefined` array entries become `null`. Strings, numbers, booleans, and `null` use `JSON.stringify`. Verify parses each line and re-canonicalizes, so key order on disk does not matter. A rewritten line, a swapped `prevHash`, or a line deleted from the middle of the chain fails verification.

`taintAfter` and `intentId` are part of the hashed JSON when they are present.

## Taint

`taint` is the session state before the event, which is what policy sees. `taintAfter` is written only when this event changes that state (same `tainted` flag and the same `sources` in the same order means omit it). Replay uses `taintAfter` to show the flip on the event that introduced the untrusted content. The next event's `taint` is that new state. Milestone 2 does not mark a session tainted; the scanner in milestone 3 does. A log that already contains `taintAfter` still verifies, and the gateway resumes it on startup.

## Intent and approval

An allowed call is two lines: an intent line written before the forward, then an outcome line with `resultHash`, `durationMs`, and `intentId` set to the intent line's `id`. That pairing survives interleaved identical calls. A plain denial is one line and has no `intentId`.

An `approve` decision is not forwarded. The gateway writes an `approve_pending` line with `expiresAt`, then a `deny` line whose `approval.pendingId` is the pending line's `id`. Until milestone 4 that deny is immediate and the reason says approval channels are not available. The decision line does not repeat scanner hits. Consumers read hits from the pending line via `approval.pendingId`.

A pending call's later human decision (`approved`, `denied_by_human`, or `timeout`) also sets `approval.pendingId`. Approvals are once-only: resolving a pending id does not allow the next identical call.

## Scanner hits

`hits[].path` is a bracket/dot path:

```
HIT_PATH = /^(?:[A-Za-z_][A-Za-z0-9_]*)(?:\.[A-Za-z_][A-Za-z0-9_]*|\[(?:0|[1-9][0-9]*)\])*$/
```

`content[0].text` and `body` match. `content.0.text` and `[0].text` do not. Indexes use brackets. Keys are identifiers, not quoted strings.

`hits[].span` is a half-open `[start, end)` pair of UTF-16 indexes into one string:

- `target: "args"` indexes the redacted string stored at that path in `argsRedacted` (after `redact()`), not the raw arguments that `argsHash` covers. Email masking changes the length, so a span computed on the raw address does not line up.
- `target: "result"` indexes the string at that path in the result returned to the client when the verdict is `flagged` or `wrapped`. `resultHash` is `sha256(stableStringify(that same result))`. In wrap mode the gateway wraps the hit string first, returns that wrapped result, hashes it, and spans index the injection inside the wrapped text.
- When the verdict is `blocked`, the client receives an error and does not receive the payload. `resultHash` covers that error. The hit span still indexes the upstream text that was withheld, because that text is not in the returned result.
- `target: "description"` indexes the description string the gateway holds when the verdict is `flagged` or `wrapped` (the wrapped description, in wrap mode). Descriptions are not passed through `redact()`. A `blocked` description is withheld from the client, and the span indexes the original description.

Decision lines do not carry `scanner`. The pending line may.

### Wrap delimiters

Wrap mode rewrites each hit string and no other string. The bytes are pinned:

```text
<<untrusted>>
<original string, unchanged>
<<end untrusted>>
```

The prefix is the 14 characters `<<untrusted>>` followed by one line feed (U+000A). The suffix is one line feed followed by the 17 characters `<<end untrusted>>`. Nothing else is inserted: no space between a marker and its line feed, and no second wrapper. A `wrapped` span is the original match shifted by the prefix length, 15 UTF-16 code units, and indexes that match inside the string the client receives. `resultHash` is the hash of the wrapped result. `[untrusted]` and `[/untrusted]` are not the syntax.

## Redaction

`argsRedacted` is what is stored. `argsHash` is sha256 of the raw arguments, which are not stored.

Email addresses in string values keep the domain. The local part is replaced by its first character plus three bullet characters (U+2022) and `@`:

- `john@outsidecorp.com` becomes `j•••@outsidecorp.com`
- `q@outside-sample.example` becomes `q•••@outside-sample.example`

This applies to every email in stored arguments, including approval and pending records. It replaces `[REDACTED_EMAIL]`.

Other redaction is unchanged. A key matching `secret|password|passwd|token|api[-_]?key|authorization|credential|cookie|session` has its whole primitive value replaced with `[REDACTED]`, even when that value is an email. `Bearer` tokens become `Bearer [REDACTED]`. `sk-` tokens of 8 or more characters become `[REDACTED]`.
