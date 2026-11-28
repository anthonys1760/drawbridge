# Threat model

This document describes what Drawbridge is trying to protect in milestone 5, who it does not trust, and which attacks the current code addresses. It is the operator's model of this repository, not a certification.

## Assets

- Upstream credentials. API tokens and similar secrets that an upstream needs, referenced from `drawbridge.yaml` and held by the gateway process.
- Tool arguments and results. They can contain the user's data, addresses, and anything an agent or an upstream put there.
- The audit log. A hash-chained record of what was asked, what policy decided, and what was returned.
- Approval state. A held call, who decided it, and whether the process is paused.
- The gateway process and the config file. Whoever can change those can change what Drawbridge will do.

## Trust boundaries

| Boundary | Trust |
| --- | --- |
| Agent / MCP client → Drawbridge, over stdio | Untrusted. The agent can send any tool name and any arguments, including credentials it should not have. |
| Drawbridge → an upstream, over stdio or Streamable HTTP | The upstream's content is untrusted unless that upstream sets `trusted: true`. Drawbridge is the client on this connection. The end-user client's identity and credentials are not forwarded. |
| Operator → `drawbridge.yaml`, secret files, and the environment | Trusted to name the upstreams and the policy. Not trusted to paste a secret into the YAML file. |
| Operator → the local dashboard on `127.0.0.1` | Trusted as the person who can approve, deny, or pause. The token is random per run. The server rejects a non-loopback connection. |

A `trusted: true` upstream is a statement by the operator that its results may be treated as not introducing untrusted content. Annotations from an untrusted upstream are ignored.

## Attacker goals

### Prompt injection that leads to exfiltration

An untrusted tool result tells the agent to send a secret or a copy of that result somewhere else.

Mitigations:

- Heuristics in `packages/core/src/scanner.ts` flag instruction override and role hijack. `scanner.mode` can block, warn, or wrap the text (`packages/core/src/scanner.ts`, applied from `packages/core/src/policy.ts`).
- Any untrusted `tools/call` result taints the session, and so does a scanner hit (`YamlPolicy.postResult` in `packages/core/src/policy.ts`).
- A flow such as `no-send-after-untrusted-content` can only tighten the decision, and the example holds `mail__send` once the session is tainted (`examples/drawbridge.yaml`, `packages/core/src/policy.ts`).
- On that held outbound call, `packages/core/src/exfil.ts` flags a URL or a long token that also appeared in untrusted content. The flag is stored on the pending audit line.
- The call is not forwarded until a person approves that one call (`packages/gateway/src/dispatch.ts`). The next identical call is held again.

### Tool poisoning

A malicious or compromised upstream advertises a tool whose description or schema tricks the agent, or hides a dangerous action behind a harmless name.

Mitigations:

- Tool names are namespaced as `<upstream>__<tool>` (`packages/core/src/namespace.ts`). The agent cannot call an upstream tool under a different upstream's name.
- `pinTools: true` checks the definition hash before rules. A missing pin or a mismatch is denied, or held when `onPinMismatch` is `approve` (`packages/core/src/pins.ts`, `packages/core/src/policy.ts`, `packages/gateway/src/pin.ts`).
- Descriptions are scanned when `scanner.scanDescriptions` is on. A block verdict withholds the tool from the catalog the agent sees.
- Annotations from an untrusted upstream do not grant an allow (`packages/core/src/policy.ts`).

### Rug-pull description changes

An upstream that looked safe changes a tool's description or schema after the operator pinned it.

Mitigation: the pin check runs on each `tools/list` and before a `tools/call` uses the catalog. A changed hash does not match `drawbridge.pins.json`. The call is denied or held. `drawbridge pin update` is an explicit operator action that rewrites the pin file.

### Confused deputy

The agent, or another client, gets Drawbridge to use a credential or a tool the agent was not supposed to wield. A common shape is "here is my token, send it upstream" or "call the upstream with the client's Authorization header."

Mitigations:

- Drawbridge connects as itself (`packages/gateway/src/upstreams.ts`). The stdio child gets a short default environment plus that upstream's own `env` and `secrets`. The HTTP request gets that upstream's headers and secrets only.
- `stripClientCredentials` in `packages/core/src/redact.ts` removes argument keys that look like tokens, passwords, or authorization before `callTool`. The audit line records the path and stores `[REDACTED]`.
- `secrets` is the supported way to give an upstream a credential. Values have to be `env:NAME` or `file:PATH` (`packages/core/src/secrets.ts`, checked from `packages/core/src/config.ts`). An inline value refuses startup, and that error does not include the value. A credential-shaped literal left in `env` or `headers` still starts, and `serve` prints a warning that names the key and does not print the value (`credentialLiteralWarnings`).
- Resolved values are scrubbed from connection errors and from upstream stderr (`createScrubber`, used by `packages/gateway/src/upstreams.ts`).

### Secret leakage

A secret shows up in the audit log, the dashboard, an error, or stderr, or one upstream learns another's token.

Mitigations:

- Redaction of secret-shaped keys, `Bearer` tokens, and `sk-` tokens before the audit write (`packages/core/src/redact.ts`). Email local parts are masked.
- The dashboard shows `argsRedacted` from that log (`packages/gateway/src/approvals.ts`). It does not receive the raw arguments.
- Each secret map is passed only into the matching upstream's environment or headers (`envForStdio`, `headersForHttp`).
- The pause file stores `{ paused }` and nothing else.

### Audit tampering

Someone edits, reorders, or deletes a line so the log no longer describes what happened.

Mitigations:

- `hash = sha256(prevHash + canonicalJson)` with a 64-zero genesis (`packages/core/src/audit.ts`). `docs/audit-schema.md` is the field list.
- `JsonlAuditLog.open` verifies the chain and refuses to start on a broken log. `drawbridge audit verify` checks the same schema.
- The intent line is written and fsynced before the upstream is contacted (`packages/gateway/src/dispatch.ts`). A failed intent write does not forward.

### Kill switch

An operator needs every new call to stop, including ones already waiting, and that choice has to survive a restart.

`drawbridge pause` and `drawbridge resume`, and the dashboard Pause all calls control, set `ApprovalHub.paused` and write `drawbridge-pause.json` beside the audit log (`packages/gateway/src/approvals.ts`, `packages/gateway/src/cli.ts`). A new `tools/call` is denied with `All calls paused` and `ruleId: kill:paused`. Held calls are denied with `All calls paused, so Drawbridge denied it`. Startup reads the file (`packages/gateway/src/serve.ts`).

## Out of scope

- A malicious operator. Anyone who can edit the config, read the secret file, or attach a debugger to the gateway process can take the credentials.
- Stopping an upstream side effect after the call was forwarded and the outcome line failed to write. The client does not get the payload. The upstream may already have acted.
- A model classifier. `scanner.classifier` other than `off` refuses startup. Only the heuristics run.
- Sandboxing the upstream process beyond a reduced environment. There is no container, syscall filter, or network namespace.
- OAuth, or any client-facing HTTP listener. The agent talks to Drawbridge over stdio. The dashboard is loopback only.
- `resources/*`, `prompts/*`, and completions. They are not forwarded.
- Hiding a secret from the upstream it was configured for. That upstream is supposed to receive it.
- The hosted audit replay, the attack suite, and release provenance. Those are milestone 6.
- Guaranteeing that a person notices an exfil flag. The flag is on the pending call. Approving still forwards that one call.

## Known limits

`secrets` is the supported path for an upstream credential. These limits stay in this version:

- `env` and `headers` can still hold a literal string or a `${VAR}`. Startup prints a warning when that entry looks credential-shaped: an Authorization header, a Bearer value, a name ending in `_TOKEN`, `_KEY`, or `_SECRET`, or a password. The warning names the upstream and the key. It does not print the value, and it does not refuse to start.
- Client credentials are stripped by argument key (`token`, `authorization`, `api_key`, and the same family), including nested keys. A token pasted into a free-text field such as `message` is forwarded. Bearer-shaped text in a stored string is still redacted in the audit log.
- Pause and resume reuse the existing decisions `deny` and `allow`, with rule ids `kill:paused` and `kill:resumed`. There is no separate audit method.
- `tools/list` while paused throws `All calls paused` instead of writing a `tools/call` denial. A new `tools/call` does write that denial.
