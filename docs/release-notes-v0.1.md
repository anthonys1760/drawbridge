# Drawbridge 0.1.0

Draft. Do not tag this commit and do not publish a release from it. `package.json` stays at `0.0.0` until the tag is cut on purpose.

Drawbridge is an MCP security gateway. An agent connects to it over stdio. Drawbridge connects to the upstream servers in `drawbridge.yaml`, shows one namespaced catalog, checks each call, and writes a hash-chained audit log before it forwards.

## Try it

```bash
pnpm install
pnpm build
pnpm demo
```

`pnpm demo` reads the sample `q4-notes` fixture, taints the session, and holds `mail__send`. On a terminal it waits for the dashboard. Without one, it denies the call and runs `audit verify`. The shot list is [docs/demo-script.md](demo-script.md).

## What 0.1 includes

- Policy: allow, deny, and approve, argument checks, rate limits, flow rules, and tool pins. A changed tool description fails the pin check on the next call.
- Scanner: block, warn, or wrap. The example wraps hits between `<<untrusted>>` and `<<end untrusted>>`. Untrusted tool results taint the session. The demo flow then holds `mail__send`.
- Approvals are once-only. High-risk sends wait on the local dashboard or the CLI.
- Secrets are `env:` or `file:` references on one upstream. Client tokens are not forwarded.
- `drawbridge pause` denies new tool calls and auto-denies calls that are already waiting. The choice survives a restart.
- `pnpm attacks` records expected and actual verdicts for indirect and direct injection, description poisoning, a rug pull, a confused deputy, secret leakage, audit tampering, and the kill switch. The scorecard is [docs/attack-results.md](attack-results.md). CI checks it.
- The audit replay in `site/replay/` verifies a log in the browser, including a tampered copy that breaks at entry 5. It does not call the network. Serve `site/` so the page and the fonts stay on the same origin. It is also the page that will be hosted on anthonysdigital.net.

## Trust boundary

Read [docs/threat-model.md](threat-model.md) before pointing Drawbridge at a credential or an untrusted server. The known limits in that document are still the limits of this draft: credential-shaped `env` and `headers` literals warn but are not refused, a token in a free-text field is forwarded, and pause reuses the allow and deny decisions.
