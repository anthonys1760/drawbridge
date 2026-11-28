# Changelog

## 0.1.0 — draft

Not tagged and not published. The package version stays `0.0.0` until that tag exists.

### Added

- Stdio gateway in front of upstream MCP servers, with namespaced tools and a hash-chained JSONL audit log.
- Policy: allow, deny, and approve rules, argument checks, rate limits, flows, and tool pins.
- Heuristic scanner in block, warn, and wrap modes. An untrusted tool result taints the session.
- One-time approvals through elicitation, `drawbridge approvals`, and a local dashboard.
- Per-upstream `secrets` (`env:` and `file:` only). Client credentials are stripped before a call is forwarded. `drawbridge pause` and `drawbridge resume` deny new calls until you resume.
- `pnpm attacks`, a scored suite of eight sessions. CI fails when a verdict regresses.
- `pnpm demo`, the three-command story, and `docs/demo-script.md`.
- Static audit replay in `site/replay/`. A Web Worker recomputes the hash chain in the browser.

### Known limits

Documented in [docs/threat-model.md](docs/threat-model.md). A credential-shaped literal in `env` or `headers` warns at startup and is still sent. A token pasted into a free-text field is forwarded. Pause and resume reuse allow and deny. `tools/list` while paused throws instead of writing a tools/call denial.
