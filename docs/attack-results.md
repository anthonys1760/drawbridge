# Attack results

Score: 8/8. Each row is one scripted session against the demo upstreams. `pnpm attacks` rewrites this file. `pnpm attacks -- --check` exits 1 when a verdict changes or this scorecard drifts.

| Scenario | Expected | Actual | Result |
| --- | --- | --- | --- |
| Indirect prompt injection to exfiltration | fixture wrapped, then held and not sent | fixture wrapped, then held and not sent | pass |
| Direct prompt injection to exfiltration | argument echoed wrapped, then held and not sent | argument echoed wrapped, then held and not sent | pass |
| Tool-description poisoning | tool description wrapped | tool description wrapped | pass |
| Rug pull after the first tools/list | first call allowed, changed description denied | first call allowed, changed description denied | pass |
| Confused deputy (client credentials) | client credentials stripped and not forwarded | client credentials stripped and not forwarded | pass |
| Secret leakage | secret absent from audit, stderr, and dashboard | secret absent from audit, stderr, and dashboard | pass |
| Audit tampering | audit verify exits 1 | audit verify exits 1 | pass |
| Kill switch | new call denied while paused | new call denied while paused | pass |
