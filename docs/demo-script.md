# Demo script

Two minutes. Anthony records it. The commands are `pnpm install`, `pnpm build`, and `pnpm demo` from a checkout. `pnpm demo` is the story: list the catalogs, read `q4-notes`, read `q4-roadmap`, hold `mail__send`, then deny it and run `audit verify`.

The timestamps below are video cues, the same chapters as the audit replay. They are not log times.

## Shot list

| Time | Picture | Do this |
| --- | --- | --- |
| 0:00 | Terminal, repo root | Say the three commands. Run `pnpm demo` if install and build are already done. The first lines list notes and mail. |
| 0:20 | Terminal, then the dashboard | The read of `q4-notes` comes back between `<<untrusted>>` and `<<end untrusted>>`. The next read, `q4-roadmap`, is an ordinary note. Say that the session is already tainted. |
| 0:50 | Dashboard, held call | `mail__send` does not return. The script prints the dashboard URL. Open it. The queue shows one held send. The recipient is masked. The reason is the flow rule `no-send-after-untrusted-content`. |
| 1:15 | Dashboard, then terminal | Click Deny. The terminal shows the tool error, `Blocked by policy`. Say that approving once would have let this call through and the next send would ask again. |
| 1:35 | Terminal, then the replay | `audit verify` prints ok. Open `site/replay/` (any static server rooted at `site/`, so the fonts resolve). Show the verified chain, then the tampered sample, which breaks at entry 5. |

## Words

Drawbridge sits between an agent and its tools. This demo is three commands: install, build, and `pnpm demo`.

The agent lists its tools, then reads a project note. The note contains an instruction to email the keys. Drawbridge does not follow that instruction. It wraps the text so the model can see it is data, and it marks the session tainted.

The next read is a normal roadmap. Nothing in it is a scanner hit. The policy still sees a tainted session, because the first read already changed that.

The agent then tries to send mail to the address from the note. That call does not go out. It waits here. The dashboard is the out-of-band channel. The reason is the flow rule: once untrusted content has entered the session, a send needs a person.

Deny is the safe choice. The agent receives a tool error for this one call. A later send asks again.

The audit log was written before the call was forwarded, and each line is hashed to the line before it. `audit verify` recomputes that chain. The replay does the same check in the browser. The tampered file is the same log with one line rewritten, so the chain breaks at that entry and the rest cannot be trusted.

## GIF

`docs/demo.gif` is a headless pass over the replay: setup, the poisoned read, the held send, the denial, the chain chapter, then the tampered log. It does not include the dashboard, because that URL carries the per-run token. For the recording, use the 0:50 shot in the dashboard after the page has loaded, and keep the token out of the frame.
