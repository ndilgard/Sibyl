# HIDS Improvement Backlog

Ideas for what to build next, roughly in the order they were proposed. Not commitments — pull
from this list when there's appetite for the next round of work.

## 1. Self-protection (heartbeat / dead-man's-switch) — DONE

Closes the "who watches the watcher" gap. Right now, if the daemon crashed, got killed, or an
attacker with root disabled it outright, nothing would notice — every existing module only
detects *other* things going wrong on the host, not HIDS itself going quiet. The fix has to live
outside the host, since anything running only on this machine can be silenced the same way the
daemon itself can.

## 2. Real-time detection via eBPF

Process and network activity are currently caught by polling (10s / 30s intervals). Something
fast-lived — a process that starts, does something, and exits between two polls — could slip
through entirely. eBPF hooks on `exec`/`connect` syscalls would catch activity the instant it
happens instead of sampling for it. Heavier build: new toolchain, likely a small Rust or C
component alongside the existing TypeScript/Bun modules.

## 3. Daily health digest

A quiet, scheduled email confirming all four modules (FIM, process, auth, network) are alive and
scanning. Today, HIDS is silent by design unless something triggers an alert — which means a
silent failure in one module could go unnoticed for a long time with no signal either way.

## 4. Automated test suite — DONE

93 `bun:test` tests across 9 files (`4d5aeb9`), prioritized by regression history and real
security decisions: `network.ts` parsing (incl. a regression test reproducing the exact
`841710e` UDP column mis-indexing bug — verified it fails against the pre-fix code),
`auth.ts` classification/parsing, `whitelist-store.ts`'s alert-suppression predicate,
`link-auth.ts`/`suspicious-process.ts`, `history-db.ts`/`json-store.ts` round-trips via
temp dirs, `config.ts` defaulting, and an integration-style `fim.ts` test. Scoped to
parsing/detection logic only — live `fs.watch`, `journalctl -f`, `ss`/`systemctl`
shell-outs, email sending, the dashboard server, and heartbeat's `fetch()` are still
untested.

## 5. Dashboard alert search/filtering — DONE

Module/severity/text filters over Recent Alerts and Suppressed Events, re-rendered client-side
from already-fetched data (`86ac173`). Bulk select + whitelist/unwhitelist actions and the
Suppressed Events audit view (`2236d28`, `1abf59e`) came out of this same round of dashboard work.

## 6. Cross-module correlation + investigation report generator — SCOPED

Right now each module fires alerts independently and the triage agent reasons about them one at
a time. A related set of signals across modules — a FIM change followed seconds later by a new
network connection, say — has no mechanism to be recognized as one incident. This item is really
two things that turn out to be the same feature: build the correlation logic (group related
alerts across modules by time/process/file proximity), then have the triage agent turn a
correlated group into a single structured investigation report (timeline, evidence per module,
one narrative) instead of separate per-alert emails. Matches a pattern seen repeatedly in
detection-engineering job postings (case documentation, timeline reconstruction, evidence
indexing) — also the single most direct way to make Sibyl demonstrate end-to-end investigative
reasoning, not just alert-and-forward.

**Scoped 2026-10-27, IN PROGRESS.** Full design (correlation logic, time window, trigger,
storage, email surfacing, build order) in `~/.claude/plans/hids-cross-module-correlation.md` —
read that back before continuing, don't re-derive.

Steps 1-5 done (2026-11-12): `src/state/identifiers.ts`, `src/state/correlate.ts` (union-find
grouping so an incident can chain through more than one shared identifier), and
`src/state/incident-store.ts` (append-only JSONL, mirrors `triage-store.ts`) all built and
tested, plus `src/agent/triage.ts` now has `runIncidentReportConversation()` — turns a
correlated `Incident` + its alerts into a three-section (timeline/evidence/narrative) report
using the same tools and fail-safe contract as per-alert triage. 38 tests passing total across
this item. Next: step 6, wire correlation into the triage cycle + new "Investigation Report"
email template.

## 7. Human-confirmed response recommendations

HIDS is deliberately detection-only — autonomous containment (killing a process, isolating the
host) was already considered and rejected as high-risk, and would undercut the design's own
prompt-injection mitigation (fail-safe-to-"unreviewed", never act unilaterally on LLM output).
A safer middle ground: the triage agent drafts a specific recommended response ("kill PID 1234",
"block 1.2.3.4 at the firewall") alongside its analysis, and a human confirms it via the same
signed-link click-to-confirm pattern already used for whitelist-confirm. Gets the "automated
response" capability recruiters look for without ever letting the LLM take action on its own.

## 8. Scheduled hunt mode

Every existing module (and the correlation/triage layer above) is reactive — it only reasons
about things that already tripped a detection. A hunt mode would run on a schedule (e.g. nightly)
and have the triage agent proactively query historical data/baselines for anomalies that never
crossed an alert threshold on their own — the "go looking" complement to "wait for something to
trip." Bigger lift than 6 or 7 since it needs a baseline/history store to query against rather
than reacting to a single event; lower priority until the reactive path is mature.

## 9. Whitelist prefix matching — SCOPED

`whitelist-store.ts` only does exact-value matching, which breaks for any whitelisted identifier
that changes by design on every update — confirmed recurring case: the Claude Code self-update
daemon's `exePath` embeds its version number, so the existing rule (pinned to `2.1.241`) silently
stopped working and 5 different version bumps (`2.1.241/310/311/312/316`) each re-triggered the
same alert this session. Firefox and p11-kit hit a related but distinct issue (needing a *new*
rule after an update, not a *structurally broken* one) and don't need this fix.

**Scoped 2026-11-01, not started.** Full design (prefix vs. glob decision, exact code change,
dashboard checkbox, test plan, migration of the dead Claude Code rule) in
`~/.claude/plans/hids-whitelist-prefix-matching.md` — read that back before starting, don't
re-derive.

## Other ideas raised in passing (not yet scoped)

- Rootkit / hidden-process detection (kernel module loading, process list discrepancies)
- Installed-package drift baseline (apt/dpkg) for supply-chain awareness
- Alert severity routing (critical → push notification in addition to email, not just warning-level email)
