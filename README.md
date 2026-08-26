# Sibyl

A custom lightweight Host Intrusion Detection System for a single personal Linux PC — named for the
mythological prophetess who interpreted ambiguous signs, since that's what the AI triage layer
(`src/agent/triage.ts`) does with borderline findings. Detection-only (read-only observers, no
enforcement/blocking) across five monitoring modules, plus an agentic triage layer that reviews
anything not clear-cut enough to page immediately:

- **File integrity** — hashes a configurable watch list (`~/.ssh`, dotfiles, `/etc/passwd`,
  hal-skeleton's `credentials/` dir), real-time via `fs.watch` plus a periodic full re-walk
  safety net. `/etc/sudoers` is deliberately excluded — not readable by a normal user.
- **Process** — polls `/proc` every 10s; flags anything running from `/tmp`/`/dev/shm`/`/var/tmp`
  or a deleted-on-disk binary immediately. New-but-legitimate binaries are absorbed into an
  allowlist silently (no email, keeps this the noisy case in the polling world).
- **Auth** — streams `journalctl -f`; failed SSH logins, accepted SSH logins, and failed sudo
  attempts are always alert-worthy.
- **Network** — polls every 30s. Listening ports (`ss -tulnp`): new TCP listeners always alert;
  new UDP listeners only alert after fewer than 3 distinct ephemeral ports have been seen from that
  process (kills WebRTC/QUIC noise without blinding detection to an unrecognized process).
  Outbound connections (`ss -tnp state established` + `ss -unp`): a process already flagged
  suspicious (deleted binary / running from `/tmp`, `/dev/shm`, `/var/tmp`) always alerts the
  moment it talks to the network; trust is tracked per (binary, destination subnet) — a
  compromised-but-familiar binary reaching genuinely new infrastructure still alerts, while a CDN
  handing out a different edge IP in an already-seen /24 (v4) or /48 (v6) doesn't re-alert.
- **Heartbeat** — pings an external healthchecks.io dead-man's-switch every 2 minutes. This is the
  one module that can detect Sibyl itself going quiet (crashed, killed, or disabled by an attacker
  with root) — nothing running only on this host can reliably report its own death, so the
  alerting-on-absence logic lives entirely outside this machine.
- **Agent (triage)** — reviews `warning`/`info` findings the other modules recorded but never
  emailed, using Claude to judge ALARMING vs. BENIGN and escalating genuine ones to email. Has
  real tool use, not a single-shot classifier: can call `whois_lookup`/`reverse_dns_lookup` on an
  unfamiliar network destination, or `check_package_ownership` (via `dpkg -S`) on a suspicious
  binary path, before deciding. Fail-safe throughout — an API failure or unparseable response is
  recorded as `unreviewed`, never silently dropped or treated as benign.

**Only real triggers ever touch disk** — routine scans that find nothing are never persisted, so
there's no retention/rotation job to maintain. All runtime data (baselines + the alerts database)
lives on the NAS at `/mnt/omv/HIDS/`, not in this repo.

## Setup

```bash
bun install
bun link                     # registers the `hids` command globally (~/.bun/bin/hids)
hids init                    # build baselines for all four modules
hids test-email              # confirm Gmail alerting works
```

## Running persistently (24/7 while the PC is on)

Two independent services — deliberately separate processes, not one:

```bash
mkdir -p ~/.config/systemd/user
cp systemd/hids.service systemd/hids-dashboard.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now hids.service hids-dashboard.service
loginctl enable-linger nate   # makes both survive logout and start at boot — do this once
```

`loginctl enable-linger` is a persistent setting (stored in `/var/lib/systemd/linger/nate`) — it
does not need to be re-run. Verify anytime with `loginctl show-user nate --property=Linger`.

`hids-dashboard.service` has no dependency on `hids.service` — if the detection daemon crashes,
gets killed, or is disabled, the dashboard keeps running and keeps serving the last known state
(with a "may be down" banner once that state goes stale), rather than becoming unreachable itself.
Both read the same plain JSON/JSONL files in `dataDir`, which tolerate concurrent access fine
(that's the whole reason this project doesn't use SQLite — see Known limits).

## CLI

| Command | What it does |
|---|---|
| `hids init [module] [--force]` | Build/rebuild a baseline (fim/process/network; auth has none) |
| `hids scan-now [module]` | Run a one-off scan immediately, no daemon needed — records to `alerts` but never sends real email, only the daemon does |
| `hids status` | Last-scan time + result per module |
| `hids alerts [--since] [--module]` | List recorded alerts |
| `hids config` | Print resolved config |
| `hids test-email` | Send a test alert email |
| `hids daemon` | Run the foreground daemon (what systemd execs) |
| `hids start` / `stop` / `restart` | Thin wrappers around `systemctl --user` |

Dashboard: `http://<lan-ip>:8787`, served by `hids-dashboard.service` (LAN-reachable, no auth — a
deliberate assumption for a single-user home network with no port-forward to the internet). Runs
independently of `hids.service` — see above.

Alert emails include a link to the dashboard and, for whitelistable findings (`network`/`fim`/
`process`), a one-click "Whitelist" link — signed per-alert (`src/web/link-auth.ts`) so it can't
be replayed against a different finding, and it opens a confirmation page rather than applying the
rule on click (a prefetching mail scanner just renders the page, it can't submit the form).

The dashboard itself has module/severity/text filters over Recent Alerts (re-rendered client-side
from already-fetched data, so typing in the search box doesn't hit the server per keystroke), plus
checkboxes for bulk "Whitelist Selected" — deduping repeated (module, field, value) matches into
one rule rather than several. Whitelisted findings aren't dropped: they're still recorded
(`suppressed`/`whitelistRuleId` on the `Alert`) and shown in a separate **Suppressed Events**
section, each with its own "Unwhitelist" action (or bulk "Unwhitelist Selected"), so a rule that
turns out too broad can be reviewed and undone instead of silently hiding history.

## Config

`config/hids.config.json` (copy from `config/hids.config.json.example`). Key fields: `dataDir`
(defaults to `/mnt/omv/HIDS`, override via `HIDS_DATA_DIR`), `gmailEnvPath` (defaults to
hal-skeleton's existing `credentials/gmail-smtp.env`, override via `HIDS_GMAIL_ENV_PATH`), and
per-module intervals/thresholds.

## Known limits

- No `auditd` installed, so process monitoring is polling-based (10s interval) — a process that
  spawns and exits between polls is invisible. `sudo apt install auditd` + execve rules would
  close this gap, out of scope for v1.
- Dashboard has no auth and binds to `0.0.0.0` (LAN-reachable) — fine for a trusted home network,
  but don't port-forward it to the internet without adding real auth first.
