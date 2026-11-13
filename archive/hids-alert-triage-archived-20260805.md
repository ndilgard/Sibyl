---
hal-id: "#HAL-20260730-0001-NH-V6"
description: Reviews new HIDS findings every 30 min and only surfaces genuinely alarming ones
---

**Archived 2026-08-05:** retired. The HIDS daemon's own `AlertRecorder` (`src/alert/policy.ts`,
HIDS repo) now emails only `critical`-severity findings directly and near-instantly — this AI
triage layer was redundant with that and was also the source of ~30-min notification lag on top
of a daemon that was already emailing every non-suppressed finding of any severity (201 emails in
2 days, mostly benign `warning`-tier network noise). Warning/info findings are still recorded and
visible on the HIDS dashboard; they're no longer proactively reviewed or emailed by anything.

Read every HIDS finding recorded since the last run, apply real security judgment to each one (the
same kind of check Nate would ask for manually — is this actually alarming, or a legitimate app/
connection that happens to trip a mechanical rule), and only notify Nate when something is real.
Silence means everything reviewed came back clean — this exists so Nate doesn't have to personally
read and interpret every raw HIDS alert email himself.

## Steps

1. Get the current timestamp (`date -u +%Y-%m-%dT%H:%M:%S.%3NZ` or similar ISO8601) — this becomes
   the new high-water mark at the end of the run.

2. Read the triage state file at `temp/hids-triage-state.json` (`{"lastTs": "..."}`) — kept inside
   this project (not on the NAS) so writing it doesn't hit a permission prompt an unattended cron
   session can't answer. If it doesn't exist, this is the first run — use 24 hours ago as `lastTs`
   so it doesn't try to backfill the entire alert history.

3. Read `/mnt/omv/HIDS/alerts.jsonl` (one JSON object per line: `id`, `ts`, `module`, `severity`,
   `summary`, `detail`, `emailed`). Filter to lines where `ts > lastTs`. If there are none: update
   `temp/hids-triage-state.json` to the current timestamp and stop — nothing to report, this is
   the expected good outcome.

4. For each new alert, decide **ALARMING** or **BENIGN** using this judgment, most-trusted-first:

   - **`auth` module, any finding** (failed SSH, accepted SSH, failed sudo): always **ALARMING**.
     This PC doesn't expect remote logins; the module itself already restricts this to
     always-alert-worthy events, so don't second-guess it here.
   - **`fim` module, tamper-detected finding** (a trusted-process binary's hash changed, or a
     static watch-path file was modified unexpectedly): always **ALARMING**. This is specifically
     designed to be rare and high-signal.
   - **`process` module** (new process from `/tmp`/`/dev/shm`/`/var/tmp`, or a deleted-on-disk
     binary): default **ALARMING** unless you can concretely explain it — e.g. correlate the
     timestamp with a legitimate install/update you can verify actually happened (a real package
     manager temp-extraction path, not just "looks plausible"). If you can't verify it concretely,
     it's ALARMING, not benign-by-assumption.
   - **`network` module** — this is where most of the real judgment work happens:
     - Identify the process (exe path) and the destination (IP, and port if present in `detail`).
     - A recognized system/desktop component (GNOME/KDE services, browser, package manager,
       standard Linux tooling) reaching a destination that plausibly matches its own function
       (e.g. a weather applet calling a weather API, a browser making CDN requests) → check the
       destination's reverse DNS / ASN via WebSearch if not obviously legitimate; if it checks out,
       **BENIGN**.
     - A known remote-work tool (VPN client, Citrix, RDP) connecting to what resolves to a
       corporate/enterprise gateway consistent with Nate's own employer infrastructure → **BENIGN**.
     - The wording "known process contacting a new destination" (Layer 2 destination-pair
       tracking) is deliberately designed to catch a compromised-but-familiar binary — treat this
       tier with real scrutiny, not a rubber stamp just because the binary is old news. Look up the
       destination before clearing it.
     - Anything reaching an IP with no legitimate reverse DNS, a residential/hosting-provider range
       with no plausible reason, a Tor exit node, or a country/ASN with no plausible connection to
       Nate's actual usage → **ALARMING**.
     - Genuinely uncertain after a real look (not just "couldn't be bothered to check") →
       **ALARMING**. The cost of a false positive here is one extra email; the cost of a false
       negative is a missed compromise.

5. Append one line per reviewed alert to `temp/hids-triage-log.md` (create with a one-line header
   if it doesn't exist): `{ts} [{module}] {ALARMING|BENIGN} — {summary} — {one-line reasoning}`.

6. If every alert in this batch came back BENIGN: update `temp/hids-triage-state.json` to the
   current timestamp and stop. Do not send anything — silence is the correct, expected outcome.

7. If one or more alerts came back ALARMING:
   1. Run `utils/send-alert-email.py "HIDS Alarming Event — {today's date}: {N} finding(s)" "{plain-text summary of each alarming finding with its reasoning}"` via Bash. This is the reliable, load-bearing channel — it actually sends via Gmail SMTP and rides Nate's existing phone notification setup. If it exits non-zero, note the failure but don't let it block anything else.
   2. Also call `PushNotification` (status `proactive`) with a one-line summary under 200
      characters — best-effort only, not guaranteed to reach the phone from an unattended cron
      session.
   3. Update `temp/hids-triage-state.json` to the current timestamp.
