import { readdirSync, readFileSync, readlinkSync } from "node:fs";
import { upsertScanStatus } from "../state/history-db.ts";
import { readJson, writeJsonAtomic } from "../state/json-store.ts";
import {
	createPackageLookup,
	type PackageLookup,
} from "../state/package-ownership.ts";
import { noopSignatureDbStore } from "../state/signature-db-store.ts";
import {
	buildSuspiciousFinding,
	checkSuspiciousExePath,
	hashSuspiciousBinary,
} from "./suspicious-process.ts";
import type { Module, ModuleContext } from "./types.ts";

interface PackageUpgradeCheck {
	/** True when the path is dpkg-owned AND that package was upgraded within the configured grace
	 * window — the only case that downgrades the finding. */
	explained: boolean;
	/** The owning package name, if any was found (independent of `explained` — set even when the
	 * package wasn't recently upgraded, purely for dashboard/triage visibility). */
	package: string | null;
}

/**
 * Explains away the routine "process still holds an open fd to a binary a `dpkg`/`apt` upgrade
 * just unlinked" shape — this has fired as a false-positive `critical` alert four times in the
 * last month (journalctl, Claude Code's self-update, p11-kit-server, flatpak-session-helper), each
 * time requiring a manual `dpkg -S`/`apt history.log` check before whitelisting by hand.
 *
 * Deliberately a SIMPLE recency check ("was the owning package upgraded within the last N days"),
 * not precise correlation between the deletion and the process's own `/proc/<pid>/exe` mtime —
 * that was discussed and rejected as too fragile (mtimes get smudged by hardlinks/atomic-rename
 * package managers use, clock skew, etc). See package-ownership.ts's wasPackageRecentlyUpgraded
 * for the exact recency semantics.
 *
 * Fail-safe by construction: not dpkg-owned, not recently upgraded, and the lookup itself throwing
 * (dpkg missing, apt history.log missing/unreadable, anything unexpected) all fall through to
 * `explained: false` here — a lookup failure is never treated as evidence of benignity, only a
 * clean positive match ever downgrades the finding.
 */
function checkPackageUpgradeExplanation(
	path: string,
	graceDays: number,
	lookup: PackageLookup,
): PackageUpgradeCheck {
	try {
		const pkg = lookup.ownerOf(path);
		if (!pkg) return { explained: false, package: null };
		return {
			explained: lookup.wasRecentlyUpgraded(pkg, graceDays),
			package: pkg,
		};
	} catch {
		return { explained: false, package: null };
	}
}

interface ProcInfo {
	pid: string;
	exePath: string | null;
	deleted: boolean;
	cmdline: string;
}

function readProcs(): ProcInfo[] {
	const pids = readdirSync("/proc").filter((name) => /^\d+$/.test(name));
	const procs: ProcInfo[] = [];
	for (const pid of pids) {
		let exePath: string | null = null;
		let deleted = false;
		try {
			const link = readlinkSync(`/proc/${pid}/exe`);
			deleted = link.endsWith(" (deleted)");
			exePath = deleted ? link.slice(0, -" (deleted)".length) : link;
		} catch {
			// EACCES (other user's process) or ENOENT (already exited) — can't assess, skip path checks
			continue;
		}
		let cmdline = "";
		try {
			cmdline = readFileSync(`/proc/${pid}/cmdline`, "utf-8")
				.replaceAll("\0", " ")
				.trim();
		} catch {
			// process exited between listing and reading — fine, cmdline is just informational
		}
		procs.push({ pid, exePath, deleted, cmdline });
	}
	return procs;
}

export function createProcessModule(ctx: ModuleContext): Module {
	const { config, db, recorder } = ctx;
	const signatureDb = ctx.signatureDb ?? noopSignatureDbStore();
	const packageLookup = ctx.packageLookup ?? createPackageLookup();
	const baselinePath = `${config.dataDir}/baseline-processes.json`;
	let timer: ReturnType<typeof setInterval> | null = null;

	// Tracks which pid+condition pairs already alerted, so a still-running offender (e.g. a
	// self-updating binary whose old file was unlinked while the process kept running) alerts once
	// instead of every poll cycle (config.process.pollIntervalMs) for as long as it's alive. Replaced
	// wholesale each scan rather than merged, so a pid that exits (or whose condition clears) is
	// automatically pruned and free to alert again if the condition recurs on a new pid.
	let alertedCriticalKeys = new Set<string>();

	async function scanNow(): Promise<void> {
		const knownExePaths = new Set(readJson<string[]>(baselinePath, []));
		const isFirstRun = knownExePaths.size === 0;
		const procs = readProcs();
		let newExePaths = 0;
		const currentCriticalKeys = new Set<string>();

		for (const proc of procs) {
			if (!proc.exePath) continue;

			// proc.exePath is already the resolved (deleted-suffix-stripped) path; re-run through the
			// exePath+" (deleted)" form when it was deleted so the shared check sees the same signal.
			const checkInput = proc.deleted
				? `${proc.exePath} (deleted)`
				: proc.exePath;
			const check = checkSuspiciousExePath(
				checkInput,
				config.process.suspiciousDirs,
			);

			if (check.reason === "deleted") {
				const key = `deleted:${proc.pid}:${proc.exePath}`;
				currentCriticalKeys.add(key);
				if (!alertedCriticalKeys.has(key)) {
					const sha256 = hashSuspiciousBinary(proc.pid, check);
					const upgradeCheck = checkPackageUpgradeExplanation(
						proc.exePath,
						config.process.packageUpgradeGraceDays,
						packageLookup,
					);
					const finding = buildSuspiciousFinding({
						summaryBase: upgradeCheck.explained
							? `Process running from a deleted binary: ${proc.exePath} (pid ${proc.pid}) — likely explained by a recent apt upgrade of ${upgradeCheck.package}`
							: `Process running from a deleted binary: ${proc.exePath} (pid ${proc.pid})`,
						detail: { ...proc, packageUpgrade: upgradeCheck },
						sha256,
						match: sha256 ? signatureDb.lookup(sha256) : null,
					});
					// A recently-upgraded, dpkg-owned binary being deleted-on-disk is routine apt
					// behavior, not tampering — downgraded to warning so it's still logged and still
					// flows through triage.ts's periodic review, never silently dropped (see
					// checkPackageUpgradeExplanation's fail-safe doc comment for why every other case
					// stays critical).
					recorder.record({
						module: "process",
						severity: upgradeCheck.explained ? "warning" : "critical",
						...finding,
					});
				}
				continue;
			}
			if (check.reason === "suspicious-path") {
				const key = `suspicious-path:${proc.pid}:${proc.exePath}`;
				currentCriticalKeys.add(key);
				if (!alertedCriticalKeys.has(key)) {
					const sha256 = hashSuspiciousBinary(proc.pid, check);
					const finding = buildSuspiciousFinding({
						summaryBase: `Process launched from suspicious path: ${proc.exePath} (pid ${proc.pid})`,
						detail: proc,
						sha256,
						match: sha256 ? signatureDb.lookup(sha256) : null,
					});
					recorder.record({
						module: "process",
						severity: "critical",
						...finding,
					});
				}
				continue;
			}

			if (!knownExePaths.has(proc.exePath)) {
				knownExePaths.add(proc.exePath);
				newExePaths++;
				// Deliberately not alert-worthy by default (emailOnNewBinary: false) — a desktop spawns
				// new legitimate binaries constantly; keying the allowlist by exe path (not pid/argv)
				// means this only fires once per new binary, not once per process.
			}
		}

		alertedCriticalKeys = currentCriticalKeys;
		writeJsonAtomic(baselinePath, [...knownExePaths]);
		upsertScanStatus(
			db,
			"process",
			isFirstRun
				? `baseline created (${knownExePaths.size} known binaries)`
				: `ok (+${newExePaths} new)`,
		);
	}

	function start(): void {
		timer = setInterval(() => void scanNow(), config.process.pollIntervalMs);
	}

	function stop(): void {
		if (timer) clearInterval(timer);
	}

	return { scanNow, start, stop };
}
