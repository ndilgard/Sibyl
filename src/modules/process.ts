import { readdirSync, readFileSync, readlinkSync } from "node:fs";
import { upsertScanStatus } from "../state/history-db.ts";
import { readJson, writeJsonAtomic } from "../state/json-store.ts";
import { checkSuspiciousExePath } from "./suspicious-process.ts";
import type { Module, ModuleContext } from "./types.ts";

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
					recorder.record({
						module: "process",
						severity: "critical",
						summary: `Process running from a deleted binary: ${proc.exePath} (pid ${proc.pid})`,
						detail: proc,
					});
				}
				continue;
			}
			if (check.reason === "suspicious-path") {
				const key = `suspicious-path:${proc.pid}:${proc.exePath}`;
				currentCriticalKeys.add(key);
				if (!alertedCriticalKeys.has(key)) {
					recorder.record({
						module: "process",
						severity: "critical",
						summary: `Process launched from suspicious path: ${proc.exePath} (pid ${proc.pid})`,
						detail: proc,
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
