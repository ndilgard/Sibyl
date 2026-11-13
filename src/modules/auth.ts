import { upsertScanStatus } from "../state/history-db.ts";
import type { Module, ModuleContext } from "./types.ts";

export interface JournalEntry {
	MESSAGE?: string;
	SYSLOG_IDENTIFIER?: string;
	__REALTIME_TIMESTAMP?: string;
}

export interface Classified {
	severity: "warning" | "critical";
	summary: string;
}

export function classify(entry: JournalEntry): Classified | null {
	const msg = entry.MESSAGE ?? "";
	const ident = entry.SYSLOG_IDENTIFIER ?? "";

	if (ident.includes("sshd")) {
		if (msg.includes("Failed password") || msg.includes("Invalid user")) {
			return {
				severity: "critical",
				summary: `Failed SSH login attempt: ${msg}`,
			};
		}
		if (
			msg.includes("Accepted password") ||
			msg.includes("Accepted publickey")
		) {
			return { severity: "warning", summary: `SSH login accepted: ${msg}` };
		}
	}
	if (ident.includes("sudo")) {
		if (
			msg.includes("authentication failure") ||
			/\d+ incorrect password attempt/.test(msg)
		) {
			return {
				severity: "critical",
				summary: `Failed sudo authentication: ${msg}`,
			};
		}
	}
	return null;
}

export function parseLines(chunk: string): JournalEntry[] {
	const entries: JournalEntry[] = [];
	for (const line of chunk.split("\n")) {
		if (!line.trim()) continue;
		try {
			entries.push(JSON.parse(line));
		} catch {
			// partial line from stream buffering — dropped, will complete on next chunk boundary
		}
	}
	return entries;
}

export function createAuthModule(ctx: ModuleContext): Module {
	const { db, recorder, config } = ctx;
	let proc: Bun.ReadableSubprocess | null = null;
	let stopped = false;
	let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

	/** One-shot check over recent history, for `hids scan-now auth` / manual verification. */
	async function scanNow(): Promise<void> {
		const result = Bun.spawnSync([
			"journalctl",
			"-n",
			"50",
			"-o",
			"json",
			"--no-pager",
		]);
		const entries = parseLines(result.stdout.toString());
		let found = 0;
		for (const entry of entries) {
			const classified = classify(entry);
			if (classified) {
				found++;
				recorder.record({
					module: "auth",
					severity: classified.severity,
					summary: classified.summary,
					detail: entry,
				});
			}
		}
		upsertScanStatus(
			db,
			"auth",
			`ok (${found} matches in last 50 log entries)`,
		);
	}

	async function streamLoop(): Promise<void> {
		if (stopped) return;
		proc = Bun.spawn(
			["journalctl", "-f", "-n", "0", "-o", "json", "--no-pager"],
			{
				stdout: "pipe",
				stderr: "pipe",
			},
		);
		upsertScanStatus(db, "auth", "watching (journalctl -f)");

		const reader = proc.stdout.getReader();
		const decoder = new TextDecoder();
		let buffer = "";
		try {
			while (true) {
				const { done, value } = await reader.read();
				if (done) break;
				buffer += decoder.decode(value, { stream: true });
				const lines = buffer.split("\n");
				buffer = lines.pop() ?? "";
				for (const entry of parseLines(lines.join("\n"))) {
					const classified = classify(entry);
					if (classified) {
						recorder.record({
							module: "auth",
							severity: classified.severity,
							summary: classified.summary,
							detail: entry,
						});
					}
				}
			}
		} catch (err) {
			console.error("[auth] journalctl stream error:", err);
		}

		if (!stopped) {
			console.warn(
				`[auth] journalctl -f exited, reconnecting in ${config.auth.reconnectBackoffMs}ms`,
			);
			reconnectTimer = setTimeout(
				() => void streamLoop(),
				config.auth.reconnectBackoffMs,
			);
		}
	}

	function start(): void {
		stopped = false;
		void streamLoop();
	}

	function stop(): void {
		stopped = true;
		if (reconnectTimer) clearTimeout(reconnectTimer);
		proc?.kill();
	}

	return { scanNow, start, stop };
}
