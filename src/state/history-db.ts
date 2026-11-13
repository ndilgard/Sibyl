import {
	appendFileSync,
	existsSync,
	mkdirSync,
	readFileSync,
	renameSync,
	writeFileSync,
} from "node:fs";
import { readJson, writeJsonAtomic } from "./json-store.ts";

/**
 * Alert storage lives on a network (SMB/CIFS) mount, not local disk (Nate's explicit choice —
 * NAS-hosted output). bun:sqlite was the original design here, but writes over this mount
 * reliably fail with SQLITE_BUSY/"database is locked" — confirmed empirically, not just a
 * theoretical risk: network filesystems and SQLite's fcntl-based locking don't get along, even
 * with a single writer. Plain appendFileSync/writeFileSync+renameSync both work fine on the same
 * mount, so alerts are an append-only JSONL file and scan_status is a small atomically-written
 * JSON object — no sqlite dependency needed at all.
 */

export type Severity = "info" | "warning" | "critical";

export interface Alert {
	id: string;
	ts: string;
	module: string;
	severity: Severity;
	summary: string;
	detail: unknown;
	emailed: boolean;
	/** True for findings that matched a whitelist rule — recorded for the "Suppressed Events"
	 * review view (so a bad whitelist rule can be caught after the fact) but excluded from the
	 * normal alert list/email flow. Absent (not just false) on every alert recorded before this
	 * field existed — treated the same as false everywhere it's read. */
	suppressed?: boolean;
	/** The whitelist rule that suppressed this alert, if any — lets the dashboard offer a direct
	 * "remove this rule" action next to the evidence. */
	whitelistRuleId?: string | null;
}

export interface ScanStatus {
	last_scan_ts: string;
	last_result: string;
}

let counter = 0;
function nextId(): string {
	counter += 1;
	return `${Date.now()}-${process.pid}-${counter}`;
}

export interface HistoryStore {
	dataDir: string;
}

export function openHistoryDb(dataDir: string): HistoryStore {
	mkdirSync(dataDir, { recursive: true });
	return { dataDir };
}

function alertsPath(store: HistoryStore): string {
	return `${store.dataDir}/alerts.jsonl`;
}

function statusPath(store: HistoryStore): string {
	return `${store.dataDir}/scan_status.json`;
}

function readAllAlerts(store: HistoryStore): Alert[] {
	const path = alertsPath(store);
	if (!existsSync(path)) return [];
	const lines = readFileSync(path, "utf-8")
		.split("\n")
		.filter((l) => l.trim());
	const alerts: Alert[] = [];
	for (const line of lines) {
		try {
			alerts.push(JSON.parse(line));
		} catch {
			// corrupted/partial line — skip rather than fail the whole read
		}
	}
	return alerts;
}

/** Only ever called when a finding actually crosses the alert-worthy threshold. */
export function insertAlert(
	store: HistoryStore,
	args: {
		module: string;
		severity: Severity;
		summary: string;
		detail: unknown;
		suppressed?: boolean;
		whitelistRuleId?: string | null;
	},
): string {
	const id = nextId();
	const alert: Alert = {
		id,
		ts: new Date().toISOString(),
		module: args.module,
		severity: args.severity,
		summary: args.summary,
		detail: args.detail,
		emailed: false,
		suppressed: args.suppressed ?? false,
		whitelistRuleId: args.whitelistRuleId ?? null,
	};
	appendFileSync(alertsPath(store), `${JSON.stringify(alert)}\n`);
	return id;
}

/** Rewrites the whole file with the matching row updated — fine at the low volume this sees. */
export function markEmailed(store: HistoryStore, id: string): void {
	const path = alertsPath(store);
	const alerts = readAllAlerts(store).map((a) =>
		a.id === id ? { ...a, emailed: true } : a,
	);
	const content =
		alerts.map((a) => JSON.stringify(a)).join("\n") +
		(alerts.length ? "\n" : "");
	const tmpPath = `${path}.tmp-${process.pid}`;
	writeFileSync(tmpPath, content);
	renameSync(tmpPath, path);
}

export function getAlerts(
	store: HistoryStore,
	opts: {
		since?: string;
		module?: string;
		limit?: number;
		/** Defaults to false (existing behavior) — alerts recorded before this field existed have
		 * no `suppressed` key at all, which reads the same as false here. Pass true to fetch the
		 * "Suppressed Events" review list instead. */
		suppressed?: boolean;
	} = {},
): Alert[] {
	let alerts = readAllAlerts(store);
	if (opts.since) alerts = alerts.filter((a) => a.ts >= opts.since!);
	if (opts.module) alerts = alerts.filter((a) => a.module === opts.module);
	const wantSuppressed = opts.suppressed ?? false;
	alerts = alerts.filter((a) => Boolean(a.suppressed) === wantSuppressed);
	alerts.sort((a, b) => (a.ts < b.ts ? 1 : -1));
	return alerts.slice(0, opts.limit ?? 200);
}

export function getAlertById(
	store: HistoryStore,
	id: string,
): Alert | undefined {
	return readAllAlerts(store).find((a) => a.id === id);
}

/** Fixed-size, one row per module — overwritten every scan, never grows. */
export function upsertScanStatus(
	store: HistoryStore,
	module: string,
	result: string,
): void {
	const all = readJson<Record<string, ScanStatus>>(statusPath(store), {});
	all[module] = { last_scan_ts: new Date().toISOString(), last_result: result };
	writeJsonAtomic(statusPath(store), all);
}

export function getScanStatus(
	store: HistoryStore,
): (ScanStatus & { module: string })[] {
	const all = readJson<Record<string, ScanStatus>>(statusPath(store), {});
	return Object.entries(all).map(([module, status]) => ({ module, ...status }));
}
