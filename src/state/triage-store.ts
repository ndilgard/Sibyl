import { appendFileSync, existsSync, readFileSync } from "node:fs";
import type { HistoryStore } from "./history-db.ts";

/**
 * Companion store to history-db.ts's alerts.jsonl — one row per AI triage verdict, keyed by the
 * alert it judged. Same append-only-JSONL-on-NAS pattern as history-db.ts (bun:sqlite ruled out
 * repo-wide for SQLITE_BUSY over the SMB mount — don't reintroduce it here). Never mutates
 * alerts.jsonl itself; a verdict is a separate fact about an alert, not an edit to it.
 */

export type Verdict = "alarming" | "benign" | "unreviewed";

export interface TriageVerdict {
	id: string;
	alertId: string;
	/** "unreviewed" means the API call failed or returned something unparseable — the fail-safe
	 * path. Never silently drop a finding; an unreviewed alert still shows up as needing a human
	 * look, same as if the AI layer didn't exist. */
	verdict: Verdict;
	reasoning: string;
	/** What to look for / suggested next steps. Empty string, not omitted, when there's nothing
	 * more specific to add (e.g. a clear-cut benign verdict) — keeps the field always-present for
	 * callers rather than optional. */
	suggestions: string;
	ts: string;
}

let counter = 0;
function nextId(): string {
	counter += 1;
	return `triage-${Date.now()}-${process.pid}-${counter}`;
}

function triagePath(store: HistoryStore): string {
	return `${store.dataDir}/triage.jsonl`;
}

function readAllVerdicts(store: HistoryStore): TriageVerdict[] {
	const path = triagePath(store);
	if (!existsSync(path)) return [];
	const lines = readFileSync(path, "utf-8")
		.split("\n")
		.filter((l) => l.trim());
	const verdicts: TriageVerdict[] = [];
	for (const line of lines) {
		try {
			verdicts.push(JSON.parse(line));
		} catch {
			// corrupted/partial line — skip rather than fail the whole read
		}
	}
	return verdicts;
}

export function insertVerdict(
	store: HistoryStore,
	args: {
		alertId: string;
		verdict: Verdict;
		reasoning: string;
		suggestions: string;
	},
): string {
	const id = nextId();
	const record: TriageVerdict = {
		id,
		alertId: args.alertId,
		verdict: args.verdict,
		reasoning: args.reasoning,
		suggestions: args.suggestions,
		ts: new Date().toISOString(),
	};
	appendFileSync(triagePath(store), `${JSON.stringify(record)}\n`);
	return id;
}

/** Last verdict wins if an alert is somehow triaged twice (shouldn't happen in normal operation
 * since getTriagedAlertIds() is checked before triaging, but a race is cheaper to tolerate than
 * to prevent here). */
export function getVerdictByAlertId(
	store: HistoryStore,
	alertId: string,
): TriageVerdict | undefined {
	const matches = readAllVerdicts(store).filter((v) => v.alertId === alertId);
	return matches.at(-1);
}

/** The set of alertIds that already have a verdict recorded — callers use this to filter
 * history-db.ts's getAlerts() down to only what still needs triage. */
export function getTriagedAlertIds(store: HistoryStore): Set<string> {
	return new Set(readAllVerdicts(store).map((v) => v.alertId));
}
