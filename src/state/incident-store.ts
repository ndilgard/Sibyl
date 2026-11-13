import { appendFileSync, existsSync, readFileSync } from "node:fs";
import type { Incident } from "./correlate.ts";
import type { HistoryStore } from "./history-db.ts";

/**
 * Companion store to history-db.ts's alerts.jsonl — one row per correlated incident, carrying
 * the alert grouping from correlate.ts plus the triage agent's generated investigation report
 * and whether it's been emailed yet. Same append-only-JSONL-on-NAS pattern as history-db.ts /
 * triage-store.ts (bun:sqlite ruled out repo-wide for SQLITE_BUSY over the SMB mount — don't
 * reintroduce it here).
 *
 * Exists so a restart doesn't regenerate/re-send a report for an incident already handled: the
 * triage cycle checks getCorrelatedAlertIds() before re-running correlateAlerts() over alerts
 * that already belong to a recorded incident.
 */

export type IncidentReportStatus = "pending" | "generated" | "unreviewed";

export interface IncidentRecord extends Incident {
	/** "pending" until the report-generation step runs; "unreviewed" is the same fail-safe
	 * meaning as triage-store's Verdict — API failure or unparseable response, never silently
	 * dropped. "generated" means `report` holds real narrative text ready to email. */
	status: IncidentReportStatus;
	report: string;
	emailed: boolean;
	ts: string;
}

function incidentsPath(store: HistoryStore): string {
	return `${store.dataDir}/incidents.jsonl`;
}

function readAllIncidents(store: HistoryStore): IncidentRecord[] {
	const path = incidentsPath(store);
	if (!existsSync(path)) return [];
	const lines = readFileSync(path, "utf-8")
		.split("\n")
		.filter((l) => l.trim());
	const records: IncidentRecord[] = [];
	for (const line of lines) {
		try {
			records.push(JSON.parse(line));
		} catch {
			// corrupted/partial line — skip rather than fail the whole read
		}
	}
	return records;
}

/** Records a freshly-correlated incident with no report yet (status "pending"). Returns the
 * stored record so the caller has its `ts`/full shape without a re-read. */
export function insertIncident(
	store: HistoryStore,
	incident: Incident,
): IncidentRecord {
	const record: IncidentRecord = {
		...incident,
		status: "pending",
		report: "",
		emailed: false,
		ts: new Date().toISOString(),
	};
	appendFileSync(incidentsPath(store), `${JSON.stringify(record)}\n`);
	return record;
}

/** Appends an updated copy of the incident with its generated report (or fail-safe "unreviewed"
 * status) and/or emailed flag. Append-only like the rest of this layer — readers always take the
 * last record for a given id, mirroring triage-store's "last verdict wins" pattern. */
export function updateIncident(
	store: HistoryStore,
	id: string,
	patch: Partial<Pick<IncidentRecord, "status" | "report" | "emailed">>,
): IncidentRecord | undefined {
	const existing = getIncidentById(store, id);
	if (!existing) return undefined;
	const updated: IncidentRecord = {
		...existing,
		...patch,
		ts: new Date().toISOString(),
	};
	appendFileSync(incidentsPath(store), `${JSON.stringify(updated)}\n`);
	return updated;
}

/** Last record wins if an incident id appears more than once (insert, then one or more
 * updates) — same tolerate-the-race stance as triage-store.ts. */
export function getIncidentById(
	store: HistoryStore,
	id: string,
): IncidentRecord | undefined {
	const matches = readAllIncidents(store).filter((r) => r.id === id);
	return matches.at(-1);
}

/** The set of alertIds already folded into some recorded incident — callers use this to filter
 * a batch of alerts down to only ones not yet considered for correlation, so re-running
 * correlateAlerts() on every triage cycle doesn't regenerate/re-send an existing incident's
 * report. */
export function getCorrelatedAlertIds(store: HistoryStore): Set<string> {
	const ids = new Set<string>();
	for (const record of readAllIncidents(store)) {
		for (const alertId of record.alertIds) ids.add(alertId);
	}
	return ids;
}
