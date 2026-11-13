import {
	appendFileSync,
	existsSync,
	readFileSync,
	renameSync,
	writeFileSync,
} from "node:fs";
import type { HistoryStore } from "./history-db.ts";

/**
 * Same NAS-mount-safe append+rewrite JSONL pattern as alerts.jsonl in history-db.ts (SQLite
 * writes over the SMB/CIFS mount reliably fail with SQLITE_BUSY — see the comment there).
 */

/** Modules with a clean, structured field to match on. `auth` alerts are built from raw
 * journalctl text with nothing structured to key off — see policy.ts for the fuller rationale. */
export const WHITELISTABLE_MODULES = ["network", "fim", "process"];

/** Sensible default field to whitelist on for a given module's findings — used both by the
 * dashboard's inline form (its own copy, no build step to import from) and server-rendered
 * whitelist-from-email confirmation pages. */
export function defaultWhitelistField(module: string): string {
	return module === "fim" ? "path" : "exePath";
}

export interface WhitelistRule {
	id: string;
	module: string;
	/** Dot-free key into finding.detail, e.g. "exePath", "path". Exact match only. */
	field: string;
	value: string;
	note?: string;
	createdAt: string;
	matchCount: number;
	lastMatchedAt: string | null;
}

let counter = 0;
function nextId(): string {
	counter += 1;
	return `${Date.now()}-${process.pid}-${counter}`;
}

function whitelistPath(store: HistoryStore): string {
	return `${store.dataDir}/whitelist.jsonl`;
}

function readAllRules(store: HistoryStore): WhitelistRule[] {
	const path = whitelistPath(store);
	if (!existsSync(path)) return [];
	const lines = readFileSync(path, "utf-8")
		.split("\n")
		.filter((l) => l.trim());
	const rules: WhitelistRule[] = [];
	for (const line of lines) {
		try {
			rules.push(JSON.parse(line));
		} catch {
			// corrupted/partial line — skip rather than fail the whole read
		}
	}
	return rules;
}

function writeAllRules(store: HistoryStore, rules: WhitelistRule[]): void {
	const path = whitelistPath(store);
	const content =
		rules.map((r) => JSON.stringify(r)).join("\n") + (rules.length ? "\n" : "");
	const tmpPath = `${path}.tmp-${process.pid}`;
	writeFileSync(tmpPath, content);
	renameSync(tmpPath, path);
}

export function getWhitelistRules(store: HistoryStore): WhitelistRule[] {
	return readAllRules(store).sort((a, b) =>
		a.createdAt < b.createdAt ? 1 : -1,
	);
}

export function addWhitelistRule(
	store: HistoryStore,
	args: { module: string; field: string; value: string; note?: string },
): WhitelistRule {
	const rule: WhitelistRule = {
		id: nextId(),
		module: args.module,
		field: args.field,
		value: args.value,
		note: args.note,
		createdAt: new Date().toISOString(),
		matchCount: 0,
		lastMatchedAt: null,
	};
	appendFileSync(whitelistPath(store), `${JSON.stringify(rule)}\n`);
	return rule;
}

export function removeWhitelistRule(store: HistoryStore, id: string): void {
	const rules = readAllRules(store).filter((r) => r.id !== id);
	writeAllRules(store, rules);
}

/** Finds the first rule whose module+field+value matches the given finding detail, if any. */
export function findMatchingRule(
	store: HistoryStore,
	module: string,
	detail: unknown,
): WhitelistRule | null {
	if (typeof detail !== "object" || detail === null) return null;
	const rules = readAllRules(store).filter((r) => r.module === module);
	for (const rule of rules) {
		const actual = (detail as Record<string, unknown>)[rule.field];
		if (actual === rule.value) return rule;
	}
	return null;
}

export function recordWhitelistMatch(store: HistoryStore, id: string): void {
	const rules = readAllRules(store).map((r) =>
		r.id === id
			? {
					...r,
					matchCount: r.matchCount + 1,
					lastMatchedAt: new Date().toISOString(),
				}
			: r,
	);
	writeAllRules(store, rules);
}
