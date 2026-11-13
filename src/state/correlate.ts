import type { Alert } from "./history-db.ts";
import { extractIdentifiers } from "./identifiers.ts";

/**
 * Groups alerts from *different* modules into incidents when they fall within a shared time
 * window AND share a real identifier (same exePath, pid, parent directory, or IP) — see
 * ~/.claude/plans/hids-cross-module-correlation.md for the full design/rationale. Deliberately
 * not time-window-only and not LLM-judged: hand-coded identifier matching is auditable and won't
 * lump unrelated coincidences together during a busy scan.
 *
 * Same-module alerts never correlate with each other here — that's already deduped/suppressed by
 * each module's own logic before an alert reaches this stage. This engine only looks for links
 * *across* modules.
 */

export interface Incident {
	id: string;
	alertIds: string[];
	modules: string[];
	sharedIdentifier: string;
	windowStart: string;
	windowEnd: string;
}

let counter = 0;
function nextIncidentId(): string {
	counter += 1;
	return `incident-${Date.now()}-${process.pid}-${counter}`;
}

function identifierKey(kind: string, value: string): string {
	return `${kind}:${value}`;
}

/**
 * Union-find (disjoint set) over alert indices, so an incident can grow by more than one shared
 * identifier (e.g. A-B share an exePath, B-C share an IP) without needing a second merge pass.
 */
function find(parent: number[], i: number): number {
	while (parent[i] !== i) {
		parent[i] = parent[parent[i]];
		i = parent[i];
	}
	return i;
}

function union(parent: number[], a: number, b: number): void {
	const rootA = find(parent, a);
	const rootB = find(parent, b);
	if (rootA !== rootB) parent[rootA] = rootB;
}

/**
 * Groups `alerts` into cross-module incidents. Only groups of 2+ alerts spanning 2+ distinct
 * modules are returned — a lone alert, or several alerts from only one module, is not an
 * incident on its own and produces no entry. `windowMs` bounds how far apart (by `ts`) two
 * alerts may be and still be considered for correlation (inclusive of the boundary).
 */
export function correlateAlerts(alerts: Alert[], windowMs: number): Incident[] {
	const n = alerts.length;
	if (n < 2) return [];

	const times = alerts.map((a) => new Date(a.ts).getTime());
	const idsByAlert = alerts.map((a) => extractIdentifiers(a));

	const parent = Array.from({ length: n }, (_, i) => i);
	// For each (kind, value) pair, which alert indices carry it — used both to union matches and
	// to record which identifier actually linked a given incident.
	const linkFor: Map<string, string> = new Map();

	for (let i = 0; i < n; i++) {
		for (let j = i + 1; j < n; j++) {
			if (alerts[i].module === alerts[j].module) continue;
			if (Math.abs(times[i] - times[j]) > windowMs) continue;

			for (const idA of idsByAlert[i]) {
				const match = idsByAlert[j].find(
					(idB) => idB.kind === idA.kind && idB.value === idA.value,
				);
				if (!match) continue;
				union(parent, i, j);
				const key = identifierKey(idA.kind, idA.value);
				if (!linkFor.has(`${find(parent, i)}`)) {
					linkFor.set(`${find(parent, i)}`, key);
				}
				break;
			}
		}
	}

	const groups = new Map<number, number[]>();
	for (let i = 0; i < n; i++) {
		const root = find(parent, i);
		const group = groups.get(root);
		if (group) group.push(i);
		else groups.set(root, [i]);
	}

	const incidents: Incident[] = [];
	for (const [root, indices] of groups) {
		if (indices.length < 2) continue;
		const modules = new Set(indices.map((i) => alerts[i].module));
		if (modules.size < 2) continue;

		const groupTimes = indices.map((i) => times[i]);
		incidents.push({
			id: nextIncidentId(),
			alertIds: indices.map((i) => alerts[i].id),
			modules: [...modules],
			sharedIdentifier: linkFor.get(`${root}`) ?? "",
			windowStart: new Date(Math.min(...groupTimes)).toISOString(),
			windowEnd: new Date(Math.max(...groupTimes)).toISOString(),
		});
	}

	return incidents;
}
