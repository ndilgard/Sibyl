import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Incident } from "./correlate.ts";
import { type HistoryStore, openHistoryDb } from "./history-db.ts";
import {
	getCorrelatedAlertIds,
	getIncidentById,
	insertIncident,
	updateIncident,
} from "./incident-store.ts";

let store: HistoryStore;

function sampleIncident(overrides: Partial<Incident> = {}): Incident {
	return {
		id: "incident-1",
		alertIds: ["a1", "a2"],
		modules: ["fim", "network"],
		sharedIdentifier: "exePath:/usr/bin/evil-cron",
		windowStart: "2026-11-09T12:00:00.000Z",
		windowEnd: "2026-11-09T12:00:05.000Z",
		...overrides,
	};
}

beforeEach(() => {
	store = openHistoryDb(mkdtempSync(join(tmpdir(), "hids-incident-test-")));
});

afterEach(() => {
	rmSync(store.dataDir, { recursive: true, force: true });
});

describe("insertIncident / getIncidentById round-trip", () => {
	test("an inserted incident round-trips with pending status and no report yet", () => {
		const record = insertIncident(store, sampleIncident());
		expect(record.status).toBe("pending");
		expect(record.report).toBe("");
		expect(record.emailed).toBe(false);

		const found = getIncidentById(store, "incident-1");
		expect(found?.alertIds).toEqual(["a1", "a2"]);
		expect(found?.sharedIdentifier).toBe("exePath:/usr/bin/evil-cron");
	});

	test("returns undefined for an incident that was never recorded", () => {
		expect(getIncidentById(store, "does-not-exist")).toBeUndefined();
	});
});

describe("updateIncident", () => {
	test("patches status and report, preserving the original grouping fields", () => {
		insertIncident(store, sampleIncident());
		const updated = updateIncident(store, "incident-1", {
			status: "generated",
			report:
				"Timeline: FIM tamper at 12:00:00, outbound connection at 12:00:05.",
		});

		expect(updated?.status).toBe("generated");
		expect(updated?.report).toContain("Timeline");
		expect(updated?.alertIds).toEqual(["a1", "a2"]);

		const reread = getIncidentById(store, "incident-1");
		expect(reread?.status).toBe("generated");
	});

	test("fail-safe unreviewed status round-trips", () => {
		insertIncident(store, sampleIncident({ id: "incident-2" }));
		updateIncident(store, "incident-2", {
			status: "unreviewed",
			report: "",
		});
		expect(getIncidentById(store, "incident-2")?.status).toBe("unreviewed");
	});

	test("marking emailed after report generation", () => {
		insertIncident(store, sampleIncident({ id: "incident-3" }));
		updateIncident(store, "incident-3", {
			status: "generated",
			report: "narrative",
		});
		updateIncident(store, "incident-3", { emailed: true });

		const final = getIncidentById(store, "incident-3");
		expect(final?.emailed).toBe(true);
		expect(final?.report).toBe("narrative");
	});

	test("returns undefined when patching an incident that was never inserted", () => {
		expect(
			updateIncident(store, "ghost", { status: "generated" }),
		).toBeUndefined();
	});
});

describe("getCorrelatedAlertIds", () => {
	test("returns every alertId folded into any recorded incident", () => {
		insertIncident(store, sampleIncident());
		insertIncident(
			store,
			sampleIncident({ id: "incident-2", alertIds: ["a3", "a4", "a5"] }),
		);

		const ids = getCorrelatedAlertIds(store);
		expect(ids.has("a1")).toBe(true);
		expect(ids.has("a4")).toBe(true);
		expect(ids.has("a6")).toBe(false);
	});

	test("empty store returns an empty set", () => {
		expect(getCorrelatedAlertIds(store).size).toBe(0);
	});
});
