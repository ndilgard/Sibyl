import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { appendFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	getAlertById,
	getAlerts,
	getScanStatus,
	type HistoryStore,
	insertAlert,
	markEmailed,
	openHistoryDb,
	upsertScanStatus,
} from "./history-db.ts";

let store: HistoryStore;

beforeEach(() => {
	store = openHistoryDb(mkdtempSync(join(tmpdir(), "hids-test-")));
});

afterEach(() => {
	rmSync(store.dataDir, { recursive: true, force: true });
});

describe("insertAlert / getAlerts round-trip", () => {
	test("an inserted alert round-trips with expected defaults", () => {
		const id = insertAlert(store, {
			module: "fim",
			severity: "critical",
			summary: "Watched file modified: /etc/passwd",
			detail: { path: "/etc/passwd" },
		});
		const [alert] = getAlerts(store);
		expect(alert!.id).toBe(id);
		expect(alert!.emailed).toBe(false);
		expect(alert!.suppressed).toBe(false);
		expect(alert!.whitelistRuleId).toBeNull();
	});

	test("getAlerts defaults to non-suppressed alerts only", () => {
		insertAlert(store, {
			module: "network",
			severity: "warning",
			summary: "a",
			detail: {},
			suppressed: true,
			whitelistRuleId: "rule-1",
		});
		expect(getAlerts(store)).toEqual([]);
		expect(getAlerts(store, { suppressed: true })).toHaveLength(1);
	});

	test("filters by module", () => {
		insertAlert(store, {
			module: "fim",
			severity: "warning",
			summary: "a",
			detail: {},
		});
		insertAlert(store, {
			module: "network",
			severity: "warning",
			summary: "b",
			detail: {},
		});
		const fimOnly = getAlerts(store, { module: "fim" });
		expect(fimOnly).toHaveLength(1);
		expect(fimOnly[0]!.module).toBe("fim");
	});

	test("filters by since (ts-based)", async () => {
		insertAlert(store, {
			module: "fim",
			severity: "warning",
			summary: "old",
			detail: {},
		});
		await Bun.sleep(2);
		const cutoff = new Date().toISOString();
		await Bun.sleep(2);
		insertAlert(store, {
			module: "fim",
			severity: "warning",
			summary: "new",
			detail: {},
		});
		const recent = getAlerts(store, { since: cutoff });
		expect(recent).toHaveLength(1);
		expect(recent[0]!.summary).toBe("new");
	});

	test("sorts newest first", async () => {
		insertAlert(store, {
			module: "fim",
			severity: "warning",
			summary: "first",
			detail: {},
		});
		await Bun.sleep(2);
		insertAlert(store, {
			module: "fim",
			severity: "warning",
			summary: "second",
			detail: {},
		});
		const alerts = getAlerts(store);
		expect(alerts.map((a) => a.summary)).toEqual(["second", "first"]);
	});

	test("defaults limit to 200", () => {
		for (let i = 0; i < 205; i++) {
			insertAlert(store, {
				module: "fim",
				severity: "info",
				summary: `n${i}`,
				detail: {},
			});
		}
		expect(getAlerts(store)).toHaveLength(200);
	});

	test("respects an explicit limit", () => {
		insertAlert(store, {
			module: "fim",
			severity: "info",
			summary: "a",
			detail: {},
		});
		insertAlert(store, {
			module: "fim",
			severity: "info",
			summary: "b",
			detail: {},
		});
		expect(getAlerts(store, { limit: 1 })).toHaveLength(1);
	});

	test("an alert record with no `suppressed` key at all reads as not-suppressed", () => {
		const legacy = {
			id: "legacy-1",
			ts: new Date().toISOString(),
			module: "fim",
			severity: "warning",
			summary: "pre-whitelist-feature alert",
			detail: {},
			emailed: false,
		};
		appendFileSync(
			`${store.dataDir}/alerts.jsonl`,
			`${JSON.stringify(legacy)}\n`,
		);
		const alerts = getAlerts(store, { module: "fim" });
		expect(alerts.map((a) => a.id)).toContain("legacy-1");
	});
});

describe("getAlertById", () => {
	test("finds an alert by id", () => {
		const id = insertAlert(store, {
			module: "fim",
			severity: "info",
			summary: "a",
			detail: {},
		});
		expect(getAlertById(store, id)?.summary).toBe("a");
	});

	test("returns undefined for an unknown id", () => {
		expect(getAlertById(store, "does-not-exist")).toBeUndefined();
	});
});

describe("markEmailed", () => {
	test("sets emailed to true on the matching alert only", () => {
		const a = insertAlert(store, {
			module: "fim",
			severity: "info",
			summary: "a",
			detail: {},
		});
		const b = insertAlert(store, {
			module: "fim",
			severity: "info",
			summary: "b",
			detail: {},
		});
		markEmailed(store, a);
		expect(getAlertById(store, a)?.emailed).toBe(true);
		expect(getAlertById(store, b)?.emailed).toBe(false);
	});
});

describe("upsertScanStatus / getScanStatus", () => {
	test("records and overwrites a fixed-size per-module status row", () => {
		upsertScanStatus(store, "fim", "baseline created");
		upsertScanStatus(store, "fim", "ok");
		upsertScanStatus(store, "network", "ok (0 listeners)");
		const statuses = getScanStatus(store);
		expect(statuses).toHaveLength(2);
		const fim = statuses.find((s) => s.module === "fim");
		expect(fim?.last_result).toBe("ok");
	});
});
