import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type HistoryStore, openHistoryDb } from "./history-db.ts";
import {
	getTriagedAlertIds,
	getVerdictByAlertId,
	insertVerdict,
} from "./triage-store.ts";

let store: HistoryStore;

beforeEach(() => {
	store = openHistoryDb(mkdtempSync(join(tmpdir(), "hids-triage-test-")));
});

afterEach(() => {
	rmSync(store.dataDir, { recursive: true, force: true });
});

describe("insertVerdict / getVerdictByAlertId round-trip", () => {
	test("an inserted verdict round-trips", () => {
		const id = insertVerdict(store, {
			alertId: "alert-1",
			verdict: "alarming",
			reasoning:
				"known process contacting a never-seen destination in a foreign ASN",
			suggestions: "check whether this process should ever talk to this host",
		});
		const verdict = getVerdictByAlertId(store, "alert-1");
		expect(verdict?.id).toBe(id);
		expect(verdict?.verdict).toBe("alarming");
		expect(verdict?.reasoning).toContain("foreign ASN");
	});

	test("returns undefined for an alert with no verdict yet", () => {
		expect(getVerdictByAlertId(store, "does-not-exist")).toBeUndefined();
	});

	test("benign verdict round-trips", () => {
		insertVerdict(store, {
			alertId: "alert-2",
			verdict: "benign",
			reasoning: "known process, previously-trusted destination subnet",
			suggestions: "",
		});
		expect(getVerdictByAlertId(store, "alert-2")?.verdict).toBe("benign");
	});

	test("unreviewed verdict round-trips (fail-safe path)", () => {
		insertVerdict(store, {
			alertId: "alert-3",
			verdict: "unreviewed",
			reasoning: "API call failed: request timed out",
			suggestions: "",
		});
		expect(getVerdictByAlertId(store, "alert-3")?.verdict).toBe("unreviewed");
	});
});

describe("getTriagedAlertIds", () => {
	test("returns the set of alertIds that already have a verdict", () => {
		insertVerdict(store, {
			alertId: "a",
			verdict: "benign",
			reasoning: "r",
			suggestions: "",
		});
		insertVerdict(store, {
			alertId: "b",
			verdict: "alarming",
			reasoning: "r",
			suggestions: "",
		});
		const ids = getTriagedAlertIds(store);
		expect(ids.has("a")).toBe(true);
		expect(ids.has("b")).toBe(true);
		expect(ids.has("c")).toBe(false);
	});

	test("empty store returns an empty set", () => {
		expect(getTriagedAlertIds(store).size).toBe(0);
	});
});
