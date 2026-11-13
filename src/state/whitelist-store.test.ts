import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { HistoryStore } from "./history-db.ts";
import {
	addWhitelistRule,
	defaultWhitelistField,
	findMatchingRule,
	getWhitelistRules,
	recordWhitelistMatch,
	removeWhitelistRule,
	WHITELISTABLE_MODULES,
} from "./whitelist-store.ts";

let store: HistoryStore;

beforeEach(() => {
	store = { dataDir: mkdtempSync(join(tmpdir(), "hids-test-")) };
});

afterEach(() => {
	rmSync(store.dataDir, { recursive: true, force: true });
});

describe("WHITELISTABLE_MODULES / defaultWhitelistField", () => {
	test("network, fim, process are whitelistable; auth is not", () => {
		expect(WHITELISTABLE_MODULES).toEqual(["network", "fim", "process"]);
		expect(WHITELISTABLE_MODULES).not.toContain("auth");
	});

	test("fim defaults to matching on path, everything else on exePath", () => {
		expect(defaultWhitelistField("fim")).toBe("path");
		expect(defaultWhitelistField("network")).toBe("exePath");
		expect(defaultWhitelistField("process")).toBe("exePath");
	});
});

describe("addWhitelistRule / getWhitelistRules", () => {
	test("returns no rules for an empty store", () => {
		expect(getWhitelistRules(store)).toEqual([]);
	});

	test("adds a rule with zeroed match counters", () => {
		const rule = addWhitelistRule(store, {
			module: "network",
			field: "exePath",
			value: "/usr/bin/firefox",
		});
		expect(rule.matchCount).toBe(0);
		expect(rule.lastMatchedAt).toBeNull();
		expect(rule.id).toBeTruthy();
		expect(getWhitelistRules(store)).toHaveLength(1);
	});

	test("lists rules newest-first", async () => {
		addWhitelistRule(store, {
			module: "network",
			field: "exePath",
			value: "/a",
		});
		await Bun.sleep(2); // ensure a distinct createdAt timestamp
		addWhitelistRule(store, {
			module: "network",
			field: "exePath",
			value: "/b",
		});
		const rules = getWhitelistRules(store);
		expect(rules.map((r) => r.value)).toEqual(["/b", "/a"]);
	});
});

describe("removeWhitelistRule", () => {
	test("removes only the matching rule by id", () => {
		const a = addWhitelistRule(store, {
			module: "network",
			field: "exePath",
			value: "/a",
		});
		const b = addWhitelistRule(store, {
			module: "network",
			field: "exePath",
			value: "/b",
		});
		removeWhitelistRule(store, a.id);
		const remaining = getWhitelistRules(store);
		expect(remaining).toHaveLength(1);
		expect(remaining[0]!.id).toBe(b.id);
	});
});

describe("recordWhitelistMatch", () => {
	test("increments matchCount and sets lastMatchedAt", () => {
		const rule = addWhitelistRule(store, {
			module: "fim",
			field: "path",
			value: "/etc/passwd",
		});
		recordWhitelistMatch(store, rule.id);
		recordWhitelistMatch(store, rule.id);
		const [updated] = getWhitelistRules(store);
		expect(updated!.matchCount).toBe(2);
		expect(updated!.lastMatchedAt).not.toBeNull();
	});
});

describe("findMatchingRule", () => {
	test("matches on exact field+value for the given module", () => {
		addWhitelistRule(store, {
			module: "network",
			field: "exePath",
			value: "/usr/bin/firefox",
		});
		const match = findMatchingRule(store, "network", {
			exePath: "/usr/bin/firefox",
		});
		expect(match?.value).toBe("/usr/bin/firefox");
	});

	test("does not match a different module even with the same field+value", () => {
		addWhitelistRule(store, {
			module: "network",
			field: "exePath",
			value: "/usr/bin/firefox",
		});
		const match = findMatchingRule(store, "fim", {
			exePath: "/usr/bin/firefox",
		});
		expect(match).toBeNull();
	});

	test("does not match a different value (exact match only, no prefix/substring)", () => {
		addWhitelistRule(store, {
			module: "network",
			field: "exePath",
			value: "/usr/bin/firefox",
		});
		const match = findMatchingRule(store, "network", {
			exePath: "/usr/bin/firefox-bin",
		});
		expect(match).toBeNull();
	});

	test("returns null when the finding's detail lacks the rule's field entirely", () => {
		addWhitelistRule(store, {
			module: "network",
			field: "exePath",
			value: "/usr/bin/firefox",
		});
		expect(
			findMatchingRule(store, "network", { somethingElse: "x" }),
		).toBeNull();
	});

	test("returns null for a non-object detail", () => {
		addWhitelistRule(store, {
			module: "network",
			field: "exePath",
			value: "/usr/bin/firefox",
		});
		expect(findMatchingRule(store, "network", "not an object")).toBeNull();
		expect(findMatchingRule(store, "network", null)).toBeNull();
	});

	test("returns null when there are no rules for that module at all", () => {
		expect(
			findMatchingRule(store, "network", { exePath: "/usr/bin/firefox" }),
		).toBeNull();
	});
});
