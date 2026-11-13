import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	createSignatureDbStore,
	noopSignatureDbStore,
} from "./signature-db-store.ts";

let dataDir: string;

beforeEach(() => {
	dataDir = mkdtempSync(join(tmpdir(), "hids-signature-db-store-test-"));
});

afterEach(() => {
	rmSync(dataDir, { recursive: true, force: true });
});

describe("createSignatureDbStore", () => {
	test("empty cache file: lookup misses, size 0, lastRefreshedAt null", () => {
		const store = createSignatureDbStore(dataDir);
		expect(store.lookup("abc123")).toBeNull();
		expect(store.size()).toBe(0);
		expect(store.lastRefreshedAt()).toBeNull();
	});

	test("replaceAll persists atomically and is readable from a fresh store instance", () => {
		const store = createSignatureDbStore(dataDir);
		store.replaceAll(
			[{ sha256: "a".repeat(64), signature: "Trojan.Test" }],
			"2026-08-27T00:00:00.000Z",
		);

		const reopened = createSignatureDbStore(dataDir);
		expect(reopened.size()).toBe(1);
		expect(reopened.lastRefreshedAt()).toBe("2026-08-27T00:00:00.000Z");
		expect(reopened.lookup("a".repeat(64))).toEqual({
			sha256: "a".repeat(64),
			signature: "Trojan.Test",
		});
	});

	test("lookup is case-insensitive", () => {
		const store = createSignatureDbStore(dataDir);
		store.replaceAll(
			[{ sha256: "ABCDEF0123456789".toLowerCase() }],
			"2026-08-27T00:00:00.000Z",
		);
		expect(store.lookup("ABCDEF0123456789")).not.toBeNull();
		expect(store.lookup("abcdef0123456789")).not.toBeNull();
	});

	test("replaceAll fully replaces the prior set, not merges", () => {
		const store = createSignatureDbStore(dataDir);
		store.replaceAll([{ sha256: "a".repeat(64) }], "2026-08-27T00:00:00.000Z");
		store.replaceAll([{ sha256: "b".repeat(64) }], "2026-08-27T06:00:00.000Z");
		expect(store.size()).toBe(1);
		expect(store.lookup("a".repeat(64))).toBeNull();
		expect(store.lookup("b".repeat(64))).not.toBeNull();
	});
});

describe("noopSignatureDbStore", () => {
	test("always reports a miss and never throws on replaceAll", () => {
		const store = noopSignatureDbStore();
		store.replaceAll([{ sha256: "a".repeat(64) }], "2026-08-27T00:00:00.000Z");
		expect(store.lookup("a".repeat(64))).toBeNull();
		expect(store.size()).toBe(0);
		expect(store.lastRefreshedAt()).toBeNull();
	});
});
