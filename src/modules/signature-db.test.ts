import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { HidsConfig } from "../config.ts";
import {
	getScanStatus,
	type HistoryStore,
	openHistoryDb,
} from "../state/history-db.ts";
import type {
	SignatureDbStore,
	SignatureEntry,
} from "../state/signature-db-store.ts";
import type { MalwareBazaarClient } from "./signature-db.ts";
import {
	createSignatureDbModule,
	parseMalwareBazaarCsv,
} from "./signature-db.ts";

describe("parseMalwareBazaarCsv", () => {
	const header =
		"first_seen_utc,sha256_hash,md5_hash,sha1_hash,reporter,file_name,file_type_guess,mime_type,signature,clamav,vtpercent,imphash,ssdeep,tlsh";

	test("parses a real-shaped row into a SignatureEntry", () => {
		const row =
			'2026-08-27 00:00:00,ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789,md5x,sha1x,reporter1,"payload, v2.exe",exe,application/x-dosexec,Trojan.GenericKD,clamavsig,90,imphashx,ssdeepx,tlshx';
		const result = parseMalwareBazaarCsv([header, row].join("\n"));
		expect(result).toEqual([
			{
				sha256:
					"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				signature: "Trojan.GenericKD",
				fileType: "exe",
				firstSeen: "2026-08-27 00:00:00",
			},
		]);
	});

	test("skips comment lines and blank lines", () => {
		const result = parseMalwareBazaarCsv(
			["# generated 2026-08-27", header, "", "   "].join("\n"),
		);
		expect(result).toEqual([]);
	});

	test("skips a row with an empty sha256_hash", () => {
		const row =
			"2026-08-27,,md5x,sha1x,reporter1,file.exe,exe,mimex,sig,clam,90,imp,ssdeepx,tlshx";
		expect(parseMalwareBazaarCsv([header, row].join("\n"))).toEqual([]);
	});

	test("throws when the sha256_hash column is missing entirely", () => {
		expect(() =>
			parseMalwareBazaarCsv(["reporter,file_name", "a,b"].join("\n")),
		).toThrow();
	});

	test("column order doesn't matter — looked up by header name", () => {
		const reordered = "sha256_hash,signature,file_type_guess,first_seen_utc";
		const row = `${"a".repeat(64)},Trojan.X,exe,2026-08-27`;
		const result = parseMalwareBazaarCsv([reordered, row].join("\n"));
		expect(result).toEqual([
			{
				sha256: "a".repeat(64),
				signature: "Trojan.X",
				fileType: "exe",
				firstSeen: "2026-08-27",
			},
		]);
	});
});

function signatureDbConfig(): HidsConfig["signatureDb"] {
	return {
		enabled: true,
		feed: "recent",
		refreshIntervalMs: 6 * 60 * 60 * 1000,
		authKeyEnvPath: "unused-in-tests",
	};
}

function fakeStore(): SignatureDbStore & {
	replaceAllCalls: Array<{ entries: SignatureEntry[]; refreshedAt: string }>;
} {
	const replaceAllCalls: Array<{
		entries: SignatureEntry[];
		refreshedAt: string;
	}> = [];
	let size = 0;
	let lastRefreshedAt: string | null = null;
	return {
		replaceAllCalls,
		lookup: () => null,
		size: () => size,
		lastRefreshedAt: () => lastRefreshedAt,
		replaceAll(entries, refreshedAt) {
			replaceAllCalls.push({ entries, refreshedAt });
			size = entries.length;
			lastRefreshedAt = refreshedAt;
		},
	};
}

function fakeClient(
	fetchHashes: MalwareBazaarClient["fetchHashes"],
): MalwareBazaarClient {
	return { fetchHashes };
}

let db: HistoryStore;

beforeEach(() => {
	db = openHistoryDb(
		mkdtempSync(join(tmpdir(), "hids-signature-db-module-test-")),
	);
});

afterEach(() => {
	rmSync(db.dataDir, { recursive: true, force: true });
});

describe("createSignatureDbModule — scanNow", () => {
	test("success: calls store.replaceAll and records an 'ok' scan status", async () => {
		const store = fakeStore();
		const entries: SignatureEntry[] = [{ sha256: "a".repeat(64) }];
		const client = fakeClient(async () => entries);

		const mod = createSignatureDbModule(
			{
				config: { signatureDb: signatureDbConfig() } as HidsConfig,
				db,
				recorder: undefined as never,
				signatureDb: store,
			},
			client,
		);
		await mod.scanNow();

		expect(store.replaceAllCalls).toHaveLength(1);
		expect(store.replaceAllCalls[0]?.entries).toEqual(entries);
		const status = getScanStatus(db).find((s) => s.module === "signature-db");
		expect(status?.last_result).toContain("ok (1 hashes");
	});

	test("failure: does NOT call replaceAll, records a 'refresh failed' status, never throws", async () => {
		const store = fakeStore();
		const client = fakeClient(async () => {
			throw new Error("network unreachable");
		});

		const mod = createSignatureDbModule(
			{
				config: { signatureDb: signatureDbConfig() } as HidsConfig,
				db,
				recorder: undefined as never,
				signatureDb: store,
			},
			client,
		);
		await mod.scanNow(); // must not reject

		expect(store.replaceAllCalls).toHaveLength(0);
		const status = getScanStatus(db).find((s) => s.module === "signature-db");
		expect(status?.last_result).toContain(
			"refresh failed: network unreachable",
		);
		expect(status?.last_result).toContain("serving last-good cache");
	});

	test("failure keeps reporting the last-good cache size/timestamp from a prior success", async () => {
		const store = fakeStore();
		let call = 0;
		const client = fakeClient(async () => {
			call++;
			if (call === 1)
				return [{ sha256: "a".repeat(64) }, { sha256: "b".repeat(64) }];
			throw new Error("timed out");
		});

		const mod = createSignatureDbModule(
			{
				config: { signatureDb: signatureDbConfig() } as HidsConfig,
				db,
				recorder: undefined as never,
				signatureDb: store,
			},
			client,
		);
		await mod.scanNow();
		await mod.scanNow();

		const status = getScanStatus(db).find((s) => s.module === "signature-db");
		expect(status?.last_result).toContain("2 hashes from");
	});
});

describe("createSignatureDbModule — start/stop", () => {
	test("enabled: false makes start() a no-op — no immediate fetch", () => {
		const store = fakeStore();
		let calls = 0;
		const client = fakeClient(async () => {
			calls++;
			return [];
		});

		const mod = createSignatureDbModule(
			{
				config: {
					signatureDb: { ...signatureDbConfig(), enabled: false },
				} as HidsConfig,
				db,
				recorder: undefined as never,
				signatureDb: store,
			},
			client,
		);
		mod.start();
		expect(calls).toBe(0);
		mod.stop();
	});

	test("enabled: true fires an immediate scan on start()", async () => {
		const store = fakeStore();
		let calls = 0;
		const client = fakeClient(async () => {
			calls++;
			return [];
		});

		const mod = createSignatureDbModule(
			{
				config: { signatureDb: signatureDbConfig() } as HidsConfig,
				db,
				recorder: undefined as never,
				signatureDb: store,
			},
			client,
		);
		mod.start();
		await Bun.sleep(20);
		expect(calls).toBe(1);
		mod.stop();
	});
});
