import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readJson, writeJsonAtomic } from "./json-store.ts";

let dir: string;

beforeEach(() => {
	dir = mkdtempSync(join(tmpdir(), "hids-test-"));
});

afterEach(() => {
	rmSync(dir, { recursive: true, force: true });
});

describe("writeJsonAtomic / readJson", () => {
	test("round-trips arbitrary JSON-serializable data", () => {
		const path = join(dir, "baseline.json");
		const data = { foo: "bar", nested: { n: 1 }, list: [1, 2, 3] };
		writeJsonAtomic(path, data);
		expect(readJson<typeof data | null>(path, null)).toEqual(data);
	});

	test("creates parent directories that don't exist yet", () => {
		const path = join(dir, "nested", "deeper", "baseline.json");
		writeJsonAtomic(path, { ok: true });
		expect(readJson<{ ok: boolean } | null>(path, null)).toEqual({ ok: true });
	});

	test("readJson returns the fallback when the file doesn't exist", () => {
		const path = join(dir, "missing.json");
		expect(readJson(path, { fallback: true })).toEqual({ fallback: true });
	});

	test("leaves no leftover .tmp-{pid} file after a write (atomicity)", () => {
		const path = join(dir, "baseline.json");
		writeJsonAtomic(path, { a: 1 });
		const entries = readdirSync(dir);
		expect(entries).toEqual(["baseline.json"]);
		expect(existsSync(`${path}.tmp-${process.pid}`)).toBe(false);
	});

	test("a second write fully replaces the first (not merged)", () => {
		const path = join(dir, "baseline.json");
		writeJsonAtomic(path, { a: 1 });
		writeJsonAtomic(path, { b: 2 });
		expect(readJson<{ b: number } | null>(path, null)).toEqual({ b: 2 });
	});
});
