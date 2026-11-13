import { describe, expect, test } from "bun:test";
import { formatDetailLines } from "./format-detail.ts";

describe("formatDetailLines — flat objects", () => {
	test("renders label: value lines with humanized keys", () => {
		const lines = formatDetailLines({ exePath: "/usr/bin/test", pid: 1234 });
		expect(lines).toContain("Exe Path: /usr/bin/test");
		expect(lines).toContain("Pid: 1234");
	});

	test("null/undefined detail yields no lines", () => {
		expect(formatDetailLines(null)).toEqual([]);
		expect(formatDetailLines(undefined)).toEqual([]);
	});
});

describe("formatDetailLines — FIM previous/current diff", () => {
	test("changed fields render as old -> new", () => {
		const lines = formatDetailLines({
			path: "/usr/bin/curl",
			previous: { hash: "a".repeat(64), size: 297288 },
			current: { hash: "b".repeat(64), size: 297288 },
		});
		expect(lines[0]).toBe("File: /usr/bin/curl");
		expect(lines.some((l) => l.startsWith("Hash:") && l.includes("->"))).toBe(
			true,
		);
	});

	test("unchanged fields are marked (unchanged), not repeated as a diff", () => {
		const lines = formatDetailLines({
			path: "/usr/bin/curl",
			previous: { hash: "a".repeat(64), size: 297288 },
			current: { hash: "b".repeat(64), size: 297288 },
		});
		expect(lines.some((l) => l === "Size: 297,288 bytes (unchanged)")).toBe(
			true,
		);
	});

	test("long hex hashes are truncated, not dumped in full", () => {
		const hash =
			"459c937b69bd76620d6d01100a0793294349c89871f4474d398efdae49fcee";
		const lines = formatDetailLines({
			path: "/usr/bin/dig",
			previous: { hash },
			current: { hash: `${hash.slice(0, -1)}0` },
		});
		const hashLine = lines.find((l) => l.startsWith("Hash:"));
		expect(hashLine).toBeDefined();
		expect(hashLine).not.toContain(hash);
		expect(hashLine).toContain("…");
	});

	test("ISO date fields render as human-readable timestamps", () => {
		const lines = formatDetailLines({
			path: "/usr/bin/curl",
			previous: { mtime: "2026-07-06T17:02:02.000Z" },
			current: { mtime: "2026-08-18T19:28:10.000Z" },
		});
		const mtimeLine = lines.find((l) => l.startsWith("Mtime:"));
		expect(mtimeLine).toBeDefined();
		expect(mtimeLine).not.toContain("2026-07-06T17:02:02.000Z");
		expect(mtimeLine).not.toContain("2026-08-18T19:28:10.000Z");
	});
});
