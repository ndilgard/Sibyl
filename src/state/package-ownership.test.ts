import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	isPlausiblePath,
	parseOwningPackage,
	wasPackageRecentlyUpgraded,
} from "./package-ownership.ts";

describe("isPlausiblePath", () => {
	test("accepts a normal absolute path", () => {
		expect(isPlausiblePath("/usr/bin/curl")).toBe(true);
	});

	test("rejects a relative path", () => {
		expect(isPlausiblePath("usr/bin/curl")).toBe(false);
	});

	test("rejects an empty string", () => {
		expect(isPlausiblePath("")).toBe(false);
	});

	test("rejects a path containing a null byte", () => {
		expect(isPlausiblePath("/usr/bin/curl\0/etc/passwd")).toBe(false);
	});

	test("rejects an implausibly long string", () => {
		expect(isPlausiblePath(`/${"a".repeat(5000)}`)).toBe(false);
	});
});

describe("parseOwningPackage", () => {
	test("parses a plain 'package: /path' line", () => {
		expect(parseOwningPackage("coreutils: /bin/ls")).toBe("coreutils");
	});

	test("strips a multiarch ':amd64' suffix", () => {
		expect(parseOwningPackage("coreutils:amd64: /bin/ls")).toBe("coreutils");
	});

	test("takes only the first line when multiple packages own overlapping paths", () => {
		const output = "pkg-a: /usr/bin/x\npkg-b: /usr/bin/x";
		expect(parseOwningPackage(output)).toBe("pkg-a");
	});

	test("returns null for output that doesn't look like '<pkg>: /path'", () => {
		expect(parseOwningPackage("no installed package")).toBeNull();
	});

	test("returns null for empty output", () => {
		expect(parseOwningPackage("")).toBeNull();
	});
});

describe("wasPackageRecentlyUpgraded", () => {
	let dir: string;
	let logPath: string;

	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), "hids-apt-history-test-"));
		logPath = join(dir, "history.log");
	});

	afterEach(() => {
		rmSync(dir, { recursive: true, force: true });
	});

	function isoNow(daysAgo: number): string {
		const d = new Date(Date.now() - daysAgo * 24 * 60 * 60 * 1000);
		return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(
			d.getDate(),
		).padStart(2, "0")}  ${String(d.getHours()).padStart(2, "0")}:${String(
			d.getMinutes(),
		).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}`;
	}

	test("true when the package appears in an Upgrade: line within the grace window", () => {
		writeFileSync(
			logPath,
			[
				`Start-Date: ${isoNow(2)}`,
				"Commandline: apt-get upgrade",
				"Upgrade: coreutils:amd64 (8.30-3, 8.30-3ubuntu2), libc6:amd64 (2.31-0, 2.31-1)",
				`End-Date: ${isoNow(2)}`,
				"",
			].join("\n"),
		);
		expect(wasPackageRecentlyUpgraded("coreutils", 10, logPath)).toBe(true);
	});

	test("true when the package appears in an Install: line within the grace window", () => {
		writeFileSync(
			logPath,
			[
				`Start-Date: ${isoNow(1)}`,
				"Commandline: apt-get install journalctl",
				"Install: journalctl:amd64 (247.3-6)",
				`End-Date: ${isoNow(1)}`,
				"",
			].join("\n"),
		);
		expect(wasPackageRecentlyUpgraded("journalctl", 10, logPath)).toBe(true);
	});

	test("false when the entry is older than the grace window", () => {
		writeFileSync(
			logPath,
			[
				`Start-Date: ${isoNow(30)}`,
				"Commandline: apt-get upgrade",
				"Upgrade: coreutils:amd64 (8.30-3, 8.30-3ubuntu2)",
				`End-Date: ${isoNow(30)}`,
				"",
			].join("\n"),
		);
		expect(wasPackageRecentlyUpgraded("coreutils", 10, logPath)).toBe(false);
	});

	test("false when the package is never mentioned", () => {
		writeFileSync(
			logPath,
			[
				`Start-Date: ${isoNow(1)}`,
				"Commandline: apt-get upgrade",
				"Upgrade: some-other-package:amd64 (1.0, 1.1)",
				`End-Date: ${isoNow(1)}`,
				"",
			].join("\n"),
		);
		expect(wasPackageRecentlyUpgraded("coreutils", 10, logPath)).toBe(false);
	});

	test("throws when the log file doesn't exist (fail-safe: caller must not treat as false)", () => {
		expect(() =>
			wasPackageRecentlyUpgraded("coreutils", 10, join(dir, "missing.log")),
		).toThrow();
	});
});
