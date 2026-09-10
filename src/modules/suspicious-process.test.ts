import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
	copyFileSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	unlinkSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	buildSuspiciousFinding,
	checkSuspiciousExePath,
	hashSuspiciousBinary,
} from "./suspicious-process.ts";

const suspiciousDirs = ["/tmp", "/dev/shm", "/var/tmp"];

describe("checkSuspiciousExePath", () => {
	test("flags a deleted binary and strips the ' (deleted)' suffix", () => {
		const result = checkSuspiciousExePath(
			"/usr/bin/curl (deleted)",
			suspiciousDirs,
		);
		expect(result).toEqual({
			suspicious: true,
			reason: "deleted",
			resolvedExePath: "/usr/bin/curl",
		});
	});

	test("flags a binary running from a suspicious directory", () => {
		const result = checkSuspiciousExePath("/tmp/payload", suspiciousDirs);
		expect(result.suspicious).toBe(true);
		expect(result.reason).toBe("suspicious-path");
		expect(result.resolvedExePath).toBe("/tmp/payload");
	});

	test("flags a binary under any configured suspicious dir, not just the first", () => {
		expect(
			checkSuspiciousExePath("/dev/shm/x", suspiciousDirs).suspicious,
		).toBe(true);
		expect(
			checkSuspiciousExePath("/var/tmp/x", suspiciousDirs).suspicious,
		).toBe(true);
	});

	test("does not flag a normal binary in a trusted path", () => {
		const result = checkSuspiciousExePath("/usr/bin/bash", suspiciousDirs);
		expect(result).toEqual({
			suspicious: false,
			reason: null,
			resolvedExePath: "/usr/bin/bash",
		});
	});

	test("a deleted binary that also lives in a suspicious dir is reported as 'deleted', not 'suspicious-path'", () => {
		const result = checkSuspiciousExePath(
			"/tmp/payload (deleted)",
			suspiciousDirs,
		);
		expect(result.reason).toBe("deleted");
	});

	test("respects an empty suspiciousDirs list (nothing path-based flags)", () => {
		const result = checkSuspiciousExePath("/tmp/payload", []);
		expect(result.suspicious).toBe(false);
	});
});

describe("hashSuspiciousBinary", () => {
	let dir: string;

	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), "hids-hash-suspicious-test-"));
	});

	afterEach(() => {
		rmSync(dir, { recursive: true, force: true });
	});

	test("hashes a still-present file at resolvedExePath (suspicious-path)", () => {
		const path = join(dir, "payload");
		writeFileSync(path, "fake malware bytes");
		const expected = createHash("sha256")
			.update("fake malware bytes")
			.digest("hex");

		const hash = hashSuspiciousBinary(12345, {
			suspicious: true,
			reason: "suspicious-path",
			resolvedExePath: path,
		});
		expect(hash).toBe(expected);
	});

	test("hashes a 'deleted' binary via /proc/<pid>/exe while the process is still alive", () => {
		const sleepBin = Bun.which("sleep");
		if (!sleepBin) {
			// Environment without `sleep` on PATH — skip rather than fail the suite.
			return;
		}
		const copyPath = join(dir, "sleep-copy");
		copyFileSync(sleepBin, copyPath);
		const expected = createHash("sha256")
			.update(readFileSync(copyPath))
			.digest("hex");

		const child = Bun.spawn([copyPath, "5"]);
		// Unlink while still running — /proc/<pid>/exe keeps resolving to the deleted inode.
		unlinkSync(copyPath);

		try {
			const hash = hashSuspiciousBinary(child.pid, {
				suspicious: true,
				reason: "deleted",
				resolvedExePath: copyPath,
			});
			expect(hash).toBe(expected);
		} finally {
			child.kill();
		}
	});

	test("returns null (never throws) once the file/process is truly gone", () => {
		expect(
			hashSuspiciousBinary(999999, {
				suspicious: true,
				reason: "deleted",
				resolvedExePath: "/tmp/nonexistent-binary-xyz",
			}),
		).toBeNull();

		expect(
			hashSuspiciousBinary(1, {
				suspicious: true,
				reason: "suspicious-path",
				resolvedExePath: "/tmp/also-nonexistent-xyz",
			}),
		).toBeNull();
	});

	test("returns null when resolvedExePath is null", () => {
		expect(
			hashSuspiciousBinary(1, {
				suspicious: true,
				reason: "suspicious-path",
				resolvedExePath: null,
			}),
		).toBeNull();
	});
});

describe("buildSuspiciousFinding", () => {
	test("no match: summary/detail pass through with sha256 and null match attached", () => {
		const result = buildSuspiciousFinding({
			summaryBase: "Process launched from suspicious path: /tmp/x (pid 1)",
			detail: { pid: "1", exePath: "/tmp/x" },
			sha256: "abc123",
			match: null,
		});
		expect(result.summary).toBe(
			"Process launched from suspicious path: /tmp/x (pid 1)",
		);
		expect(result.detail).toEqual({
			pid: "1",
			exePath: "/tmp/x",
			sha256: "abc123",
			malwareBazaarMatch: null,
		});
	});

	test("match: summary is prefixed with the signature name, detail carries the match", () => {
		const result = buildSuspiciousFinding({
			summaryBase: "Process launched from suspicious path: /tmp/x (pid 1)",
			detail: { pid: "1", exePath: "/tmp/x" },
			sha256: "abc123",
			match: { sha256: "abc123", signature: "Trojan.GenericKD" },
		});
		expect(result.summary).toBe(
			"MATCHES KNOWN MALWARE (Trojan.GenericKD): Process launched from suspicious path: /tmp/x (pid 1)",
		);
		expect(
			(result.detail as { malwareBazaarMatch: unknown }).malwareBazaarMatch,
		).toEqual({
			sha256: "abc123",
			signature: "Trojan.GenericKD",
		});
	});

	test("match with no signature name falls back to the hash in the summary prefix", () => {
		const result = buildSuspiciousFinding({
			summaryBase: "base",
			detail: {},
			sha256: "abc123",
			match: { sha256: "abc123" },
		});
		expect(result.summary).toBe("MATCHES KNOWN MALWARE (abc123): base");
	});
});
