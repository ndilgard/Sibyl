import { describe, expect, test } from "bun:test";
import { classify, parseLines } from "./auth.ts";

describe("classify", () => {
	test("flags a failed SSH password login as critical", () => {
		const result = classify({
			SYSLOG_IDENTIFIER: "sshd",
			MESSAGE: "Failed password for root from 203.0.113.5 port 51000 ssh2",
		});
		expect(result?.severity).toBe("critical");
		expect(result?.summary).toContain("Failed SSH login attempt");
	});

	test("flags an invalid-user SSH attempt as critical", () => {
		const result = classify({
			SYSLOG_IDENTIFIER: "sshd",
			MESSAGE: "Invalid user admin from 203.0.113.5 port 51001 ssh2",
		});
		expect(result?.severity).toBe("critical");
	});

	test("flags an accepted SSH password login as warning", () => {
		const result = classify({
			SYSLOG_IDENTIFIER: "sshd",
			MESSAGE: "Accepted password for nate from 192.168.1.10 port 51002 ssh2",
		});
		expect(result?.severity).toBe("warning");
		expect(result?.summary).toContain("SSH login accepted");
	});

	test("flags an accepted SSH publickey login as warning", () => {
		const result = classify({
			SYSLOG_IDENTIFIER: "sshd",
			MESSAGE: "Accepted publickey for nate from 192.168.1.10 port 51003 ssh2",
		});
		expect(result?.severity).toBe("warning");
	});

	test("flags a failed sudo authentication as critical", () => {
		const result = classify({
			SYSLOG_IDENTIFIER: "sudo",
			MESSAGE: "pam_unix(sudo:auth): authentication failure; user=nate",
		});
		expect(result?.severity).toBe("critical");
		expect(result?.summary).toContain("Failed sudo authentication");
	});

	test("flags a sudo incorrect-password-attempt message as critical", () => {
		const result = classify({
			SYSLOG_IDENTIFIER: "sudo",
			MESSAGE: "3 incorrect password attempts",
		});
		expect(result?.severity).toBe("critical");
	});

	test("returns null for an sshd message that doesn't match a known pattern", () => {
		expect(
			classify({
				SYSLOG_IDENTIFIER: "sshd",
				MESSAGE: "Server listening on 0.0.0.0 port 22",
			}),
		).toBeNull();
	});

	test("returns null for a sudo message that isn't a failure", () => {
		expect(
			classify({
				SYSLOG_IDENTIFIER: "sudo",
				MESSAGE: "nate : TTY=pts/0 ; PWD=/home/nate ; COMMAND=/usr/bin/ls",
			}),
		).toBeNull();
	});

	test("returns null for an unrelated syslog identifier", () => {
		expect(
			classify({
				SYSLOG_IDENTIFIER: "systemd",
				MESSAGE: "Failed password for nobody",
			}),
		).toBeNull();
	});

	test("returns null for an entry with no fields at all", () => {
		expect(classify({})).toBeNull();
	});
});

describe("parseLines", () => {
	test("parses one JSON object per line", () => {
		const chunk = [
			JSON.stringify({ SYSLOG_IDENTIFIER: "sshd", MESSAGE: "a" }),
			JSON.stringify({ SYSLOG_IDENTIFIER: "sudo", MESSAGE: "b" }),
		].join("\n");
		expect(parseLines(chunk)).toEqual([
			{ SYSLOG_IDENTIFIER: "sshd", MESSAGE: "a" },
			{ SYSLOG_IDENTIFIER: "sudo", MESSAGE: "b" },
		]);
	});

	test("skips blank lines", () => {
		const chunk = `${JSON.stringify({ MESSAGE: "a" })}\n\n   \n${JSON.stringify({ MESSAGE: "b" })}`;
		expect(parseLines(chunk)).toHaveLength(2);
	});

	test("silently drops a malformed/partial trailing line instead of throwing", () => {
		const chunk = `${JSON.stringify({ MESSAGE: "a" })}\n{"MESSAGE": "truncated by stream buffe`;
		expect(() => parseLines(chunk)).not.toThrow();
		expect(parseLines(chunk)).toEqual([{ MESSAGE: "a" }]);
	});

	test("returns an empty array for empty input", () => {
		expect(parseLines("")).toEqual([]);
	});
});
