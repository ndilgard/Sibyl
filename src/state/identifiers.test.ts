import { describe, expect, test } from "bun:test";
import type { Alert } from "./history-db.ts";
import { extractIdentifiers } from "./identifiers.ts";

function alert(module: string, detail: unknown): Alert {
	return {
		id: "test-id",
		ts: new Date().toISOString(),
		module,
		severity: "warning",
		summary: "test",
		detail,
		emailed: false,
	};
}

describe("extractIdentifiers / fim", () => {
	test("returns exePath (file path) and its parent dir", () => {
		const ids = extractIdentifiers(alert("fim", { path: "/etc/cron.d/evil" }));
		expect(ids).toEqual([
			{ kind: "exePath", value: "/etc/cron.d/evil" },
			{ kind: "dir", value: "/etc/cron.d" },
		]);
	});

	test("missing path returns empty", () => {
		expect(extractIdentifiers(alert("fim", {}))).toEqual([]);
	});
});

describe("extractIdentifiers / process", () => {
	test("returns pid, exePath, and exePath's dir", () => {
		const ids = extractIdentifiers(
			alert("process", {
				pid: "1234",
				exePath: "/tmp/.hidden/x",
				cmdline: "x",
			}),
		);
		expect(ids).toEqual([
			{ kind: "pid", value: "1234" },
			{ kind: "exePath", value: "/tmp/.hidden/x" },
			{ kind: "dir", value: "/tmp/.hidden" },
		]);
	});

	test("null exePath (deleted binary case) still yields pid", () => {
		const ids = extractIdentifiers(
			alert("process", { pid: "99", exePath: null, deleted: true }),
		);
		expect(ids).toEqual([{ kind: "pid", value: "99" }]);
	});

	test("missing detail fields returns empty", () => {
		expect(extractIdentifiers(alert("process", null))).toEqual([]);
	});
});

describe("extractIdentifiers / network", () => {
	test("returns exePath, dir, and remoteAddress", () => {
		const ids = extractIdentifiers(
			alert("network", {
				exePath: "/usr/bin/nc",
				remoteAddress: "203.0.113.5",
			}),
		);
		expect(ids).toEqual([
			{ kind: "exePath", value: "/usr/bin/nc" },
			{ kind: "dir", value: "/usr/bin" },
			{ kind: "ip", value: "203.0.113.5" },
		]);
	});

	test("falls back to localAddress when remoteAddress is absent (listener)", () => {
		const ids = extractIdentifiers(
			alert("network", { exePath: "/usr/bin/sshd", localAddress: "0.0.0.0" }),
		);
		expect(ids.some((i) => i.kind === "ip" && i.value === "0.0.0.0")).toBe(
			true,
		);
	});

	test("no exePath or address returns empty", () => {
		expect(extractIdentifiers(alert("network", {}))).toEqual([]);
	});
});

describe("extractIdentifiers / auth", () => {
	test("extracts source IP from an invalid-user Failed password message", () => {
		const ids = extractIdentifiers(
			alert("auth", {
				MESSAGE:
					"Failed password for invalid user admin from 198.51.100.7 port 51515 ssh2",
				SYSLOG_IDENTIFIER: "sshd",
			}),
		);
		expect(ids).toEqual([{ kind: "ip", value: "198.51.100.7" }]);
	});

	test("extracts source IP from an Accepted password message", () => {
		const ids = extractIdentifiers(
			alert("auth", {
				MESSAGE: "Accepted password for nate from 192.168.1.50 port 22 ssh2",
				SYSLOG_IDENTIFIER: "sshd",
			}),
		);
		expect(ids).toEqual([{ kind: "ip", value: "192.168.1.50" }]);
	});

	test("sudo failures have no IP in the message, so no identifier", () => {
		const ids = extractIdentifiers(
			alert("auth", {
				MESSAGE: "3 incorrect password attempts",
				SYSLOG_IDENTIFIER: "sudo",
			}),
		);
		expect(ids).toEqual([]);
	});

	test("missing MESSAGE field returns empty", () => {
		expect(
			extractIdentifiers(alert("auth", { SYSLOG_IDENTIFIER: "sshd" })),
		).toEqual([]);
	});
});

describe("extractIdentifiers / unknown module", () => {
	test("returns empty for an unrecognized module name", () => {
		expect(extractIdentifiers(alert("heartbeat", { anything: true }))).toEqual(
			[],
		);
	});
});
