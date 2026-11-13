import { describe, expect, test } from "bun:test";
import { correlateAlerts } from "./correlate.ts";
import type { Alert } from "./history-db.ts";

function alert(id: string, module: string, ts: string, detail: unknown): Alert {
	return {
		id,
		ts,
		module,
		severity: "warning",
		summary: "test",
		detail,
		emailed: false,
	};
}

const WINDOW_MS = 5 * 60 * 1000;

describe("correlateAlerts", () => {
	test("links a FIM change to a network connection from the same process (shared exePath)", () => {
		const alerts = [
			alert("a1", "fim", "2026-11-09T12:00:00.000Z", {
				path: "/usr/bin/evil-cron",
			}),
			alert("a2", "network", "2026-11-09T12:00:05.000Z", {
				exePath: "/usr/bin/evil-cron",
				remoteAddress: "203.0.113.5",
			}),
		];

		const incidents = correlateAlerts(alerts, WINDOW_MS);

		expect(incidents).toHaveLength(1);
		expect(incidents[0].alertIds.sort()).toEqual(["a1", "a2"]);
		expect(incidents[0].modules.sort()).toEqual(["fim", "network"]);
		expect(incidents[0].sharedIdentifier).toBe("exePath:/usr/bin/evil-cron");
	});

	test("no identifier overlap -> no incident", () => {
		const alerts = [
			alert("a1", "fim", "2026-11-09T12:00:00.000Z", {
				path: "/usr/bin/evil-cron",
			}),
			alert("a2", "network", "2026-11-09T12:00:05.000Z", {
				exePath: "/opt/other/unrelated",
				remoteAddress: "203.0.113.5",
			}),
		];

		expect(correlateAlerts(alerts, WINDOW_MS)).toEqual([]);
	});

	test("same-module alerts sharing an identifier do not correlate", () => {
		const alerts = [
			alert("a1", "process", "2026-11-09T12:00:00.000Z", {
				pid: "100",
				exePath: "/usr/bin/evil",
			}),
			alert("a2", "process", "2026-11-09T12:00:05.000Z", {
				pid: "100",
				exePath: "/usr/bin/evil",
			}),
		];

		expect(correlateAlerts(alerts, WINDOW_MS)).toEqual([]);
	});

	test("two alerts exactly at the window boundary still correlate (inclusive)", () => {
		const alerts = [
			alert("a1", "fim", "2026-11-09T12:00:00.000Z", {
				path: "/usr/bin/evil-cron",
			}),
			alert("a2", "network", "2026-11-09T12:05:00.000Z", {
				exePath: "/usr/bin/evil-cron",
				remoteAddress: "203.0.113.5",
			}),
		];

		const incidents = correlateAlerts(alerts, WINDOW_MS);

		expect(incidents).toHaveLength(1);
		expect(incidents[0].alertIds.sort()).toEqual(["a1", "a2"]);
	});

	test("alerts just past the window boundary do not correlate", () => {
		const alerts = [
			alert("a1", "fim", "2026-11-09T12:00:00.000Z", {
				path: "/usr/bin/evil-cron",
			}),
			alert("a2", "network", "2026-11-09T12:05:00.001Z", {
				exePath: "/usr/bin/evil-cron",
				remoteAddress: "203.0.113.5",
			}),
		];

		expect(correlateAlerts(alerts, WINDOW_MS)).toEqual([]);
	});

	test("a lone unmatched alert produces no incident", () => {
		const alerts = [
			alert("a1", "auth", "2026-11-09T12:00:00.000Z", {
				MESSAGE: "3 incorrect password attempts",
				SYSLOG_IDENTIFIER: "sudo",
			}),
		];

		expect(correlateAlerts(alerts, WINDOW_MS)).toEqual([]);
	});

	test("three alerts chain together via different shared identifiers into one incident", () => {
		const alerts = [
			alert("a1", "fim", "2026-11-09T12:00:00.000Z", {
				path: "/usr/bin/evil-cron",
			}),
			alert("a2", "process", "2026-11-09T12:00:05.000Z", {
				pid: "500",
				exePath: "/usr/bin/evil-cron",
			}),
			alert("a3", "network", "2026-11-09T12:00:10.000Z", {
				exePath: "/usr/bin/other-tool",
				remoteAddress: "198.51.100.9",
			}),
		];

		const incidents = correlateAlerts(alerts, WINDOW_MS);

		expect(incidents).toHaveLength(1);
		expect(incidents[0].alertIds.sort()).toEqual(["a1", "a2", "a3"]);
		expect(incidents[0].modules.sort()).toEqual(["fim", "network", "process"]);
	});

	test("empty input returns no incidents", () => {
		expect(correlateAlerts([], WINDOW_MS)).toEqual([]);
	});
});
