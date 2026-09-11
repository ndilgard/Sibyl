import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AlertRecorder } from "../alert/policy.ts";
import type { HidsConfig } from "../config.ts";
import { getAlerts, openHistoryDb } from "../state/history-db.ts";
import { createFimModule } from "./fim.ts";
import type { ModuleContext } from "./types.ts";

let dataDir: string;
let watchDir: string;
let ctx: ModuleContext;

function config(overrides: Partial<HidsConfig["fim"]> = {}): HidsConfig {
	return {
		dataDir,
		gmailEnvPath: "unused",
		web: { host: "0.0.0.0", port: 0 },
		fim: {
			watchPaths: [watchDir],
			reconcileIntervalMs: 900000,
			debounceMs: 2000,
			watchTrustedProcessBinaries: false,
			...overrides,
		},
		process: {
			pollIntervalMs: 10000,
			suspiciousDirs: [],
			packageUpgradeGraceDays: 10,
		},
		auth: { reconnectBackoffMs: 5000 },
		network: {
			pollIntervalMs: 30000,
			alertOnNewListener: true,
			alertOnOutbound: true,
			alertOnUdp: false,
		},
		alert: { debounceMs: 60000, emailOnNewBinary: false },
		heartbeat: { enabled: false, url: "", intervalMs: 120000 },
		agent: {
			enabled: false,
			model: "claude-sonnet-5",
			intervalMs: 300000,
			apiKeyEnvPath: "unused",
		},
		signatureDb: {
			enabled: false,
			feed: "recent",
			refreshIntervalMs: 21600000,
			authKeyEnvPath: "unused",
		},
	};
}

beforeEach(() => {
	dataDir = mkdtempSync(join(tmpdir(), "hids-test-data-"));
	watchDir = mkdtempSync(join(tmpdir(), "hids-test-watch-"));
	const db = openHistoryDb(dataDir);
	// Real AlertRecorder with a null mailer — same pattern cli.ts's buildContext() uses for
	// local-only scans: record() still writes to the alert store synchronously, it just never
	// sends email. Short debounceMs so no meaningfully-delayed flush lingers past the test.
	const recorder = new AlertRecorder(db, null, 5, 0);
	ctx = { config: config(), db, recorder };
});

afterEach(() => {
	rmSync(dataDir, { recursive: true, force: true });
	rmSync(watchDir, { recursive: true, force: true });
});

describe("fim scanNow", () => {
	test("first run builds a baseline and records no alerts", async () => {
		writeFileSync(join(watchDir, "unchanged.txt"), "same forever");
		const fim = createFimModule(ctx);
		await fim.scanNow();
		expect(getAlerts(ctx.db, { module: "fim" })).toEqual([]);
	});

	test("a new file appearing after baseline is a warning-level alert", async () => {
		const fim = createFimModule(ctx);
		await fim.scanNow(); // baseline: empty watch dir
		writeFileSync(join(watchDir, "new.txt"), "hello");
		await fim.scanNow();
		const alerts = getAlerts(ctx.db, { module: "fim" });
		expect(alerts).toHaveLength(1);
		expect(alerts[0]!.severity).toBe("warning");
		expect(alerts[0]!.summary).toContain("New file appeared");
	});

	test("modifying a known file's contents is a critical tampering alert", async () => {
		const path = join(watchDir, "tracked.txt");
		writeFileSync(path, "original");
		const fim = createFimModule(ctx);
		await fim.scanNow(); // baseline includes tracked.txt
		writeFileSync(path, "modified content");
		await fim.scanNow();
		const alerts = getAlerts(ctx.db, { module: "fim" });
		expect(alerts).toHaveLength(1);
		expect(alerts[0]!.severity).toBe("critical");
		expect(alerts[0]!.summary).toContain("Watched file modified");
	});

	test("deleting a known file is a critical alert", async () => {
		const path = join(watchDir, "tracked.txt");
		writeFileSync(path, "original");
		const fim = createFimModule(ctx);
		await fim.scanNow(); // baseline includes tracked.txt
		rmSync(path);
		await fim.scanNow();
		const alerts = getAlerts(ctx.db, { module: "fim" });
		expect(alerts).toHaveLength(1);
		expect(alerts[0]!.severity).toBe("critical");
		expect(alerts[0]!.summary).toContain("Watched file deleted");
	});

	test("deleting a trusted-process binary is a warning, not critical", async () => {
		const path = join(watchDir, "trusted-app");
		writeFileSync(path, "binary contents");
		ctx.config = config({ watchTrustedProcessBinaries: true });
		writeFileSync(
			join(dataDir, "outbound-first-seen.json"),
			JSON.stringify({ [path]: { firstSeenAt: "2026-01-01T00:00:00.000Z" } }),
		);
		const fim = createFimModule(ctx);
		await fim.scanNow(); // baseline includes tracked.txt + trusted-app
		rmSync(path);
		await fim.scanNow();
		const alerts = getAlerts(ctx.db, { module: "fim" });
		expect(alerts).toHaveLength(1);
		expect(alerts[0]!.severity).toBe("warning");
		expect(alerts[0]!.summary).toContain("Trusted process binary removed");
	});

	test("an unchanged file never alerts across repeated scans", async () => {
		writeFileSync(join(watchDir, "stable.txt"), "same forever");
		const fim = createFimModule(ctx);
		await fim.scanNow();
		await fim.scanNow();
		await fim.scanNow();
		expect(getAlerts(ctx.db, { module: "fim" })).toEqual([]);
	});
});
