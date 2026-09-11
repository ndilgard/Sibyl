import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { copyFileSync, mkdtempSync, rmSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AlertRecorder } from "../alert/policy.ts";
import type { HidsConfig } from "../config.ts";
import { getAlerts, openHistoryDb } from "../state/history-db.ts";
import type { PackageLookup } from "../state/package-ownership.ts";
import { createProcessModule } from "./process.ts";
import type { ModuleContext } from "./types.ts";

let dataDir: string;
let binDir: string;
let ctx: ModuleContext;

function config(overrides: Partial<HidsConfig["process"]> = {}): HidsConfig {
	return {
		dataDir,
		gmailEnvPath: "unused",
		web: { host: "0.0.0.0", port: 0 },
		fim: {
			watchPaths: [],
			reconcileIntervalMs: 900000,
			debounceMs: 2000,
			watchTrustedProcessBinaries: false,
		},
		process: {
			pollIntervalMs: 10000,
			suspiciousDirs: [],
			packageUpgradeGraceDays: 10,
			...overrides,
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

/** A fake so tests never shell out to real dpkg or read the real /var/log/apt/history.log — only
 * the injected functions decide the outcome. */
function fakePackageLookup(
	overrides: Partial<PackageLookup> = {},
): PackageLookup {
	return {
		ownerOf: () => null,
		wasRecentlyUpgraded: () => false,
		...overrides,
	};
}

beforeEach(() => {
	dataDir = mkdtempSync(join(tmpdir(), "hids-test-data-"));
	binDir = mkdtempSync(join(tmpdir(), "hids-test-bin-"));
	const db = openHistoryDb(dataDir);
	const recorder = new AlertRecorder(db, null, 5, 0);
	ctx = { config: config(), db, recorder, packageLookup: fakePackageLookup() };
});

afterEach(() => {
	rmSync(dataDir, { recursive: true, force: true });
	rmSync(binDir, { recursive: true, force: true });
});

type Subprocess = ReturnType<typeof Bun.spawn>;

/**
 * Spawns a copy of a real system binary, then unlinks it while the process is still running —
 * `/proc/<pid>/exe` keeps resolving to the deleted inode, which is exactly the "process running
 * from a deleted binary" condition process.ts's `deleted` branch reacts to. Matches the technique
 * suspicious-process.test.ts already uses for the same reason: this can't be faked without a real
 * running process backed by a real (now-unlinked) file on disk.
 */
function spawnWithDeletedBinary(): { child: Subprocess; copyPath: string } {
	const sleepBin = Bun.which("sleep");
	if (!sleepBin) {
		throw new Error("`sleep` not found on PATH — required for this test");
	}
	const copyPath = join(binDir, "sleep-copy");
	copyFileSync(sleepBin, copyPath);
	const child = Bun.spawn([copyPath, "5"]);
	unlinkSync(copyPath);
	return { child, copyPath };
}

/**
 * `readProcs()` scans the real, shared `/proc` — on some hosts (this sandbox included) that
 * already contains unrelated processes with their own deleted-binary condition (e.g. a
 * memfd-backed process, which always resolves as "(deleted)" since it never had a path). Filter
 * down to the alert for our own spawned test process rather than assuming it's the only one.
 */
function alertForPath(alerts: ReturnType<typeof getAlerts>, copyPath: string) {
	const alert = alerts.find((a) => a.summary.includes(copyPath));
	if (!alert) {
		throw new Error(
			`No alert found mentioning ${copyPath} among: ${JSON.stringify(alerts.map((a) => a.summary))}`,
		);
	}
	return alert;
}

describe("process scanNow: deleted-binary package-upgrade pre-filter", () => {
	test("package-owned + recently upgraded -> downgraded to warning, not critical", async () => {
		const { child, copyPath } = spawnWithDeletedBinary();
		ctx.packageLookup = fakePackageLookup({
			ownerOf: (path) => (path === copyPath ? "coreutils" : null),
			wasRecentlyUpgraded: (pkg, days) => pkg === "coreutils" && days === 10,
		});
		try {
			const proc = createProcessModule(ctx);
			await proc.scanNow();
			const alert = alertForPath(
				getAlerts(ctx.db, { module: "process" }),
				copyPath,
			);
			expect(alert.severity).toBe("warning");
			expect(alert.summary).toContain(
				"likely explained by a recent apt upgrade of coreutils",
			);
		} finally {
			child.kill();
		}
	});

	test("package-owned but NOT recently upgraded -> stays critical", async () => {
		const { child, copyPath } = spawnWithDeletedBinary();
		ctx.packageLookup = fakePackageLookup({
			ownerOf: (path) => (path === copyPath ? "coreutils" : null),
			wasRecentlyUpgraded: () => false,
		});
		try {
			const proc = createProcessModule(ctx);
			await proc.scanNow();
			const alert = alertForPath(
				getAlerts(ctx.db, { module: "process" }),
				copyPath,
			);
			expect(alert.severity).toBe("critical");
			expect(alert.summary).not.toContain("likely explained by");
		} finally {
			child.kill();
		}
	});

	test("path not dpkg-owned -> stays critical", async () => {
		const { child, copyPath } = spawnWithDeletedBinary();
		ctx.packageLookup = fakePackageLookup({
			ownerOf: () => null,
			wasRecentlyUpgraded: () => {
				throw new Error("must not be called when ownerOf finds no package");
			},
		});
		try {
			const proc = createProcessModule(ctx);
			await proc.scanNow();
			const alert = alertForPath(
				getAlerts(ctx.db, { module: "process" }),
				copyPath,
			);
			expect(alert.severity).toBe("critical");
		} finally {
			child.kill();
		}
	});

	test("dpkg lookup throws -> fails safe, stays critical", async () => {
		const { child, copyPath } = spawnWithDeletedBinary();
		ctx.packageLookup = fakePackageLookup({
			ownerOf: () => {
				throw new Error("dpkg: command not found");
			},
		});
		try {
			const proc = createProcessModule(ctx);
			await proc.scanNow();
			const alert = alertForPath(
				getAlerts(ctx.db, { module: "process" }),
				copyPath,
			);
			expect(alert.severity).toBe("critical");
		} finally {
			child.kill();
		}
	});

	test("apt history log missing/unreadable -> fails safe, stays critical", async () => {
		const { child, copyPath } = spawnWithDeletedBinary();
		ctx.packageLookup = fakePackageLookup({
			ownerOf: (path) => (path === copyPath ? "coreutils" : null),
			wasRecentlyUpgraded: () => {
				throw new Error("ENOENT: /var/log/apt/history.log");
			},
		});
		try {
			const proc = createProcessModule(ctx);
			await proc.scanNow();
			const alert = alertForPath(
				getAlerts(ctx.db, { module: "process" }),
				copyPath,
			);
			expect(alert.severity).toBe("critical");
		} finally {
			child.kill();
		}
	});
});
