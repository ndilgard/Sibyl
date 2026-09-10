import { existsSync, mkdirSync } from "node:fs";
import { createTriageModule } from "./agent/triage.ts";
import { createMailer } from "./alert/email.ts";
import { AlertRecorder, safeCreateMailer } from "./alert/policy.ts";
import { loadConfig } from "./config.ts";
import { createAuthModule } from "./modules/auth.ts";
import { createFimModule } from "./modules/fim.ts";
import { createHeartbeatModule } from "./modules/heartbeat.ts";
import { createNetworkModule } from "./modules/network.ts";
import { createProcessModule } from "./modules/process.ts";
import { createSignatureDbModule } from "./modules/signature-db.ts";
import type { Module } from "./modules/types.ts";
import { openHistoryDb } from "./state/history-db.ts";
import { createSignatureDbStore } from "./state/signature-db-store.ts";

async function waitForDataDir(
	dataDir: string,
	maxWaitMs = 60000,
): Promise<boolean> {
	const start = Date.now();
	while (Date.now() - start < maxWaitMs) {
		if (existsSync(dataDir)) return true;
		await new Promise((r) => setTimeout(r, 2000));
	}
	return false;
}

async function main() {
	const config = loadConfig();
	const primaryDataDir = config.dataDir;

	const dataDirReady = await waitForDataDir(config.dataDir);
	const degraded = !dataDirReady;
	if (degraded) {
		console.warn(
			`[startup] WARNING: ${config.dataDir} not available after 60s — starting in degraded mode. ` +
				`Baselines/alerts won't persist until it appears, but detection and email alerts still work.`,
		);
		// Fall back to a local dir so the daemon can still run (baselines just won't be on the NAS
		// until it's back — this is intentionally not a crash).
		mkdirSync("/tmp/hids-fallback", { recursive: true });
		config.dataDir = "/tmp/hids-fallback";
	}

	const db = openHistoryDb(config.dataDir);
	const mailer = safeCreateMailer(createMailer, config.gmailEnvPath);
	const recorder = new AlertRecorder(
		db,
		mailer,
		config.alert.debounceMs,
		config.web.port,
	);

	const signatureDb = createSignatureDbStore(config.dataDir);
	const ctx = { config, db, recorder, signatureDb };
	const modules: Record<string, Module> = {
		fim: createFimModule(ctx),
		process: createProcessModule(ctx),
		auth: createAuthModule(ctx),
		network: createNetworkModule(ctx),
		heartbeat: createHeartbeatModule(ctx),
		agent: createTriageModule(ctx),
		signatureDb: createSignatureDbModule(ctx),
	};

	for (const [name, mod] of Object.entries(modules)) {
		console.log(`[daemon] starting ${name} module`);
		mod.start();
	}

	const shutdown = (exitCode: number) => {
		console.log("[daemon] shutting down");
		for (const mod of Object.values(modules)) mod.stop();
		process.exit(exitCode);
	};
	process.on("SIGTERM", () => shutdown(0));
	process.on("SIGINT", () => shutdown(0));

	if (degraded) {
		// The 60s startup check has no visibility into transient blips (e.g. a CIFS mount
		// dropping during suspend/resume) vs. a genuinely missing NAS. Once degraded, this
		// process would otherwise stay pinned to /tmp/hids-fallback forever, silently going
		// dark to the dashboard even after the mount comes back. Re-check periodically and
		// exit non-zero so systemd's Restart=on-failure reattaches to the real dataDir.
		const recheckMs = 5 * 60 * 1000;
		const recheckTimer = setInterval(() => {
			if (existsSync(primaryDataDir)) {
				console.warn(
					`[startup] ${primaryDataDir} is back — restarting to reattach (was degraded, writing to /tmp/hids-fallback).`,
				);
				clearInterval(recheckTimer);
				shutdown(1);
			}
		}, recheckMs);
	}

	console.log("[daemon] HIDS running");
}

void main();
