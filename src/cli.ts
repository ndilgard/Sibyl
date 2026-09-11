#!/usr/bin/env bun
import { existsSync, unlinkSync } from "node:fs";
import { createMailer } from "./alert/email.ts";
import { AlertRecorder, safeCreateMailer } from "./alert/policy.ts";
import { loadConfig } from "./config.ts";
import { createAuthModule } from "./modules/auth.ts";
import { createFimModule } from "./modules/fim.ts";
import { createNetworkModule } from "./modules/network.ts";
import { createProcessModule } from "./modules/process.ts";
import { createSignatureDbModule } from "./modules/signature-db.ts";
import type { Module } from "./modules/types.ts";
import { getAlerts, getScanStatus, openHistoryDb } from "./state/history-db.ts";
import { createPackageLookup } from "./state/package-ownership.ts";
import { createSignatureDbStore } from "./state/signature-db-store.ts";

const BASELINE_FILES: Record<string, string | null> = {
	fim: "baseline-fim.json",
	process: "baseline-processes.json",
	network: "baseline-network.json",
	auth: null, // event-driven, no baseline file
	signatureDb: "signature-db-cache.json",
};

/**
 * Deliberately no real mailer here: `scan-now`/`init` are for manual, local inspection — only the
 * persistent daemon should ever dispatch real alert emails. Findings still get recorded to
 * alerts.jsonl (visible via `hids alerts`) so a manual scan is still useful, they just don't
 * trigger a live page. `test-email` builds its own mailer separately since sending is the whole
 * point of that command.
 */
function buildContext() {
	const config = loadConfig();
	const db = openHistoryDb(config.dataDir);
	const recorder = new AlertRecorder(
		db,
		null,
		config.alert.debounceMs,
		config.web.port,
	);
	const signatureDb = createSignatureDbStore(config.dataDir);
	const packageLookup = createPackageLookup();
	return { config, db, recorder, signatureDb, packageLookup };
}

function buildModules(
	ctx: ReturnType<typeof buildContext>,
): Record<string, Module> {
	return {
		fim: createFimModule(ctx),
		process: createProcessModule(ctx),
		auth: createAuthModule(ctx),
		network: createNetworkModule(ctx),
		signatureDb: createSignatureDbModule(ctx),
	};
}

// signatureDb is deliberately NOT in the default no-arg set below (same treatment as
// heartbeat/agent) — it needs a MalwareBazaar Auth-Key configured first (see README), so
// `hids init`/`hids scan-now` with no module arg must keep working for everyone else. Still
// reachable explicitly: `hids init signatureDb` / `hids scan-now signatureDb`.
function moduleNames(arg: string | undefined): string[] {
	if (arg && arg in BASELINE_FILES) return [arg];
	if (arg) {
		console.error(
			`Unknown module "${arg}". Valid: fim, process, auth, network, signatureDb`,
		);
		process.exit(1);
	}
	return ["fim", "process", "auth", "network"];
}

async function cmdInit(args: string[]) {
	const force = args.includes("--force");
	const moduleArg = args.find((a) => !a.startsWith("--"));
	const ctx = buildContext();
	const modules = buildModules(ctx);

	for (const name of moduleNames(moduleArg)) {
		const baselineFile = BASELINE_FILES[name];
		if (baselineFile) {
			const path = `${ctx.config.dataDir}/${baselineFile}`;
			if (existsSync(path) && !force) {
				console.error(
					`Baseline already exists for ${name} (${path}). Use --force to overwrite.`,
				);
				continue;
			}
			if (existsSync(path)) unlinkSync(path);
		}
		console.log(`Building baseline for ${name}...`);
		await modules[name]!.scanNow();
	}
	console.log("Done.");
	// Explicit exit: with no real mailer there's nothing worth lingering for, but the alert
	// recorder's debounce timer would otherwise keep this process alive for up to debounceMs
	// doing nothing — don't leave a silent background process hanging around after a manual scan.
	process.exit(0);
}

async function cmdScanNow(args: string[]) {
	const moduleArg = args[0];
	const ctx = buildContext();
	const modules = buildModules(ctx);
	for (const name of moduleNames(moduleArg)) {
		console.log(`Scanning ${name}...`);
		await modules[name]!.scanNow();
	}
	console.log("Scan complete. See `hids alerts` for any findings.");
	process.exit(0);
}

function cmdStatus() {
	const ctx = buildContext();
	const rows = getScanStatus(ctx.db);
	if (rows.length === 0) {
		console.log("No scans recorded yet. Run `hids init` first.");
		return;
	}
	for (const row of rows) {
		console.log(
			`${row.module.padEnd(10)} last: ${row.last_scan_ts}  ${row.last_result}`,
		);
	}
}

function cmdAlerts(args: string[]) {
	const ctx = buildContext();
	let since: string | undefined;
	let module: string | undefined;
	for (let i = 0; i < args.length; i++) {
		if (args[i] === "--since") since = args[++i];
		if (args[i] === "--module") module = args[++i];
	}
	const rows = getAlerts(ctx.db, { since, module });
	if (rows.length === 0) {
		console.log("No alerts.");
		return;
	}
	for (const row of rows) {
		console.log(
			`[${row.ts}] ${row.module} ${row.severity.toUpperCase()}: ${row.summary}`,
		);
	}
}

function cmdConfig() {
	const config = loadConfig();
	console.log(JSON.stringify(config, null, 2));
}

async function cmdTestEmail() {
	const config = loadConfig();
	const mailer = safeCreateMailer(createMailer, config.gmailEnvPath);
	if (!mailer) {
		console.error("Email is not configured — check the startup warning above.");
		process.exit(1);
	}
	await mailer.send(
		"HIDS test email",
		"This is a test alert from `hids test-email`.",
	);
	console.log("Sent. Check your inbox.");
}

async function cmdDaemon() {
	await import("./daemon.ts");
}

function cmdServiceAction(action: "start" | "stop" | "restart") {
	const result = Bun.spawnSync(["systemctl", "--user", action, "hids.service"]);
	process.stdout.write(result.stdout);
	process.stderr.write(result.stderr);
	process.exit(result.exitCode);
}

async function main() {
	const [command, ...args] = process.argv.slice(2);

	switch (command) {
		case "init":
		case "baseline":
			return cmdInit(args);
		case "scan-now":
			return cmdScanNow(args);
		case "status":
			return cmdStatus();
		case "alerts":
			return cmdAlerts(args);
		case "config":
			return cmdConfig();
		case "test-email":
			return cmdTestEmail();
		case "daemon":
			return cmdDaemon();
		case "start":
		case "stop":
		case "restart":
			return cmdServiceAction(command);
		default:
			console.log(`Usage: hids <command>

Commands:
  init [module] [--force]   Build baseline (fim/process/network; auth has none). signatureDb not
                            included by default — run \`hids init signatureDb\` once a
                            MalwareBazaar Auth-Key is configured (see README)
  scan-now [module]         Run a one-off scan now (recorded to \`alerts\`, does not send email —
                            only the daemon sends real alert emails)
  status                    Show last-scan status per module
  alerts [--since] [--module]  List recorded alerts
  config                    Print resolved config
  test-email                Send a test alert email
  daemon                    Run the foreground daemon (systemd execs this)
  start|stop|restart        Control the systemd --user service`);
			process.exit(command ? 1 : 0);
	}
}

void main();
