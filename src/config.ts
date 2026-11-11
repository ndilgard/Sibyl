import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export interface HidsConfig {
	dataDir: string;
	gmailEnvPath: string;
	web: { host: string; port: number };
	fim: {
		watchPaths: string[];
		reconcileIntervalMs: number;
		debounceMs: number;
		watchTrustedProcessBinaries: boolean;
	};
	process: { pollIntervalMs: number; suspiciousDirs: string[] };
	auth: { reconnectBackoffMs: number };
	network: {
		pollIntervalMs: number;
		alertOnNewListener: boolean;
		alertOnOutbound: boolean;
		alertOnUdp: boolean;
	};
	alert: { debounceMs: number; emailOnNewBinary: boolean };
	heartbeat: {
		enabled: boolean;
		url: string;
		intervalMs: number;
		/** Read-only API key for polling healthchecks.io's own view of this check (up/down/grace)
		 * onto the local dashboard. Optional — the ping itself (and its alerting) works without it;
		 * this only feeds the dashboard's remote-status card. */
		apiKey?: string;
	};
	agent: {
		enabled: boolean;
		model: string;
		intervalMs: number;
		apiKeyEnvPath: string;
	};
	signatureDb: {
		enabled: boolean;
		/** "recent" = trailing 48h window, wholesale-replaced each refresh (default — matches the
		 * atomic-cache storage convention with zero merge logic). "full" = abuse.ch's entire
		 * database (~100MB, 900k+ hashes) — full coverage, much bigger/slower to refresh. */
		feed: "recent" | "full";
		refreshIntervalMs: number;
		authKeyEnvPath: string;
	};
}

const CONFIG_PATH = join(import.meta.dir, "..", "config", "hids.config.json");
const EXAMPLE_CONFIG_PATH = join(
	import.meta.dir,
	"..",
	"config",
	"hids.config.json.example",
);

function expandHome(path: string): string {
	if (path.startsWith("~")) return join(homedir(), path.slice(1));
	return path;
}

/** Fills in fields that older config files on disk may not have. Split out from loadConfig() so
 * the defaulting rules can be unit-tested without touching disk. */
export function applyConfigDefaults(raw: HidsConfig): HidsConfig {
	raw.network.alertOnUdp ??= false; // default off — UDP "listeners" are mostly ephemeral app noise (WebRTC/QUIC/DNS)
	raw.fim.watchTrustedProcessBinaries ??= true;
	raw.heartbeat ??= { enabled: false, url: "", intervalMs: 120000 };
	raw.agent ??= {
		enabled: false,
		model: "claude-sonnet-5",
		intervalMs: 300000,
		apiKeyEnvPath: "credentials/anthropic.env",
	};
	raw.signatureDb ??= {
		enabled: false,
		feed: "recent",
		refreshIntervalMs: 6 * 60 * 60 * 1000,
		authKeyEnvPath: "credentials/malwarebazaar.env",
	};
	return raw;
}

export function loadConfig(): HidsConfig {
	const path = existsSync(CONFIG_PATH) ? CONFIG_PATH : EXAMPLE_CONFIG_PATH;
	const raw = JSON.parse(readFileSync(path, "utf-8")) as HidsConfig;

	raw.dataDir = process.env.HIDS_DATA_DIR ?? raw.dataDir;
	raw.gmailEnvPath = process.env.HIDS_GMAIL_ENV_PATH ?? raw.gmailEnvPath;
	raw.fim.watchPaths = raw.fim.watchPaths.map(expandHome);

	return applyConfigDefaults(raw);
}
