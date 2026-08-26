import { describe, expect, test } from "bun:test";
import { applyConfigDefaults, type HidsConfig } from "./config.ts";

/** A minimally valid config as loadConfig() would receive it after JSON.parse — network/fim
 * objects always exist (present in the example config on disk), but individual defaulted leaf
 * fields (alertOnUdp, watchTrustedProcessBinaries, heartbeat) may be absent on an older config
 * file, same as real production data. */
function baseConfig(overrides: Partial<HidsConfig> = {}): HidsConfig {
	return {
		dataDir: "/mnt/omv/HIDS",
		gmailEnvPath: "credentials/gmail-smtp.env",
		web: { host: "0.0.0.0", port: 8787 },
		fim: {
			watchPaths: [],
			reconcileIntervalMs: 900000,
			debounceMs: 2000,
			watchTrustedProcessBinaries: undefined as unknown as boolean,
		},
		process: { pollIntervalMs: 10000, suspiciousDirs: ["/tmp"] },
		auth: { reconnectBackoffMs: 5000 },
		network: {
			pollIntervalMs: 30000,
			alertOnNewListener: true,
			alertOnOutbound: true,
			alertOnUdp: undefined as unknown as boolean,
		},
		alert: { debounceMs: 60000, emailOnNewBinary: false },
		heartbeat: undefined as unknown as HidsConfig["heartbeat"],
		agent: undefined as unknown as HidsConfig["agent"],
		...overrides,
	};
}

describe("applyConfigDefaults", () => {
	test("defaults alertOnUdp to false when absent", () => {
		const result = applyConfigDefaults(baseConfig());
		expect(result.network.alertOnUdp).toBe(false);
	});

	test("preserves an explicit alertOnUdp: true", () => {
		const config = baseConfig();
		config.network.alertOnUdp = true;
		expect(applyConfigDefaults(config).network.alertOnUdp).toBe(true);
	});

	test("preserves an explicit alertOnUdp: false (not treated as 'absent')", () => {
		const config = baseConfig();
		config.network.alertOnUdp = false;
		expect(applyConfigDefaults(config).network.alertOnUdp).toBe(false);
	});

	test("defaults watchTrustedProcessBinaries to true when absent", () => {
		const result = applyConfigDefaults(baseConfig());
		expect(result.fim.watchTrustedProcessBinaries).toBe(true);
	});

	test("preserves an explicit watchTrustedProcessBinaries: false", () => {
		const config = baseConfig();
		config.fim.watchTrustedProcessBinaries = false;
		expect(applyConfigDefaults(config).fim.watchTrustedProcessBinaries).toBe(
			false,
		);
	});

	test("defaults heartbeat to a disabled config when absent", () => {
		const result = applyConfigDefaults(baseConfig());
		expect(result.heartbeat).toEqual({
			enabled: false,
			url: "",
			intervalMs: 120000,
		});
	});

	test("preserves an explicit heartbeat config", () => {
		const explicit = {
			enabled: true,
			url: "https://hc-ping.com/abc",
			intervalMs: 60000,
		};
		const config = baseConfig({ heartbeat: explicit });
		expect(applyConfigDefaults(config).heartbeat).toEqual(explicit);
	});

	test("defaults agent to a disabled config when absent", () => {
		const result = applyConfigDefaults(baseConfig());
		expect(result.agent).toEqual({
			enabled: false,
			model: "claude-sonnet-5",
			intervalMs: 300000,
			apiKeyEnvPath: "credentials/anthropic.env",
		});
	});

	test("preserves an explicit agent config", () => {
		const explicit = {
			enabled: true,
			model: "claude-sonnet-5",
			intervalMs: 120000,
			apiKeyEnvPath: "credentials/anthropic.env",
		};
		const config = baseConfig({ agent: explicit });
		expect(applyConfigDefaults(config).agent).toEqual(explicit);
	});

	test("leaves unrelated fields untouched", () => {
		const config = baseConfig();
		const result = applyConfigDefaults(config);
		expect(result.dataDir).toBe("/mnt/omv/HIDS");
		expect(result.web.port).toBe(8787);
	});
});
