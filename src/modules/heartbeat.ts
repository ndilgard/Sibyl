import { upsertScanStatus } from "../state/history-db.ts";
import type { Module, ModuleContext } from "./types.ts";

/** Pings an external dead-man's-switch (healthchecks.io) on a schedule. This is the one module
 * that exists to detect HIDS itself going quiet — crashed, killed, or disabled by an attacker with
 * root — which none of the other modules can do, since anything running only on this host can be
 * silenced the same way the daemon itself can. The alerting-on-absence logic deliberately lives
 * entirely on healthchecks.io's side, not here: if this module (or the whole daemon) stops
 * running, there's nothing left on this box to notice or report that. A missed ping is *itself*
 * the signal, detected by a party outside this machine.
 *
 * Failures to reach healthchecks.io (network blip, DNS hiccup) are logged locally but never
 * escalated through the normal alert pipeline — that pipeline is exactly what a truly dead daemon
 * can't use to tell anyone anything. */
export function createHeartbeatModule(ctx: ModuleContext): Module {
	const { config, db } = ctx;
	let timer: ReturnType<typeof setInterval> | null = null;

	async function scanNow(): Promise<void> {
		if (!config.heartbeat.enabled) return;
		try {
			const res = await fetch(config.heartbeat.url, { method: "GET" });
			if (res.ok) {
				upsertScanStatus(
					db,
					"heartbeat",
					`ok (last ping ${new Date().toISOString()})`,
				);
			} else {
				console.warn(`[heartbeat] ping returned HTTP ${res.status}`);
				upsertScanStatus(db, "heartbeat", `ping failed: HTTP ${res.status}`);
			}
		} catch (err) {
			console.warn(`[heartbeat] ping failed: ${(err as Error).message}`);
			upsertScanStatus(
				db,
				"heartbeat",
				`ping failed: ${(err as Error).message}`,
			);
		}
	}

	function start(): void {
		if (!config.heartbeat.enabled) return;
		void scanNow();
		timer = setInterval(() => void scanNow(), config.heartbeat.intervalMs);
	}

	function stop(): void {
		if (timer) clearInterval(timer);
	}

	return { scanNow, start, stop };
}
