import type { AlertRecorder } from "../alert/policy.ts";
import type { HidsConfig } from "../config.ts";
import type { HistoryStore } from "../state/history-db.ts";
import type { SignatureDbStore } from "../state/signature-db-store.ts";

export interface ModuleContext {
	config: HidsConfig;
	db: HistoryStore;
	recorder: AlertRecorder;
	/** Optional so hand-built ModuleContext objects in existing tests don't all need updating —
	 * call sites fall back to noopSignatureDbStore() when absent. Always provided in daemon.ts/cli.ts. */
	signatureDb?: SignatureDbStore;
}

export interface Module {
	/** Runs one scan immediately; used by both the daemon's schedule and `hids scan-now`. */
	scanNow(): Promise<void>;
	/** Starts the module's ongoing schedule (interval or event stream). No-op for CLI-only use. */
	start(): void;
	stop(): void;
}
