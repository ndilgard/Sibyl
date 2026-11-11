import { loadConfig } from "./config.ts";
import { openHistoryDb } from "./state/history-db.ts";
import { startDashboard } from "./web/server.ts";

/**
 * Deliberately separate process/service from the detection daemon (daemon.ts). If the daemon
 * crashes, gets killed, or is disabled, this keeps running and keeps showing that — "last scan
 * was 40 minutes ago" is a far more useful signal than the dashboard itself going unreachable.
 * It only ever reads dataDir's plain JSON/JSONL files (no exclusive locks, safe for a second
 * process to read concurrently with the daemon's writes) and never touches detection logic.
 */
const config = loadConfig();
const db = openHistoryDb(config.dataDir);
startDashboard(db, config);
console.log("[dashboard] running standalone — independent of hids.service");
