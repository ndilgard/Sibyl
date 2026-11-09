import { dirname } from "node:path";
import type { Alert } from "./history-db.ts";

/**
 * One or more comparable identifiers pulled out of an alert's module-specific `detail`, used by
 * the cross-module correlation engine (src/state/correlate.ts) to decide whether two alerts from
 * different modules describe the same incident. Each identifier is tagged with its kind so the
 * engine only matches exePath-to-exePath, ip-to-ip, etc. — never across kinds.
 */
export interface Identifier {
	kind: "exePath" | "pid" | "dir" | "ip";
	value: string;
}

/** sshd: "Failed password for invalid user X from 1.2.3.4 port ..." / "Accepted password for X
 * from 1.2.3.4 port ...". Matches both the invalid-user and valid-user phrasing. */
const SSHD_IP_RE = /\bfrom (\d{1,3}(?:\.\d{1,3}){3})\b/;

function extractFim(detail: unknown): Identifier[] {
	if (typeof detail !== "object" || detail === null) return [];
	const path = (detail as { path?: unknown }).path;
	if (typeof path !== "string" || path.length === 0) return [];
	return [
		{ kind: "exePath", value: path },
		{ kind: "dir", value: dirname(path) },
	];
}

function extractProcess(detail: unknown): Identifier[] {
	if (typeof detail !== "object" || detail === null) return [];
	const { pid, exePath } = detail as { pid?: unknown; exePath?: unknown };
	const ids: Identifier[] = [];
	if (typeof pid === "string" && pid.length > 0) {
		ids.push({ kind: "pid", value: pid });
	}
	if (typeof exePath === "string" && exePath.length > 0) {
		ids.push({ kind: "exePath", value: exePath });
		ids.push({ kind: "dir", value: dirname(exePath) });
	}
	return ids;
}

function extractNetwork(detail: unknown): Identifier[] {
	if (typeof detail !== "object" || detail === null) return [];
	const { exePath, remoteAddress, localAddress } = detail as {
		exePath?: unknown;
		remoteAddress?: unknown;
		localAddress?: unknown;
	};
	const ids: Identifier[] = [];
	if (typeof exePath === "string" && exePath.length > 0) {
		ids.push({ kind: "exePath", value: exePath });
		ids.push({ kind: "dir", value: dirname(exePath) });
	}
	const ip = typeof remoteAddress === "string" ? remoteAddress : localAddress;
	if (typeof ip === "string" && ip.length > 0) {
		ids.push({ kind: "ip", value: ip });
	}
	return ids;
}

function extractAuth(detail: unknown): Identifier[] {
	if (typeof detail !== "object" || detail === null) return [];
	const message = (detail as { MESSAGE?: unknown }).MESSAGE;
	if (typeof message !== "string") return [];
	const match = message.match(SSHD_IP_RE);
	if (!match) return [];
	return [{ kind: "ip", value: match[1] }];
}

/**
 * Pulls comparable identifiers out of an alert's `detail`, module-specific. Returns an empty
 * array (never throws) when the shape doesn't match what's expected — an alert that can't be
 * identified simply can't correlate, which is a safe/quiet failure mode for this feature.
 */
export function extractIdentifiers(alert: Alert): Identifier[] {
	switch (alert.module) {
		case "fim":
			return extractFim(alert.detail);
		case "process":
			return extractProcess(alert.detail);
		case "network":
			return extractNetwork(alert.detail);
		case "auth":
			return extractAuth(alert.detail);
		default:
			return [];
	}
}
