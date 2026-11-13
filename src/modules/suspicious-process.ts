import { createHash } from "node:crypto";
import { readFileSync, readlinkSync } from "node:fs";
import type { SignatureEntry } from "../state/signature-db-store.ts";

export interface SuspiciousCheck {
	suspicious: boolean;
	reason: "deleted" | "suspicious-path" | null;
	resolvedExePath: string | null;
}

/**
 * Shared with process.ts's own binary checks: exe path under a suspicious dir (/tmp, /dev/shm,
 * /var/tmp) or a binary that's been deleted from disk post-launch — both classic tamper/fileless
 * indicators. Used both when scanning /proc directly (process.ts) and when resolving a PID found
 * via `ss` (network.ts's outbound checks), so the two modules share one definition of "suspicious"
 * instead of drifting apart.
 */
export function checkSuspiciousExePath(
	exePath: string,
	suspiciousDirs: string[],
): SuspiciousCheck {
	const deleted = exePath.endsWith(" (deleted)");
	const resolvedExePath = deleted
		? exePath.slice(0, -" (deleted)".length)
		: exePath;

	if (deleted) {
		return { suspicious: true, reason: "deleted", resolvedExePath };
	}
	if (suspiciousDirs.some((dir) => resolvedExePath.startsWith(dir))) {
		return { suspicious: true, reason: "suspicious-path", resolvedExePath };
	}
	return { suspicious: false, reason: null, resolvedExePath };
}

export function resolveExePath(pid: number): string | null {
	try {
		return readlinkSync(`/proc/${pid}/exe`);
	} catch {
		return null; // process exited between listing and resolving, or not our user
	}
}

/**
 * Hashes an already-flagged-suspicious binary for a signature-DB lookup. For `reason: "deleted"`,
 * the file is unlinked from `resolvedExePath` but `/proc/<pid>/exe` still resolves to the live
 * (deleted) inode as long as the process hasn't exited yet — that window closes forever once it
 * does, so this must be called at detection time, not deferred to a later async pass. For
 * `reason: "suspicious-path"`, the file is still on disk at `resolvedExePath`. Never throws — a
 * hash miss (file gone, permissions) must never block the alert that's already firing.
 */
export function hashSuspiciousBinary(
	pid: string | number,
	check: SuspiciousCheck,
): string | null {
	const pathToHash =
		check.reason === "deleted" ? `/proc/${pid}/exe` : check.resolvedExePath;
	if (!pathToHash) return null;
	try {
		return createHash("sha256").update(readFileSync(pathToHash)).digest("hex");
	} catch {
		return null;
	}
}

/** Builds the enriched summary/detail for a suspicious-binary finding — pure function so the
 * match-formatting logic is unit-testable without touching /proc. A match is enrichment only: it
 * never changes whether the finding fires, only what it says. `detail` is deliberately typed
 * `unknown` (not `Record<string, unknown>`) so callers can pass their own concrete detail types
 * (e.g. process.ts's ProcInfo) without a cast — Object.assign avoids the object-spread typing
 * restriction that a plain `{...detail}` would hit on a non-index-signature interface. */
export function buildSuspiciousFinding(input: {
	summaryBase: string;
	detail: unknown;
	sha256: string | null;
	match: SignatureEntry | null;
}): { summary: string; detail: unknown } {
	const { summaryBase, detail, sha256, match } = input;
	const summary = match
		? `MATCHES KNOWN MALWARE (${match.signature ?? match.sha256}): ${summaryBase}`
		: summaryBase;
	const baseDetail =
		typeof detail === "object" && detail !== null ? detail : {};
	return {
		summary,
		detail: Object.assign({}, baseDetail, {
			sha256,
			malwareBazaarMatch: match,
		}),
	};
}
