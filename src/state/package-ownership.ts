import { readFileSync } from "node:fs";

/**
 * Shared dpkg/apt lookups: "does an installed package own this path" and "was that package
 * upgraded recently". Used by two callers — agent/triage.ts's `check_package_ownership` tool
 * (shows the model whether/which package owns a suspicious path) and modules/process.ts's
 * deleted-binary pre-filter (needs the same ownership check, plus the recency check, to explain
 * away the routine "process holds an fd to a binary an apt upgrade just unlinked" false-positive
 * shape) — one dpkg/apt-log-reading implementation, not two.
 */

/** Sanity check before a path reaches `Bun.spawnSync(["dpkg", "-S", path])` — not primarily a
 * shell-injection concern (args array, not a shell string, is already immune to that), but bounds
 * length and requires an absolute path so the tool does only what it's for. Rejects null bytes
 * outright, since those are never valid in a real filesystem path and Bun.spawnSync (like Node)
 * throws on them anyway — better to fail with a clear "invalid input" than a cryptic runtime error
 * deeper in the call stack. */
export function isPlausiblePath(s: string): boolean {
	if (s.length === 0 || s.length > 4096) return false;
	if (s.includes("\0")) return false;
	return s.startsWith("/");
}

const DPKG_OUTPUT_MAX_CHARS = 500;

export interface DpkgQueryResult {
	owned: boolean;
	/** Raw, trimmed (and length-capped) `dpkg -S` stdout when owned; empty string when not. */
	rawOutput: string;
}

/** Runs `dpkg -S <path>` and reports whether some installed package owns it, plus the raw output
 * for display. Caller is responsible for validating `path` first (see isPlausiblePath) — this
 * function shells out unconditionally. */
export function queryDpkgOwner(path: string): DpkgQueryResult {
	const result = Bun.spawnSync(["dpkg", "-S", path], { timeout: 10_000 });
	if (result.exitCode !== 0) return { owned: false, rawOutput: "" };
	const output = result.stdout.toString().trim();
	return {
		owned: true,
		rawOutput:
			output.length > DPKG_OUTPUT_MAX_CHARS
				? `${output.slice(0, DPKG_OUTPUT_MAX_CHARS)}\n...(truncated)`
				: output,
	};
}

/** Parses the owning package name out of `dpkg -S`'s first line, e.g. "coreutils:amd64: /bin/ls"
 * -> "coreutils" (drops the ":amd64" multiarch suffix). Multiple packages can own overlapping
 * paths (diversions); this only looks at the first line, which is enough for a recency check —
 * any one owner having been upgraded recently is sufficient to explain the finding. Returns null
 * if the output doesn't look like the expected "<pkgspec>: /path" shape. */
export function parseOwningPackage(rawOutput: string): string | null {
	const firstLine = rawOutput.split("\n")[0] ?? "";
	const sepIndex = firstLine.indexOf(": /");
	if (sepIndex === -1) return null;
	const pkgSpec = firstLine.slice(0, sepIndex);
	const name = pkgSpec.split(":")[0]?.trim();
	return name && name.length > 0 ? name : null;
}

const DEFAULT_APT_HISTORY_LOG = "/var/log/apt/history.log";
const MS_PER_DAY = 24 * 60 * 60 * 1000;

/** Whether `pkg` (a bare package name, no :arch suffix) appears in an Upgrade:/Install: line of
 * an apt history entry started within the last `graceDays` days.
 *
 * Deliberately a SIMPLE recency check, not precise correlation with the deletion event: this only
 * asks "was this package touched by apt recently", never tries to line up dpkg's timestamp against
 * `/proc/<pid>/exe`'s mtime — that was discussed and rejected as too fragile (mtimes get smudged
 * by hardlinks/atomic-rename package managers use, clock skew, etc). A package that was upgraded
 * at all in the window is explanation enough for a deleted-on-disk finding appearing that same
 * window.
 *
 * Only reads the live, uncompressed `history.log` — not rotated `history.log.<N>.gz` archives.
 * apt's default logrotate policy (`/etc/logrotate.d/apt`, monthly rotation) keeps well over a
 * month of history in that one file before the first rotation, comfortably outliving any sane
 * grace window (days, not weeks) this check is configured with.
 *
 * Throws if the log can't be read at all (missing, permission denied) — the caller must treat
 * that as "unknown", never as "not recently upgraded", per this feature's fail-safe design: a
 * lookup failure is never evidence of benignity. */
export function wasPackageRecentlyUpgraded(
	pkg: string,
	graceDays: number,
	historyLogPath: string = DEFAULT_APT_HISTORY_LOG,
): boolean {
	const content = readFileSync(historyLogPath, "utf-8");
	const cutoff = Date.now() - graceDays * MS_PER_DAY;

	for (const entry of content.split(/\n(?=Start-Date: )/)) {
		const dateMatch = entry.match(/^Start-Date:\s*(.+)$/m);
		if (!dateMatch?.[1]) continue;
		// apt writes "YYYY-MM-DD  HH:MM:SS" (local time, no offset); normalize the date/time gap
		// to "T" so Date can parse it, same as any other space run in the field.
		const startedAt = new Date(dateMatch[1].trim().replace(/\s+/, "T"));
		if (Number.isNaN(startedAt.getTime()) || startedAt.getTime() < cutoff) {
			continue;
		}

		const actionLines = entry.match(/^(?:Upgrade|Install):\s*.+$/gm) ?? [];
		for (const line of actionLines) {
			const specs = line.replace(/^(?:Upgrade|Install):\s*/, "").split(/,\s*/);
			if (specs.some((spec) => spec.split(":")[0]?.trim() === pkg)) {
				return true;
			}
		}
	}
	return false;
}

export interface PackageLookup {
	/** Owning package name for `path`, or null if no installed package owns it (or the path isn't
	 * plausible). Throws if the underlying `dpkg` call itself fails unexpectedly (not merely "no
	 * match", which returns null) — callers must treat a throw as inconclusive, not as "unowned". */
	ownerOf(path: string): string | null;
	/** See wasPackageRecentlyUpgraded — throws under the same fail-safe conditions. */
	wasRecentlyUpgraded(pkg: string, graceDays: number): boolean;
}

/** The real, system-calling implementation — shells out to `dpkg` and reads
 * `/var/log/apt/history.log`, matching this codebase's existing convention of shelling out to
 * system tools for facts it doesn't want to reimplement (network.ts's `ss`, auth.ts's
 * `journalctl`, triage.ts's `whois`). Kept separate from callers so tests can inject a fake
 * instead of touching the real filesystem/binaries. */
export function createPackageLookup(): PackageLookup {
	return {
		ownerOf(path) {
			if (!isPlausiblePath(path)) return null;
			const { owned, rawOutput } = queryDpkgOwner(path);
			return owned ? parseOwningPackage(rawOutput) : null;
		},
		wasRecentlyUpgraded(pkg, graceDays) {
			return wasPackageRecentlyUpgraded(pkg, graceDays);
		},
	};
}
