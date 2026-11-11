import { existsSync } from "node:fs";
import { loadEnv } from "../alert/email.ts";
import { upsertScanStatus } from "../state/history-db.ts";
import type { SignatureEntry } from "../state/signature-db-store.ts";
import type { Module, ModuleContext } from "./types.ts";

/**
 * Periodic refresh of the local MalwareBazaar hash cache (see state/signature-db-store.ts). This
 * module ONLY refreshes the cache — actual hash lookups happen inline in process.ts/network.ts at
 * detection time (see suspicious-process.ts's hashSuspiciousBinary/buildSuspiciousFinding). A
 * refresh failure never wipes the existing cache and never throws past scanNow() — it logs a
 * warning and keeps serving whatever was last successfully fetched.
 */

export interface MalwareBazaarClient {
	fetchHashes(): Promise<SignatureEntry[]>;
}

const FETCH_TIMEOUT_MS = 30_000;
// Post-fetch sanity cap, not a streaming limit — matches this codebase's existing convention of
// truncating/validating external output after the fact (e.g. triage.ts's WHOIS_OUTPUT_MAX_CHARS)
// rather than bounding a subprocess/response stream as it arrives.
const MAX_RESPONSE_CHARS = 50 * 1024 * 1024;

/** Minimal RFC4180-style CSV line splitter (quoted fields, "" escaping) — MalwareBazaar's export
 * can carry commas inside quoted file_name/reporter fields, so a plain .split(",") isn't safe. */
function parseCsvLine(line: string): string[] {
	const fields: string[] = [];
	let cur = "";
	let inQuotes = false;
	for (let i = 0; i < line.length; i++) {
		const ch = line[i];
		if (inQuotes) {
			if (ch === '"') {
				if (line[i + 1] === '"') {
					cur += '"';
					i++;
				} else {
					inQuotes = false;
				}
			} else {
				cur += ch;
			}
		} else if (ch === '"') {
			inQuotes = true;
		} else if (ch === ",") {
			fields.push(cur);
			cur = "";
		} else {
			cur += ch;
		}
	}
	fields.push(cur);
	return fields;
}

/** MalwareBazaar's documented recent.csv/full.csv columns (confirmed via abuse.ch, 2026-08):
 * first_seen_utc, sha256_hash, md5_hash, sha1_hash, reporter, file_name, file_type_guess,
 * mime_type, signature, clamav, vtpercent, imphash, ssdeep, tlsh. Looked up by header name rather
 * than hardcoded position so a harmless column reorder upstream doesn't silently misparse. Rows
 * missing sha256_hash are skipped (nothing to key the cache on). */
export function parseMalwareBazaarCsv(csv: string): SignatureEntry[] {
	const lines = csv
		.split("\n")
		.filter((l) => l.trim().length > 0 && !l.trim().startsWith("#"));
	const [headerLine, ...bodyLines] = lines;
	if (!headerLine) return [];

	const header = parseCsvLine(headerLine).map((h) => h.trim().toLowerCase());
	const shaIdx = header.indexOf("sha256_hash");
	if (shaIdx === -1) {
		throw new Error(
			"MalwareBazaar CSV missing sha256_hash column — unexpected format",
		);
	}
	const sigIdx = header.indexOf("signature");
	const typeIdx = header.indexOf("file_type_guess");
	const firstSeenIdx = header.indexOf("first_seen_utc");

	const entries: SignatureEntry[] = [];
	for (const line of bodyLines) {
		const fields = parseCsvLine(line);
		const sha256 = fields[shaIdx]?.trim();
		if (!sha256) continue;
		entries.push({
			sha256: sha256.toLowerCase(),
			signature:
				sigIdx !== -1 ? fields[sigIdx]?.trim() || undefined : undefined,
			fileType:
				typeIdx !== -1 ? fields[typeIdx]?.trim() || undefined : undefined,
			firstSeen:
				firstSeenIdx !== -1
					? fields[firstSeenIdx]?.trim() || undefined
					: undefined,
		});
	}
	return entries;
}

function feedUrl(feed: "recent" | "full", authKey: string): string {
	return `https://mb-api.abuse.ch/v2/files/exports/${authKey}/${feed}.csv`;
}

export function createMalwareBazaarClient(
	authKey: string,
	feed: "recent" | "full",
): MalwareBazaarClient {
	return {
		async fetchHashes(): Promise<SignatureEntry[]> {
			const res = await fetch(feedUrl(feed, authKey), {
				signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
			});
			if (!res.ok) {
				throw new Error(
					`MalwareBazaar export request failed: HTTP ${res.status}`,
				);
			}
			const text = await res.text();
			if (text.length > MAX_RESPONSE_CHARS) {
				throw new Error(
					`MalwareBazaar export response exceeded ${MAX_RESPONSE_CHARS} chars — refusing to parse`,
				);
			}
			return parseMalwareBazaarCsv(text);
		},
	};
}

export function createSignatureDbModule(
	ctx: ModuleContext,
	clientOverride?: MalwareBazaarClient,
): Module {
	const { config, db } = ctx;
	let timer: ReturnType<typeof setInterval> | null = null;
	let client = clientOverride ?? null;

	function getClient(): MalwareBazaarClient {
		if (client) return client;
		if (!existsSync(config.signatureDb.authKeyEnvPath)) {
			throw new Error(
				`MalwareBazaar credentials file not found at ${config.signatureDb.authKeyEnvPath} — signature-db refresh is disabled until this exists.`,
			);
		}
		const authKey = loadEnv(
			config.signatureDb.authKeyEnvPath,
		).MALWAREBAZAAR_AUTH_KEY;
		if (!authKey) {
			throw new Error(
				`${config.signatureDb.authKeyEnvPath} is missing MALWAREBAZAAR_AUTH_KEY.`,
			);
		}
		client = createMalwareBazaarClient(authKey, config.signatureDb.feed);
		return client;
	}

	async function scanNow(): Promise<void> {
		const store = ctx.signatureDb;
		if (!store) return; // no store wired into this context (shouldn't happen outside tests)

		try {
			const entries = await getClient().fetchHashes();
			const refreshedAt = new Date().toISOString();
			store.replaceAll(entries, refreshedAt);
			upsertScanStatus(
				db,
				"signature-db",
				`ok (${entries.length} hashes, refreshed ${refreshedAt})`,
			);
		} catch (err) {
			const message = err instanceof Error ? err.message : String(err);
			console.warn(`[signature-db] refresh failed: ${message}`);
			upsertScanStatus(
				db,
				"signature-db",
				`refresh failed: ${message} (serving last-good cache, ${store.size()} hashes from ${store.lastRefreshedAt() ?? "never"})`,
			);
		}
	}

	function start(): void {
		if (!config.signatureDb.enabled) return;
		void scanNow(); // warm the cache immediately rather than waiting a full interval
		timer = setInterval(
			() => void scanNow(),
			config.signatureDb.refreshIntervalMs,
		);
	}

	function stop(): void {
		if (timer) clearInterval(timer);
	}

	return { scanNow, start, stop };
}
