import { readJson, writeJsonAtomic } from "./json-store.ts";

/**
 * Local cache of known-malware SHA-256 hashes (from abuse.ch MalwareBazaar's `recent.csv` feed).
 * Wholesale-replaced on each periodic refresh (see modules/signature-db.ts) — same atomic-JSON-blob
 * convention as baseline-fim.json/baseline-processes.json, not the JSONL append pattern
 * (whitelist-store.ts), since this is a replaceable dataset, not an audit log.
 */

export interface SignatureEntry {
	sha256: string;
	signature?: string;
	fileType?: string;
	firstSeen?: string;
}

interface SignatureDbCache {
	refreshedAt: string | null;
	entries: SignatureEntry[];
}

export interface SignatureDbStore {
	lookup(sha256Hex: string): SignatureEntry | null;
	size(): number;
	lastRefreshedAt(): string | null;
	replaceAll(entries: SignatureEntry[], refreshedAt: string): void;
}

function cachePath(dataDir: string): string {
	return `${dataDir}/signature-db-cache.json`;
}

function indexByHash(entries: SignatureEntry[]): Map<string, SignatureEntry> {
	return new Map(entries.map((e) => [e.sha256.toLowerCase(), e]));
}

export function createSignatureDbStore(dataDir: string): SignatureDbStore {
	const path = cachePath(dataDir);
	let cache = readJson<SignatureDbCache>(path, {
		refreshedAt: null,
		entries: [],
	});
	let byHash = indexByHash(cache.entries);

	return {
		lookup(sha256Hex) {
			return byHash.get(sha256Hex.toLowerCase()) ?? null;
		},
		size() {
			return byHash.size;
		},
		lastRefreshedAt() {
			return cache.refreshedAt;
		},
		replaceAll(entries, refreshedAt) {
			cache = { refreshedAt, entries };
			byHash = indexByHash(entries);
			writeJsonAtomic(path, cache);
		},
	};
}

/** Used when a module context omits signatureDb (e.g. hand-built ModuleContext in older tests) —
 * always a cache miss, never a lookup error. */
export function noopSignatureDbStore(): SignatureDbStore {
	return {
		lookup: () => null,
		size: () => 0,
		lastRefreshedAt: () => null,
		replaceAll: () => {},
	};
}
