import {
	existsSync,
	mkdirSync,
	readFileSync,
	renameSync,
	writeFileSync,
} from "node:fs";
import { dirname } from "node:path";

/** Atomic write-then-rename so a crash mid-write never corrupts the baseline file. */
export function writeJsonAtomic(path: string, data: unknown): void {
	mkdirSync(dirname(path), { recursive: true });
	const tmpPath = `${path}.tmp-${process.pid}`;
	writeFileSync(tmpPath, JSON.stringify(data, null, 2));
	renameSync(tmpPath, path);
}

export function readJson<T>(path: string, fallback: T): T {
	if (!existsSync(path)) return fallback;
	return JSON.parse(readFileSync(path, "utf-8")) as T;
}
