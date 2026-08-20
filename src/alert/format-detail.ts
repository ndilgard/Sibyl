const HEX_HASH_RE = /^[0-9a-f]{32,}$/i;
const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

function humanizeKey(key: string): string {
	return key
		.replace(/([a-z0-9])([A-Z])/g, "$1 $2")
		.replace(/^./, (c) => c.toUpperCase());
}

function humanizeValue(key: string, value: unknown): string {
	if (typeof value === "string" && ISO_DATE_RE.test(value)) {
		return new Date(value).toLocaleString("en-US", {
			dateStyle: "medium",
			timeStyle: "short",
		});
	}
	if (typeof value === "string" && HEX_HASH_RE.test(value)) {
		return `${value.slice(0, 12)}…`;
	}
	if (typeof value === "number" && /size/i.test(key)) {
		return `${value.toLocaleString("en-US")} bytes`;
	}
	if (value === null || value === undefined) return "—";
	return String(value);
}

/**
 * Renders an alert's `detail` object as plain-text `Label: value` lines instead of a raw JSON
 * dump — dates become readable timestamps, hashes get truncated, byte counts get thousands
 * separators. FIM tamper alerts carry sibling `previous`/`current` objects that are ~90% the
 * same fields repeated twice; those get diffed field-by-field (`Label: old -> new`, or
 * `Label: value (unchanged)`) so the one thing that actually changed doesn't get buried in two
 * near-identical blocks.
 */
export function formatDetailLines(detail: unknown): string[] {
	if (typeof detail !== "object" || detail === null) return [];
	const obj = detail as Record<string, unknown>;
	const { previous, current, ...rest } = obj;

	if (
		previous &&
		current &&
		typeof previous === "object" &&
		typeof current === "object"
	) {
		const lines: string[] = [];
		if (typeof rest.path === "string") lines.push(`File: ${rest.path}`);

		const prevObj = previous as Record<string, unknown>;
		const currObj = current as Record<string, unknown>;
		const keys = new Set([...Object.keys(prevObj), ...Object.keys(currObj)]);
		for (const key of keys) {
			const label = humanizeKey(key);
			const pv = prevObj[key];
			const cv = currObj[key];
			lines.push(
				pv === cv
					? `${label}: ${humanizeValue(key, cv)} (unchanged)`
					: `${label}: ${humanizeValue(key, pv)} -> ${humanizeValue(key, cv)}`,
			);
		}

		for (const [key, value] of Object.entries(rest)) {
			if (key === "path") continue;
			lines.push(`${humanizeKey(key)}: ${humanizeValue(key, value)}`);
		}
		return lines;
	}

	return Object.entries(obj).map(
		([key, value]) => `${humanizeKey(key)}: ${humanizeValue(key, value)}`,
	);
}
