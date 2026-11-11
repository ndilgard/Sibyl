import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { HidsConfig } from "../config.ts";
import {
	type Alert,
	getAlertById,
	getAlerts,
	getScanStatus,
	type HistoryStore,
	type ScanStatus,
} from "../state/history-db.ts";
import {
	addWhitelistRule,
	defaultWhitelistField,
	getWhitelistRules,
	removeWhitelistRule,
} from "../state/whitelist-store.ts";
import { getOrCreateLinkSecret, verifyAlertToken } from "./link-auth.ts";

/** Exported for reuse by policy.ts's HTML alert emails — same escaping need, same rule: any
 * value that could contain attacker-influenced or AI-generated content must be escaped before
 * landing in HTML, here or there. */
export function escapeHtml(s: unknown): string {
	return String(s).replace(
		/[&<>"']/g,
		(c) =>
			({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
				c
			]!,
	);
}

function whitelistConfirmPage(alert: Alert, id: string, token: string): string {
	const field = defaultWhitelistField(alert.module);
	const detail = alert.detail as Record<string, unknown> | null;
	const value = detail && detail[field] != null ? String(detail[field]) : "";
	return `<!doctype html>
<html><head><meta charset="utf-8"><title>Whitelist — HIDS</title>
<style>body{font-family:system-ui,sans-serif;max-width:560px;margin:40px auto;padding:0 16px;color:#222}
label{display:block;margin-top:12px;font-size:0.9em;color:#555}
input{width:100%;padding:6px;font-size:1em;box-sizing:border-box}
button{margin-top:16px;padding:8px 16px;font-size:1em}
.detail{background:#f4f4f4;padding:12px;border-radius:4px;font-size:0.85em;overflow-x:auto}</style>
</head><body>
<h2>Whitelist this finding?</h2>
<p><strong>${escapeHtml(alert.module)}</strong> — ${escapeHtml(alert.severity)}<br>${escapeHtml(alert.summary)}</p>
<pre class="detail">${escapeHtml(JSON.stringify(alert.detail, null, 2))}</pre>
<form method="POST" action="/api/whitelist-confirm">
<input type="hidden" name="id" value="${escapeHtml(id)}">
<input type="hidden" name="token" value="${escapeHtml(token)}">
<label>Field<input type="text" name="field" value="${escapeHtml(field)}"></label>
<label>Value<input type="text" name="value" value="${escapeHtml(value)}"></label>
<label>Note (optional)<input type="text" name="note"></label>
<button type="submit">Add to Whitelist</button>
</form>
</body></html>`;
}

function whitelistSuccessPage(rule: {
	module: string;
	field: string;
	value: string;
}): string {
	return `<!doctype html>
<html><head><meta charset="utf-8"><title>Whitelisted — HIDS</title>
<style>body{font-family:system-ui,sans-serif;max-width:560px;margin:40px auto;padding:0 16px;color:#222}</style>
</head><body>
<h2>Rule added</h2>
<p>${escapeHtml(rule.module)} — ${escapeHtml(rule.field)} = ${escapeHtml(rule.value)}</p>
<p><a href="/">Back to dashboard</a></p>
</body></html>`;
}

function errorPage(status: number, message: string): Response {
	return new Response(
		`<!doctype html><html><head><meta charset="utf-8"><title>Error — HIDS</title></head><body><h2>${escapeHtml(message)}</h2></body></html>`,
		{ status, headers: { "content-type": "text/html" } },
	);
}

/** Modules with a genuinely fixed, short poll interval — the only reliable signal that the
 * detection daemon (not just this dashboard process) is actually still alive and scanning. FIM's
 * reconcile pass is 15 minutes and only reruns on a config change or a real file event, and auth's
 * journalctl stream only updates its timestamp on (re)connect, not per line watched — both can sit
 * "stale" for hours while working perfectly normally, so neither belongs in this check. */
const LIVENESS_MODULES = ["process", "network", "heartbeat"];
const LIVENESS_STALE_MS = 5 * 60 * 1000; // 5 minutes — comfortably more than 3x the slowest of the three (heartbeat, 2 min)

function computeLiveness(statuses: (ScanStatus & { module: string })[]) {
	const relevant = statuses.filter((s) => LIVENESS_MODULES.includes(s.module));
	if (relevant.length === 0) {
		return { aliveAsOf: null, staleMs: null, likelyDown: true };
	}
	const mostRecentMs = Math.max(
		...relevant.map((s) => new Date(s.last_scan_ts).getTime()),
	);
	const staleMs = Date.now() - mostRecentMs;
	return {
		aliveAsOf: new Date(mostRecentMs).toISOString(),
		staleMs,
		likelyDown: staleMs > LIVENESS_STALE_MS,
	};
}

const INDEX_HTML_PATH = join(import.meta.dir, "public", "index.html");

/** healthchecks.io's own view of the check (up/down/grace), polled server-side rather than on
 * every dashboard load — this is a convenience mirror of what's already visible on their site, not
 * a replacement for it. If HIDS itself is down, this endpoint (and the whole dashboard) is exactly
 * as unavailable as everything else on this host; healthchecks.io's email alert remains the only
 * signal that actually survives that case. */
let remoteHeartbeatCache: { data: unknown; fetchedAt: number } | null = null;
const REMOTE_HEARTBEAT_CACHE_MS = 60_000;

function extractCheckUuid(pingUrl: string): string | null {
	const match = pingUrl.match(/([0-9a-f]{8}-[0-9a-f-]{27})\/?$/i);
	return match ? match[1]! : null;
}

async function getRemoteHeartbeatStatus(config: HidsConfig): Promise<unknown> {
	if (!config.heartbeat.enabled || !config.heartbeat.apiKey) {
		return { configured: false };
	}
	if (
		remoteHeartbeatCache &&
		Date.now() - remoteHeartbeatCache.fetchedAt < REMOTE_HEARTBEAT_CACHE_MS
	) {
		return remoteHeartbeatCache.data;
	}

	const uuid = extractCheckUuid(config.heartbeat.url);
	if (!uuid) return { configured: false };

	try {
		const res = await fetch(`https://healthchecks.io/api/v3/checks/${uuid}`, {
			headers: { "X-Api-Key": config.heartbeat.apiKey },
		});
		if (!res.ok) {
			const data = { configured: true, error: `HTTP ${res.status}` };
			remoteHeartbeatCache = { data, fetchedAt: Date.now() };
			return data;
		}
		const check = (await res.json()) as {
			status: string;
			last_ping: string | null;
			next_ping: string | null;
		};
		const data = {
			configured: true,
			status: check.status,
			last_ping: check.last_ping,
			next_ping: check.next_ping,
		};
		remoteHeartbeatCache = { data, fetchedAt: Date.now() };
		return data;
	} catch (err) {
		const data = { configured: true, error: (err as Error).message };
		remoteHeartbeatCache = { data, fetchedAt: Date.now() };
		return data;
	}
}

export function startDashboard(db: HistoryStore, config: HidsConfig) {
	const server = Bun.serve({
		hostname: config.web.host,
		port: config.web.port,
		async fetch(req) {
			const url = new URL(req.url);

			if (url.pathname === "/" || url.pathname === "/index.html") {
				return new Response(readFileSync(INDEX_HTML_PATH, "utf-8"), {
					// no-store: this page is actively iterated on and has no version/asset hash to
					// bust a stale cache with — always serve the current file, not a cached one.
					headers: {
						"content-type": "text/html",
						"cache-control": "no-store",
					},
				});
			}

			if (url.pathname === "/api/status") {
				return Response.json(getScanStatus(db));
			}

			if (url.pathname === "/api/liveness") {
				return Response.json(computeLiveness(getScanStatus(db)));
			}

			if (url.pathname === "/api/heartbeat-remote") {
				return getRemoteHeartbeatStatus(config).then((data) =>
					Response.json(data),
				);
			}

			if (url.pathname === "/api/alerts") {
				const since = url.searchParams.get("since") ?? undefined;
				const module = url.searchParams.get("module") ?? undefined;
				const limit = url.searchParams.get("limit");
				const suppressed = url.searchParams.get("suppressed");
				return Response.json(
					getAlerts(db, {
						since,
						module,
						limit: limit ? Number(limit) : undefined,
						suppressed: suppressed === null ? undefined : suppressed === "true",
					}),
				);
			}

			if (url.pathname === "/api/whitelist" && req.method === "GET") {
				return Response.json(getWhitelistRules(db));
			}

			if (url.pathname === "/api/whitelist" && req.method === "POST") {
				const body = (await req.json()) as {
					module?: string;
					field?: string;
					value?: string;
					note?: string;
				};
				if (!body.module || !body.field || !body.value) {
					return Response.json(
						{ error: "module, field, and value are required" },
						{ status: 400 },
					);
				}
				const rule = addWhitelistRule(db, {
					module: body.module,
					field: body.field,
					value: body.value,
					note: body.note,
				});
				return Response.json(rule, { status: 201 });
			}

			if (
				url.pathname.startsWith("/api/whitelist/") &&
				req.method === "DELETE"
			) {
				const id = url.pathname.slice("/api/whitelist/".length);
				removeWhitelistRule(db, id);
				return new Response(null, { status: 204 });
			}

			if (url.pathname === "/api/whitelist-confirm" && req.method === "GET") {
				const id = url.searchParams.get("id");
				const token = url.searchParams.get("token");
				if (!id || !token) return errorPage(400, "Missing id or token.");
				const secret = getOrCreateLinkSecret(db.dataDir);
				if (!verifyAlertToken(secret, id, token)) {
					return errorPage(403, "Invalid or expired link.");
				}
				const alert = getAlertById(db, id);
				if (!alert) return errorPage(404, "Alert not found.");
				return new Response(whitelistConfirmPage(alert, id, token), {
					headers: { "content-type": "text/html" },
				});
			}

			if (url.pathname === "/api/whitelist-confirm" && req.method === "POST") {
				const form = await req.formData();
				const id = form.get("id")?.toString();
				const token = form.get("token")?.toString();
				const field = form.get("field")?.toString();
				const value = form.get("value")?.toString();
				const note = form.get("note")?.toString() || undefined;
				if (!id || !token || !field || !value) {
					return errorPage(400, "Missing required fields.");
				}
				const secret = getOrCreateLinkSecret(db.dataDir);
				if (!verifyAlertToken(secret, id, token)) {
					return errorPage(403, "Invalid or expired link.");
				}
				const alert = getAlertById(db, id);
				if (!alert) return errorPage(404, "Alert not found.");
				const rule = addWhitelistRule(db, {
					module: alert.module,
					field,
					value,
					note,
				});
				return new Response(whitelistSuccessPage(rule), {
					headers: { "content-type": "text/html" },
				});
			}

			return new Response("Not found", { status: 404 });
		},
	});

	// Explicit security assumption: LAN-reachable, no auth — single-user home network, no
	// port-forward to the wider internet. Whitelist-from-email links carry their own signed
	// per-alert token (see link-auth.ts) since those perform a mutation; the dashboard itself
	// still has none, same trust model as when it was localhost-only, just wider now.
	console.log(
		`[web] dashboard listening on http://${config.web.host}:${config.web.port}`,
	);
	return server;
}
