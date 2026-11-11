import { networkInterfaces } from "node:os";
import {
	type HistoryStore,
	insertAlert,
	markEmailed,
	type Severity,
} from "../state/history-db.ts";
import {
	findMatchingRule,
	recordWhitelistMatch,
	WHITELISTABLE_MODULES,
} from "../state/whitelist-store.ts";
import { getOrCreateLinkSecret, signAlertToken } from "../web/link-auth.ts";
import { escapeHtml } from "../web/server.ts";
import { type Mailer, MailerNotConfigured } from "./email.ts";
import { formatDetailLines } from "./format-detail.ts";

/** First non-internal private IPv4 found — used to build links in alert emails that work from
 * other devices on the home network (phone on home wifi), not just this host. Read fresh per
 * email rather than cached/config'd, since DHCP could reassign it. */
function lanIp(): string | null {
	for (const iface of Object.values(networkInterfaces())) {
		for (const addr of iface ?? []) {
			if (addr.family === "IPv4" && !addr.internal) return addr.address;
		}
	}
	return null;
}

export interface Finding {
	module: string;
	severity: Severity;
	summary: string;
	detail: unknown;
}

/**
 * Central recorder: modules call record() only for findings they've already decided are
 * alert-worthy per their own per-module rules (see each modules/*.ts). Routine/non-alert-worthy
 * observations never reach this — that's what keeps disk usage tied to real triggers only.
 *
 * Batches findings into one summarizing email per debounce window instead of one email per
 * finding, so a burst (e.g. a whole watched directory deleted) doesn't flood the inbox.
 */
export class AlertRecorder {
	private pending: { id: string; finding: Finding; aiReasoning?: string }[] =
		[];
	private timer: ReturnType<typeof setTimeout> | null = null;
	// Set on the first item of a batch, cleared on flush. Bounds how long a *sustained* stream of
	// findings (each one resetting the trailing debounce below) can delay the email — without this,
	// findings arriving faster than debounceMs apart reset the timer forever and flush() never runs.
	// (Real incident: a still-running process kept re-triggering a critical every 10s, which is
	// faster than the 45s debounce, and starved the email indefinitely.)
	private batchStartedAt: number | null = null;
	private static readonly MAX_BATCH_WAIT_MULTIPLIER = 3;

	constructor(
		private db: HistoryStore,
		private mailer: Mailer | null,
		private debounceMs: number,
		private port: number,
	) {}

	/** Trailing debounce with a hard cap: resets on every new item like a plain debounce (so a
	 * short burst still batches into one email), but never lets the wait exceed maxWaitMs from the
	 * first item in the batch, so a sustained stream still flushes periodically. */
	private schedule(): void {
		const now = Date.now();
		if (this.batchStartedAt === null) this.batchStartedAt = now;
		const maxWaitMs = this.debounceMs * AlertRecorder.MAX_BATCH_WAIT_MULTIPLIER;
		const remaining = maxWaitMs - (now - this.batchStartedAt);
		if (this.timer) clearTimeout(this.timer);
		const delay = Math.max(0, Math.min(this.debounceMs, remaining));
		this.timer = setTimeout(() => void this.flush(), delay);
	}

	record(finding: Finding): void {
		const whitelisted = findMatchingRule(
			this.db,
			finding.module,
			finding.detail,
		);
		if (whitelisted) {
			// Still recorded (as `suppressed`) rather than dropped entirely — a bad whitelist rule
			// should be catchable after the fact from the dashboard's "Suppressed Events" view, not
			// silently invisible. Just skipped from the normal alert list/email flow below.
			insertAlert(this.db, {
				module: finding.module,
				severity: finding.severity,
				summary: finding.summary,
				detail: finding.detail,
				suppressed: true,
				whitelistRuleId: whitelisted.id,
			});
			recordWhitelistMatch(this.db, whitelisted.id);
			return;
		}

		const id = insertAlert(this.db, {
			module: finding.module,
			severity: finding.severity,
			summary: finding.summary,
			detail: finding.detail,
		});
		console.log(
			`[alert:${finding.module}] ${finding.severity} — ${finding.summary}`,
		);

		// Only critical findings are emailed — warning/info still land in the alert store (and
		// the dashboard) but don't page Nate directly. warning-level network noise ("known
		// process contacting a new destination") was firing a real email every ~45s: 201 emails
		// in 2 days, nearly all benign. Dashboard is the review surface for anything non-critical.
		if (finding.severity !== "critical") return;

		this.pending.push({ id, finding });
		this.schedule();
	}

	/**
	 * Escalates a finding the AI triage layer judged "alarming" — the finding was already
	 * recorded (as warning/info) by an earlier record() call, so this reuses that existing alert
	 * id rather than inserting a new row. Shares the same debounce/batch/mailer flow as record()'s
	 * critical path so an escalated finding can land in the same email as a simultaneous critical
	 * one, rather than duplicating the batching logic.
	 */
	escalate(alertId: string, finding: Finding, reasoning: string): void {
		this.pending.push({ id: alertId, finding, aiReasoning: reasoning });
		this.schedule();
	}

	private async flush(): Promise<void> {
		const batch = this.pending;
		this.pending = [];
		this.timer = null;
		this.batchStartedAt = null;
		if (batch.length === 0) return;

		if (!this.mailer) {
			console.warn(
				`[alert] ${batch.length} finding(s) queued but email is not configured — see startup warning.`,
			);
			return;
		}

		const subject =
			batch.length === 1
				? `HIDS alert: ${batch[0]!.finding.module} — ${batch[0]!.finding.summary}`
				: `HIDS alert: ${batch.length} findings`;

		const ip = lanIp();
		const linkHeader = ip ? `Dashboard: http://${ip}:${this.port}/\n\n` : "";
		const secret = ip ? getOrCreateLinkSecret(this.db.dataDir) : null;
		const body =
			linkHeader +
			batch
				.map(({ id, finding, aiReasoning }) => {
					const whitelistLine =
						secret && WHITELISTABLE_MODULES.includes(finding.module)
							? `\nWhitelist: http://${ip}:${this.port}/api/whitelist-confirm?id=${id}&token=${signAlertToken(secret, id)}`
							: "";
					// Reasoning content goes on its own following line(s), not inline after the label —
					// the AI is prompted to format it as a bulleted list, and gluing the first bullet
					// onto the same line as "AI reasoning:" reads badly once there's more than one point.
					const reasoningLine = aiReasoning
						? `\nAI reasoning:\n${aiReasoning}`
						: "";
					const detailLines = formatDetailLines(finding.detail).join("\n");
					return `[${finding.module}] ${finding.severity.toUpperCase()}: ${finding.summary}\n${detailLines}${reasoningLine}${whitelistLine}`;
				})
				.join("\n\n---\n\n");

		// HTML companion to the plain-text body above — nodemailer/most email clients prefer this
		// when present, falling back to `text` otherwise. Every value pulled from `finding` or AI
		// output goes through escapeHtml() first: alert detail and AI reasoning can both contain
		// attacker-influenced or model-generated content, and unescaped HTML in an email is a real
		// injection surface, not just a formatting nicety.
		const linkHeaderHtml = ip
			? `<p><strong>Dashboard:</strong> <a href="http://${ip}:${this.port}/">http://${ip}:${this.port}/</a></p>`
			: "";
		const htmlBody =
			linkHeaderHtml +
			batch
				.map(({ id, finding, aiReasoning }) => {
					const whitelistHtml =
						secret && WHITELISTABLE_MODULES.includes(finding.module)
							? `<p><strong>Whitelist:</strong> <a href="http://${ip}:${this.port}/api/whitelist-confirm?id=${id}&token=${signAlertToken(secret, id)}">Whitelist this</a></p>`
							: "";
					const reasoningHtml = aiReasoning
						? `<p><strong>AI reasoning:</strong><br>${escapeHtml(aiReasoning).replace(/\n/g, "<br>")}</p>`
						: "";
					const detailHtml = formatDetailLines(finding.detail)
						.map((line) => escapeHtml(line))
						.join("<br>");
					const headerHtml = `<p><strong>[${escapeHtml(finding.module)}] ${finding.severity.toUpperCase()}:</strong> ${escapeHtml(finding.summary)}</p>`;
					return `${headerHtml}<p>${detailHtml}</p>${reasoningHtml}${whitelistHtml}`;
				})
				.join("<hr>");

		try {
			await this.mailer.send(subject, body, htmlBody);
			for (const { id } of batch) markEmailed(this.db, id);
		} catch (err) {
			console.error("[alert] failed to send alert email:", err);
		}
	}
}

export function safeCreateMailer(
	createMailer: (path: string) => Mailer,
	gmailEnvPath: string,
): Mailer | null {
	try {
		return createMailer(gmailEnvPath);
	} catch (err) {
		if (err instanceof MailerNotConfigured) {
			console.warn(`[startup] ${err.message}`);
			return null;
		}
		throw err;
	}
}
