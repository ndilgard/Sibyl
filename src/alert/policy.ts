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
	private pending: { id: string; finding: Finding }[] = [];
	private timer: ReturnType<typeof setTimeout> | null = null;

	constructor(
		private db: HistoryStore,
		private mailer: Mailer | null,
		private debounceMs: number,
		private port: number,
	) {}

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
		if (this.timer) clearTimeout(this.timer);
		this.timer = setTimeout(() => void this.flush(), this.debounceMs);
	}

	private async flush(): Promise<void> {
		const batch = this.pending;
		this.pending = [];
		this.timer = null;
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
				.map(({ id, finding }) => {
					const whitelistLine =
						secret && WHITELISTABLE_MODULES.includes(finding.module)
							? `\nWhitelist: http://${ip}:${this.port}/api/whitelist-confirm?id=${id}&token=${signAlertToken(secret, id)}`
							: "";
					const detailLines = formatDetailLines(finding.detail).join("\n");
					return `[${finding.module}] ${finding.severity.toUpperCase()}: ${finding.summary}\n${detailLines}${whitelistLine}`;
				})
				.join("\n\n---\n\n");

		try {
			await this.mailer.send(subject, body);
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
