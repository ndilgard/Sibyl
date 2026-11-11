import { existsSync, readFileSync } from "node:fs";
import nodemailer from "nodemailer";

/** Port of hal-skeleton's utils/send-alert-email.py: real SMTP send, not a Gmail-API draft.
 * Exported for reuse by other modules reading their own simple KEY=VALUE credential files
 * (e.g. src/agent/triage.ts's Anthropic API key) — same shape, no reason to duplicate this. */
export function loadEnv(path: string): Record<string, string> {
	const env: Record<string, string> = {};
	for (const line of readFileSync(path, "utf-8").split("\n")) {
		const trimmed = line.trim();
		if (!trimmed || trimmed.startsWith("#") || !trimmed.includes("=")) continue;
		const idx = trimmed.indexOf("=");
		env[trimmed.slice(0, idx).trim()] = trimmed.slice(idx + 1).trim();
	}
	return env;
}

export class MailerNotConfigured extends Error {}

export function createMailer(gmailEnvPath: string) {
	if (!existsSync(gmailEnvPath)) {
		throw new MailerNotConfigured(
			`Gmail credentials file not found at ${gmailEnvPath} — email alerts are disabled until this exists.`,
		);
	}
	const env = loadEnv(gmailEnvPath);
	const user = env.GMAIL_SMTP_USER;
	const pass = env.GMAIL_SMTP_APP_PASSWORD;
	if (!user || !pass) {
		throw new MailerNotConfigured(
			`${gmailEnvPath} is missing GMAIL_SMTP_USER or GMAIL_SMTP_APP_PASSWORD.`,
		);
	}

	const transport = nodemailer.createTransport({
		host: "smtp.gmail.com",
		port: 465,
		secure: true,
		auth: { user, pass },
	});

	return {
		async send(subject: string, text: string, html?: string): Promise<void> {
			await transport.sendMail({
				from: user,
				to: user,
				subject,
				text,
				...(html ? { html } : {}),
			});
		},
	};
}

export type Mailer = ReturnType<typeof createMailer>;
