import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	getAlerts,
	type HistoryStore,
	openHistoryDb,
} from "../state/history-db.ts";
import { addWhitelistRule } from "../state/whitelist-store.ts";
import type { Mailer } from "./email.ts";
import { AlertRecorder, type Finding } from "./policy.ts";

let db: HistoryStore;

function mockMailer() {
	const sent: { subject: string; body: string; html?: string }[] = [];
	const mailer: Mailer = {
		async send(subject, text, html) {
			sent.push({ subject, body: text, html });
		},
	};
	return { mailer, sent };
}

function finding(overrides: Partial<Finding> = {}): Finding {
	return {
		module: "network",
		severity: "warning",
		summary: "test finding",
		detail: { exePath: "/usr/bin/test" },
		...overrides,
	};
}

beforeEach(() => {
	db = openHistoryDb(mkdtempSync(join(tmpdir(), "hids-test-")));
});

afterEach(() => {
	rmSync(db.dataDir, { recursive: true, force: true });
});

describe("AlertRecorder — severity-gated email", () => {
	test("a critical finding is emailed", async () => {
		const { mailer, sent } = mockMailer();
		const recorder = new AlertRecorder(db, mailer, 5, 0);
		recorder.record(
			finding({ severity: "critical", summary: "critical thing" }),
		);
		await Bun.sleep(20);
		expect(sent).toHaveLength(1);
		expect(sent[0]!.subject).toContain("critical thing");
	});

	test("a warning finding is recorded but never emailed", async () => {
		const { mailer, sent } = mockMailer();
		const recorder = new AlertRecorder(db, mailer, 5, 0);
		recorder.record(finding({ severity: "warning", summary: "warning thing" }));
		await Bun.sleep(20);
		expect(sent).toHaveLength(0);
		const alerts = getAlerts(db, { module: "network" });
		expect(alerts).toHaveLength(1);
		expect(alerts[0]!.summary).toBe("warning thing");
	});

	test("an info finding is recorded but never emailed", async () => {
		const { mailer, sent } = mockMailer();
		const recorder = new AlertRecorder(db, mailer, 5, 0);
		recorder.record(finding({ severity: "info", summary: "info thing" }));
		await Bun.sleep(20);
		expect(sent).toHaveLength(0);
		expect(getAlerts(db, { module: "network" })).toHaveLength(1);
	});

	test("a mixed batch only emails the critical finding, not the warning alongside it", async () => {
		const { mailer, sent } = mockMailer();
		const recorder = new AlertRecorder(db, mailer, 20, 0);
		recorder.record(finding({ severity: "warning", summary: "noisy warning" }));
		recorder.record(
			finding({ severity: "critical", summary: "the real thing" }),
		);
		await Bun.sleep(40);
		expect(sent).toHaveLength(1);
		expect(sent[0]!.body).toContain("the real thing");
		expect(sent[0]!.body).not.toContain("noisy warning");
		// Both still land in the alert store for the dashboard, regardless of email routing.
		expect(getAlerts(db, { module: "network" })).toHaveLength(2);
	});

	test("a whitelisted critical finding is still suppressed, not emailed", async () => {
		const { mailer, sent } = mockMailer();
		addWhitelistRule(db, {
			module: "network",
			field: "exePath",
			value: "/usr/bin/test",
		});
		const recorder = new AlertRecorder(db, mailer, 5, 0);
		recorder.record(
			finding({ severity: "critical", detail: { exePath: "/usr/bin/test" } }),
		);
		await Bun.sleep(20);
		expect(sent).toHaveLength(0);
		const [alert] = getAlerts(db, { module: "network", suppressed: true });
		expect(alert?.suppressed).toBe(true);
	});

	test("with no mailer configured, a critical finding is still recorded without throwing", async () => {
		const recorder = new AlertRecorder(db, null, 5, 0);
		expect(() =>
			recorder.record(finding({ severity: "critical" })),
		).not.toThrow();
		await Bun.sleep(20);
		expect(getAlerts(db, { module: "network" })).toHaveLength(1);
	});

	test("a sustained stream of criticals arriving faster than the debounce window still flushes, instead of being starved forever", async () => {
		// Reproduces the real incident: a still-running process re-triggered a critical every 10s
		// against a 45s debounce — each new finding reset the trailing timer before it could fire,
		// so flush() (and the email) never ran. debounceMs=10 here means the stream (every 5ms) is
		// well inside debounceMs, so without the maxWait cap this would never flush.
		const { mailer, sent } = mockMailer();
		const recorder = new AlertRecorder(db, mailer, 10, 0);
		const interval = setInterval(() => {
			recorder.record(
				finding({ severity: "critical", summary: "repeating critical" }),
			);
		}, 5);
		// Assert WHILE the stream is still ongoing (interval keeps firing every 5ms, faster than
		// the 10ms debounce) — a plain trailing debounce would still be getting reset by every new
		// finding at this point and would have sent nothing yet. maxWaitMs (debounceMs * 3 = 30ms)
		// guarantees at least one flush by t=40ms even though findings never stopped arriving.
		await Bun.sleep(40);
		expect(sent.length).toBeGreaterThanOrEqual(1);
		clearInterval(interval);
		// Let the trailing debounce settle so no timer from this test leaks into the next one.
		await Bun.sleep(30);
	});
});

describe("AlertRecorder.escalate — AI-triaged warning/info findings", () => {
	test("escalating a warning finding sends an email, unlike a plain record()", async () => {
		const { mailer, sent } = mockMailer();
		const recorder = new AlertRecorder(db, mailer, 5, 0);
		const f = finding({
			severity: "warning",
			summary: "was warning, now alarming",
		});
		// simulate: the finding was already recorded earlier as a plain warning (no email)
		recorder.record(f);
		await Bun.sleep(20);
		expect(sent).toHaveLength(0);
		const [existing] = getAlerts(db, { module: "network" });

		recorder.escalate(
			existing!.id,
			f,
			"AI judged this alarming: never-seen destination",
		);
		await Bun.sleep(20);
		expect(sent).toHaveLength(1);
		expect(sent[0]!.subject).toContain("was warning, now alarming");
	});

	test("the email body includes the AI's reasoning", async () => {
		const { mailer, sent } = mockMailer();
		const recorder = new AlertRecorder(db, mailer, 5, 0);
		recorder.escalate(
			"some-existing-alert-id",
			finding({ severity: "info", summary: "escalated info finding" }),
			"never-seen destination in a foreign ASN, flagged as alarming",
		);
		await Bun.sleep(20);
		expect(sent[0]!.body).toContain("foreign ASN");
	});

	test("multi-line (bulleted) reasoning keeps each line intact in the email body", async () => {
		const { mailer, sent } = mockMailer();
		const recorder = new AlertRecorder(db, mailer, 5, 0);
		const bulletedReasoning = [
			"- No installed package owns this path",
			"- WHOIS shows a hosting provider with no legitimate reason to be contacted",
			"- No reverse DNS entry",
		].join("\n");
		recorder.escalate(
			"some-existing-alert-id",
			finding({ severity: "warning", summary: "multi-point finding" }),
			bulletedReasoning,
		);
		await Bun.sleep(20);
		const body = sent[0]!.body;
		expect(body).toContain(
			"AI reasoning:\n- No installed package owns this path",
		);
		expect(body).toContain("- WHOIS shows a hosting provider");
		expect(body).toContain("- No reverse DNS entry");
	});

	test("escalate does not insert a duplicate alert row", async () => {
		const { mailer } = mockMailer();
		const recorder = new AlertRecorder(db, mailer, 5, 0);
		recorder.record(finding({ severity: "warning", summary: "dup check" }));
		await Bun.sleep(20);
		const [existing] = getAlerts(db, { module: "network" });
		expect(getAlerts(db, { module: "network" })).toHaveLength(1);

		recorder.escalate(
			existing!.id,
			finding({ severity: "warning" }),
			"alarming",
		);
		await Bun.sleep(20);
		// still exactly one row — escalate() reused the existing alert id, didn't insert a new one
		expect(getAlerts(db, { module: "network" })).toHaveLength(1);
	});

	test("escalate batches with a simultaneous critical finding into one email", async () => {
		const { mailer, sent } = mockMailer();
		const recorder = new AlertRecorder(db, mailer, 20, 0);
		recorder.record(
			finding({ severity: "critical", summary: "real critical" }),
		);
		recorder.escalate(
			"warning-alert-id",
			finding({ severity: "warning", summary: "AI-escalated warning" }),
			"alarming per AI",
		);
		await Bun.sleep(40);
		expect(sent).toHaveLength(1);
		expect(sent[0]!.body).toContain("real critical");
		expect(sent[0]!.body).toContain("AI-escalated warning");
	});
});

describe("AlertRecorder — HTML email body", () => {
	test("a critical finding's HTML body bolds the header and includes the summary", async () => {
		const { mailer, sent } = mockMailer();
		const recorder = new AlertRecorder(db, mailer, 5, 0);
		recorder.record(
			finding({ severity: "critical", summary: "tampering detected" }),
		);
		await Bun.sleep(20);
		const html = sent[0]!.html;
		expect(html).toBeDefined();
		expect(html).toContain("<strong>");
		expect(html).toContain("tampering detected");
	});

	test("AI reasoning section is bolded and separated as its own block", async () => {
		const { mailer, sent } = mockMailer();
		const recorder = new AlertRecorder(db, mailer, 5, 0);
		recorder.escalate(
			"some-id",
			finding({ severity: "warning", summary: "escalated" }),
			"- point one\n- point two",
		);
		await Bun.sleep(20);
		const html = sent[0]!.html!;
		expect(html).toContain("<strong>AI reasoning:</strong>");
		expect(html).toContain("point one");
		expect(html).toContain("point two");
	});

	test("a whitelistable module's HTML body bolds the Whitelist label", async () => {
		const { mailer, sent } = mockMailer();
		const recorder = new AlertRecorder(db, mailer, 5, 0);
		recorder.record(finding({ severity: "critical" }));
		await Bun.sleep(20);
		const html = sent[0]!.html!;
		expect(html).toContain("<strong>Whitelist:</strong>");
	});

	test("hostile content in the summary is HTML-escaped, not rendered as raw markup", async () => {
		const { mailer, sent } = mockMailer();
		const recorder = new AlertRecorder(db, mailer, 5, 0);
		recorder.record(
			finding({
				severity: "critical",
				summary: "<script>alert(1)</script>",
			}),
		);
		await Bun.sleep(20);
		const html = sent[0]!.html!;
		expect(html).not.toContain("<script>alert(1)</script>");
		expect(html).toContain("&lt;script&gt;");
	});

	test("multiple sections render as separate <p> blocks, not one run-on paragraph", async () => {
		const { mailer, sent } = mockMailer();
		const recorder = new AlertRecorder(db, mailer, 5, 0);
		recorder.escalate(
			"some-id",
			finding({ severity: "warning" }),
			"reasoning text",
		);
		await Bun.sleep(20);
		const html = sent[0]!.html!;
		// At minimum: header paragraph, detail paragraph, reasoning paragraph, whitelist paragraph.
		const pCount = (html.match(/<p>/g) ?? []).length;
		expect(pCount).toBeGreaterThanOrEqual(3);
	});
});
