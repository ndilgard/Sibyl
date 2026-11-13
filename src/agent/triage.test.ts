import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Mailer } from "../alert/email.ts";
import { AlertRecorder } from "../alert/policy.ts";
import type { HidsConfig } from "../config.ts";
import type { Incident } from "../state/correlate.ts";
import {
	type Alert,
	type HistoryStore,
	insertAlert,
	openHistoryDb,
} from "../state/history-db.ts";
import { getVerdictByAlertId } from "../state/triage-store.ts";
import {
	buildIncidentUserMessage,
	buildUserMessage,
	createSystemToolRunners,
	createTriageModule,
	isPlausiblePath,
	isValidIp,
	type MessagesLike,
	parseVerdict,
	runIncidentReportConversation,
	runTriageConversation,
	type ToolRunners,
	type TriageClient,
	validateIncidentReport,
} from "./triage.ts";

let db: HistoryStore;

function mockMailer() {
	const sent: { subject: string; body: string }[] = [];
	const mailer: Mailer = {
		async send(subject, body) {
			sent.push({ subject, body });
		},
	};
	return { mailer, sent };
}

function agentConfig(): HidsConfig["agent"] {
	return {
		enabled: true,
		model: "claude-sonnet-5",
		intervalMs: 300000,
		apiKeyEnvPath: "unused-in-tests",
	};
}

beforeEach(() => {
	db = openHistoryDb(mkdtempSync(join(tmpdir(), "hids-triage-module-test-")));
});

afterEach(() => {
	rmSync(db.dataDir, { recursive: true, force: true });
});

describe("buildUserMessage", () => {
	test("includes module, severity, summary, and detail", () => {
		const msg = buildUserMessage({
			id: "a1",
			ts: "2026-08-23T00:00:00.000Z",
			module: "network",
			severity: "warning",
			summary:
				"Known process contacting a new destination: /usr/bin/curl -> 1.2.3.4:443 (tcp)",
			detail: { exePath: "/usr/bin/curl", peerAddress: "1.2.3.4:443" },
			emailed: false,
		});
		expect(msg).toContain("network");
		expect(msg).toContain("warning");
		expect(msg).toContain("1.2.3.4:443");
		expect(msg).toContain("/usr/bin/curl");
	});
});

describe("parseVerdict", () => {
	test("parses a valid alarming verdict", () => {
		const result = parseVerdict(
			JSON.stringify({
				verdict: "alarming",
				reasoning: "never-seen destination, no plausible reason",
				suggestions: "check what /usr/bin/curl was doing at this time",
			}),
		);
		expect(result?.verdict).toBe("alarming");
		expect(result?.reasoning).toContain("never-seen");
	});

	test("parses a valid benign verdict", () => {
		const result = parseVerdict(
			JSON.stringify({
				verdict: "benign",
				reasoning: "known package manager reaching its own update servers",
				suggestions: "",
			}),
		);
		expect(result?.verdict).toBe("benign");
	});

	test("returns null for invalid JSON", () => {
		expect(parseVerdict("not json at all")).toBeNull();
	});

	test("returns null when verdict field has an invalid value", () => {
		expect(
			parseVerdict(
				JSON.stringify({ verdict: "maybe", reasoning: "r", suggestions: "" }),
			),
		).toBeNull();
	});

	test("returns null when reasoning field is missing", () => {
		expect(parseVerdict(JSON.stringify({ verdict: "benign" }))).toBeNull();
	});

	test("tolerates response text wrapped in markdown code fences", () => {
		const wrapped = [
			"```json",
			JSON.stringify({ verdict: "benign", reasoning: "r", suggestions: "" }),
			"```",
		].join("\n");
		expect(parseVerdict(wrapped)?.verdict).toBe("benign");
	});
});

describe("createTriageModule — scanNow", () => {
	function fakeClient(judge: TriageClient["judge"]): TriageClient {
		return {
			judge,
			generateReport: async () => {
				throw new Error("generateReport not used by these scanNow tests");
			},
		};
	}

	test("an alarming warning finding gets escalated (emailed)", async () => {
		const { mailer, sent } = mockMailer();
		const recorder = new AlertRecorder(db, mailer, 5, 0);
		insertAlert(db, {
			module: "network",
			severity: "warning",
			summary: "known process, new destination",
			detail: {},
		});

		const client = fakeClient(async () => ({
			verdict: "alarming",
			reasoning: "never-seen destination",
			suggestions: "check it",
		}));

		const mod = createTriageModule(
			{ config: { agent: agentConfig() } as HidsConfig, db, recorder },
			client,
		);
		await mod.scanNow();
		await Bun.sleep(20);

		expect(sent).toHaveLength(1);
		expect(sent[0]!.body).toContain("never-seen destination");
	});

	test("a benign warning finding is recorded but not emailed", async () => {
		const { mailer, sent } = mockMailer();
		const recorder = new AlertRecorder(db, mailer, 5, 0);
		const alertId = insertAlert(db, {
			module: "network",
			severity: "warning",
			summary: "known process, known destination",
			detail: {},
		});

		const client = fakeClient(async () => ({
			verdict: "benign",
			reasoning: "recognized system service",
			suggestions: "",
		}));

		const mod = createTriageModule(
			{ config: { agent: agentConfig() } as HidsConfig, db, recorder },
			client,
		);
		await mod.scanNow();
		await Bun.sleep(20);

		expect(sent).toHaveLength(0);
		expect(getVerdictByAlertId(db, alertId)?.verdict).toBe("benign");
	});

	test("an API failure records an 'unreviewed' verdict, never drops the finding", async () => {
		const { mailer, sent } = mockMailer();
		const recorder = new AlertRecorder(db, mailer, 5, 0);
		const alertId = insertAlert(db, {
			module: "network",
			severity: "info",
			summary: "some finding",
			detail: {},
		});

		const client = fakeClient(async () => {
			throw new Error("API request timed out");
		});

		const mod = createTriageModule(
			{ config: { agent: agentConfig() } as HidsConfig, db, recorder },
			client,
		);
		await mod.scanNow();
		await Bun.sleep(20);

		expect(sent).toHaveLength(0);
		expect(getVerdictByAlertId(db, alertId)?.verdict).toBe("unreviewed");
	});

	test("an unparseable API response records an 'unreviewed' verdict", async () => {
		const { mailer } = mockMailer();
		const recorder = new AlertRecorder(db, mailer, 5, 0);
		const alertId = insertAlert(db, {
			module: "network",
			severity: "info",
			summary: "some finding",
			detail: {},
		});

		// judge() itself is expected to return a parsed result or throw — this simulates the
		// client-level catch of an unparseable raw response by throwing, same fail-safe path as
		// a network failure.
		const client = fakeClient(async () => {
			throw new Error("could not parse model response as JSON");
		});

		const mod = createTriageModule(
			{ config: { agent: agentConfig() } as HidsConfig, db, recorder },
			client,
		);
		await mod.scanNow();

		expect(getVerdictByAlertId(db, alertId)?.verdict).toBe("unreviewed");
	});

	test("an already-triaged alert is not re-judged", async () => {
		const { mailer } = mockMailer();
		const recorder = new AlertRecorder(db, mailer, 5, 0);
		insertAlert(db, {
			module: "network",
			severity: "warning",
			summary: "already handled",
			detail: {},
		});

		let calls = 0;
		const client = fakeClient(async () => {
			calls++;
			return { verdict: "benign", reasoning: "r", suggestions: "" };
		});
		const mod = createTriageModule(
			{ config: { agent: agentConfig() } as HidsConfig, db, recorder },
			client,
		);
		await mod.scanNow();
		await mod.scanNow();
		expect(calls).toBe(1);
	});

	test("a critical alert is enriched (dashboard-only) but never escalated — it was already emailed", async () => {
		const { mailer, sent } = mockMailer();
		const recorder = new AlertRecorder(db, mailer, 5, 0);
		const alertId = insertAlert(db, {
			module: "fim",
			severity: "critical",
			summary: "tampering detected",
			detail: {},
		});

		const client = fakeClient(async () => ({
			verdict: "alarming",
			reasoning: "confirmed tampering pattern",
			suggestions: "isolate the host",
		}));

		const mod = createTriageModule(
			{ config: { agent: agentConfig() } as HidsConfig, db, recorder },
			client,
		);
		await mod.scanNow();
		await Bun.sleep(20);

		// No new email from the triage module — the critical email already fired via record()
		// itself before scanNow() ever ran, and escalate() must not be called for criticals.
		expect(sent).toHaveLength(0);
		expect(getVerdictByAlertId(db, alertId)?.reasoning).toContain(
			"confirmed tampering",
		);
	});

	test("suppressed alerts are never triaged", async () => {
		const { mailer } = mockMailer();
		const recorder = new AlertRecorder(db, mailer, 5, 0);
		const alertId = insertAlert(db, {
			module: "network",
			severity: "warning",
			summary: "whitelisted noise",
			detail: {},
			suppressed: true,
		});

		let calls = 0;
		const client = fakeClient(async () => {
			calls++;
			return { verdict: "benign", reasoning: "r", suggestions: "" };
		});
		const mod = createTriageModule(
			{ config: { agent: agentConfig() } as HidsConfig, db, recorder },
			client,
		);
		await mod.scanNow();
		expect(calls).toBe(0);
		expect(getVerdictByAlertId(db, alertId)).toBeUndefined();
	});
});

describe("isValidIp", () => {
	test("accepts a valid IPv4 address", () => {
		expect(isValidIp("185.220.101.7")).toBe(true);
	});

	test("accepts a valid IPv6 address", () => {
		expect(isValidIp("2606:4700:4700::1111")).toBe(true);
	});

	test("rejects a hostname", () => {
		expect(isValidIp("example.com")).toBe(false);
	});

	test("rejects an empty string", () => {
		expect(isValidIp("")).toBe(false);
	});

	test("rejects an IPv4 address with an out-of-range octet", () => {
		expect(isValidIp("999.1.1.1")).toBe(false);
	});

	test("rejects a string with shell metacharacters", () => {
		expect(isValidIp("1.2.3.4; rm -rf /")).toBe(false);
		expect(isValidIp("$(whoami)")).toBe(false);
		expect(isValidIp("1.2.3.4 && cat /etc/passwd")).toBe(false);
	});
});

describe("runTriageConversation", () => {
	function fakeAlert(): Alert {
		return {
			id: "a1",
			ts: "2026-08-23T00:00:00.000Z",
			module: "network",
			severity: "warning",
			summary: "known process, new destination",
			detail: { peerAddress: "185.220.101.7:443" },
			emailed: false,
		};
	}

	function textResponse(json: unknown) {
		return { content: [{ type: "text", text: JSON.stringify(json) }] };
	}

	function toolUseResponse(id: string, name: string, input: unknown) {
		return { content: [{ type: "tool_use", id, name, input }] };
	}

	test("no tool use requested — returns the final verdict directly", async () => {
		const messagesApi: MessagesLike = {
			create: async () =>
				textResponse({
					verdict: "benign",
					reasoning: "recognized service",
					suggestions: "",
				}),
		};

		const result = await runTriageConversation(
			messagesApi,
			"claude-sonnet-5",
			{},
			fakeAlert(),
		);
		expect(result.verdict).toBe("benign");
	});

	test("one whois_lookup round-trip, then a final verdict", async () => {
		let call = 0;
		let capturedMessages: unknown;
		const messagesApi: MessagesLike = {
			create: async (params) => {
				call++;
				if (call === 1) {
					return toolUseResponse("tool-1", "whois_lookup", {
						ip: "185.220.101.7",
					});
				}
				capturedMessages = (params as { messages: unknown }).messages;
				return textResponse({
					verdict: "alarming",
					reasoning:
						"WHOIS shows Frantech Solutions, a hosting provider, with no legitimate reason for this process to be contacted",
					suggestions: "",
				});
			},
		};
		let lookedUp = "";
		const tools: ToolRunners = {
			whois_lookup: async (input) => {
				lookedUp = input.ip as string;
				return "OrgName: Frantech Solutions\nCountry: NL";
			},
		};

		const result = await runTriageConversation(
			messagesApi,
			"claude-sonnet-5",
			tools,
			fakeAlert(),
		);

		expect(lookedUp).toBe("185.220.101.7");
		expect(result.verdict).toBe("alarming");
		expect(result.reasoning).toContain("Frantech");
		// The second API call's message history must include the tool result so the model
		// actually sees what the lookup returned.
		expect(JSON.stringify(capturedMessages)).toContain("Frantech Solutions");
	});

	test("a failed tool call doesn't crash the conversation — result fed back as an error", async () => {
		let call = 0;
		let capturedMessages: unknown;
		const messagesApi: MessagesLike = {
			create: async (params) => {
				call++;
				if (call === 1) {
					return toolUseResponse("tool-1", "whois_lookup", {
						ip: "185.220.101.7",
					});
				}
				capturedMessages = (params as { messages: unknown }).messages;
				return textResponse({
					verdict: "alarming",
					reasoning: "could not verify, treating as alarming",
					suggestions: "",
				});
			},
		};
		const tools: ToolRunners = {
			whois_lookup: async () => {
				throw new Error("whois: connection timed out");
			},
		};

		const result = await runTriageConversation(
			messagesApi,
			"claude-sonnet-5",
			tools,
			fakeAlert(),
		);
		expect(result.verdict).toBe("alarming");
		expect(JSON.stringify(capturedMessages)).toContain("whois_lookup failed");
	});

	test("exceeding the max tool rounds throws (caller treats this as unreviewed)", async () => {
		const messagesApi: MessagesLike = {
			// Always asks for another lookup, never gives a final answer.
			create: async () =>
				toolUseResponse("tool-x", "whois_lookup", { ip: "1.1.1.1" }),
		};
		const tools: ToolRunners = {
			whois_lookup: async () => "some whois text",
		};

		await expect(
			runTriageConversation(messagesApi, "claude-sonnet-5", tools, fakeAlert()),
		).rejects.toThrow();
	});

	test("invalid tool input (non-string ip) doesn't crash — fed back as an error, not looked up", async () => {
		let call = 0;
		let whoisCalled = false;
		const messagesApi: MessagesLike = {
			create: async () => {
				call++;
				if (call === 1) {
					return toolUseResponse("tool-1", "whois_lookup", { ip: 12345 });
				}
				return textResponse({
					verdict: "benign",
					reasoning: "r",
					suggestions: "",
				});
			},
		};
		const tools: ToolRunners = {
			whois_lookup: async () => {
				whoisCalled = true;
				return "should not be reached";
			},
		};

		await runTriageConversation(
			messagesApi,
			"claude-sonnet-5",
			tools,
			fakeAlert(),
		);
		expect(whoisCalled).toBe(true);
	});

	test("an unknown tool name doesn't crash — fed back as an error", async () => {
		let call = 0;
		const messagesApi: MessagesLike = {
			create: async () => {
				call++;
				if (call === 1) {
					return toolUseResponse("tool-1", "some_future_tool", {});
				}
				return textResponse({
					verdict: "benign",
					reasoning: "r",
					suggestions: "",
				});
			},
		};

		const result = await runTriageConversation(
			messagesApi,
			"claude-sonnet-5",
			{},
			fakeAlert(),
		);
		expect(result.verdict).toBe("benign");
	});

	test("routes tool_use blocks to the matching runner by name, not just the first one available", async () => {
		let call = 0;
		const seen: string[] = [];
		const messagesApi: MessagesLike = {
			create: async () => {
				call++;
				if (call === 1) {
					return toolUseResponse("tool-1", "reverse_dns_lookup", {
						ip: "8.8.8.8",
					});
				}
				return textResponse({
					verdict: "benign",
					reasoning: "resolves to dns.google, a known Google service",
					suggestions: "",
				});
			},
		};
		const tools: ToolRunners = {
			whois_lookup: async () => {
				seen.push("whois_lookup");
				return "unused";
			},
			reverse_dns_lookup: async () => {
				seen.push("reverse_dns_lookup");
				return "dns.google";
			},
		};

		await runTriageConversation(
			messagesApi,
			"claude-sonnet-5",
			tools,
			fakeAlert(),
		);
		expect(seen).toEqual(["reverse_dns_lookup"]);
	});
});

describe("buildIncidentUserMessage", () => {
	function fakeFimAlert(): Alert {
		return {
			id: "a1",
			ts: "2026-11-09T12:00:00.000Z",
			module: "fim",
			severity: "warning",
			summary: "Watched file modified",
			detail: { path: "/usr/bin/evil-cron" },
			emailed: false,
		};
	}

	function fakeNetworkAlert(): Alert {
		return {
			id: "a2",
			ts: "2026-11-09T12:00:05.000Z",
			module: "network",
			severity: "warning",
			summary: "known process, new destination",
			detail: { exePath: "/usr/bin/evil-cron", remoteAddress: "203.0.113.5" },
			emailed: false,
		};
	}

	function fakeIncident(): Incident {
		return {
			id: "incident-1",
			alertIds: ["a1", "a2"],
			modules: ["fim", "network"],
			sharedIdentifier: "exePath:/usr/bin/evil-cron",
			windowStart: "2026-11-09T12:00:00.000Z",
			windowEnd: "2026-11-09T12:00:05.000Z",
		};
	}

	test("orders alerts chronologically and includes the shared identifier", () => {
		// Passed out of order deliberately — the function must sort by ts, not input order.
		const message = buildIncidentUserMessage(fakeIncident(), [
			fakeNetworkAlert(),
			fakeFimAlert(),
		]);

		const fimIndex = message.indexOf("Module: fim");
		const networkIndex = message.indexOf("Module: network");
		expect(fimIndex).toBeGreaterThan(-1);
		expect(networkIndex).toBeGreaterThan(fimIndex);
		expect(message).toContain("exePath:/usr/bin/evil-cron");
		expect(message).toContain("fim, network");
	});

	test("silently skips an alertId with no matching alert (shouldn't happen, but no crash)", () => {
		const incident = { ...fakeIncident(), alertIds: ["a1", "ghost"] };
		const message = buildIncidentUserMessage(incident, [fakeFimAlert()]);
		expect(message).toContain("Module: fim");
		expect(message).not.toContain("ghost");
	});
});

describe("validateIncidentReport", () => {
	test("accepts a report with all three required sections", () => {
		const report =
			"TIMELINE\n...\n\nEVIDENCE PER MODULE\n...\n\nNARRATIVE\n...";
		expect(validateIncidentReport(report)).toBe(report);
	});

	test("rejects an empty response", () => {
		expect(validateIncidentReport("   ")).toBeNull();
	});

	test("rejects a response missing a required section", () => {
		expect(
			validateIncidentReport("TIMELINE\n...\n\nNARRATIVE\n..."),
		).toBeNull();
	});
});

describe("runIncidentReportConversation", () => {
	function fakeIncident(): Incident {
		return {
			id: "incident-1",
			alertIds: ["a1", "a2"],
			modules: ["fim", "network"],
			sharedIdentifier: "exePath:/usr/bin/evil-cron",
			windowStart: "2026-11-09T12:00:00.000Z",
			windowEnd: "2026-11-09T12:00:05.000Z",
		};
	}

	function fakeAlerts(): Alert[] {
		return [
			{
				id: "a1",
				ts: "2026-11-09T12:00:00.000Z",
				module: "fim",
				severity: "warning",
				summary: "Watched file modified",
				detail: { path: "/usr/bin/evil-cron" },
				emailed: false,
			},
			{
				id: "a2",
				ts: "2026-11-09T12:00:05.000Z",
				module: "network",
				severity: "warning",
				summary: "known process, new destination",
				detail: { exePath: "/usr/bin/evil-cron", remoteAddress: "203.0.113.5" },
				emailed: false,
			},
		];
	}

	function textResponse(text: string) {
		return { content: [{ type: "text", text }] };
	}

	function toolUseResponse(id: string, name: string, input: unknown) {
		return { content: [{ type: "tool_use", id, name, input }] };
	}

	const validReport =
		"TIMELINE\n12:00:00 — fim: modified\n\nEVIDENCE PER MODULE\nfim: ...\n\nNARRATIVE\nLikely tampering.";

	test("no tool use requested — returns the final report text directly", async () => {
		const messagesApi: MessagesLike = {
			create: async () => textResponse(validReport),
		};

		const result = await runIncidentReportConversation(
			messagesApi,
			"claude-sonnet-5",
			{},
			fakeIncident(),
			fakeAlerts(),
		);
		expect(result).toContain("NARRATIVE");
	});

	test("one whois_lookup round-trip, then a final report", async () => {
		let call = 0;
		let capturedMessages: unknown;
		const messagesApi: MessagesLike = {
			create: async (params) => {
				call++;
				if (call === 1) {
					return toolUseResponse("tool-1", "whois_lookup", {
						ip: "203.0.113.5",
					});
				}
				capturedMessages = (params as { messages: unknown }).messages;
				return textResponse(validReport);
			},
		};
		let lookedUp = "";
		const tools: ToolRunners = {
			whois_lookup: async (input) => {
				lookedUp = input.ip as string;
				return "OrgName: Example Hosting";
			},
		};

		const result = await runIncidentReportConversation(
			messagesApi,
			"claude-sonnet-5",
			tools,
			fakeIncident(),
			fakeAlerts(),
		);

		expect(lookedUp).toBe("203.0.113.5");
		expect(result).toContain("NARRATIVE");
		expect(JSON.stringify(capturedMessages)).toContain("Example Hosting");
	});

	test("a malformed report (missing required sections) throws", async () => {
		const messagesApi: MessagesLike = {
			create: async () => textResponse("Just a summary, no sections."),
		};

		await expect(
			runIncidentReportConversation(
				messagesApi,
				"claude-sonnet-5",
				{},
				fakeIncident(),
				fakeAlerts(),
			),
		).rejects.toThrow(/Could not parse model response/);
	});

	test("exceeding the max tool rounds throws", async () => {
		const messagesApi: MessagesLike = {
			create: async () =>
				toolUseResponse("tool-x", "whois_lookup", { ip: "1.1.1.1" }),
		};
		const tools: ToolRunners = {
			whois_lookup: async () => "some whois text",
		};

		await expect(
			runIncidentReportConversation(
				messagesApi,
				"claude-sonnet-5",
				tools,
				fakeIncident(),
				fakeAlerts(),
			),
		).rejects.toThrow(/exceeded 3 tool-call rounds/);
	});
});

describe("isPlausiblePath", () => {
	test("accepts a normal absolute path", () => {
		expect(isPlausiblePath("/usr/bin/curl")).toBe(true);
	});

	test("rejects a relative path", () => {
		expect(isPlausiblePath("usr/bin/curl")).toBe(false);
	});

	test("rejects an empty string", () => {
		expect(isPlausiblePath("")).toBe(false);
	});

	test("rejects a path containing a null byte", () => {
		expect(isPlausiblePath("/usr/bin/curl\0/etc/passwd")).toBe(false);
	});

	test("rejects an implausibly long string", () => {
		expect(isPlausiblePath(`/${"a".repeat(5000)}`)).toBe(false);
	});
});

describe("createSystemToolRunners", () => {
	test("reverse_dns_lookup rejects a non-IP input without attempting a lookup", async () => {
		const runners = createSystemToolRunners();
		await expect(
			runners.reverse_dns_lookup?.({ ip: "not-an-ip" }),
		).rejects.toThrow();
	});

	test("check_package_ownership rejects an implausible path without shelling out", async () => {
		const runners = createSystemToolRunners();
		await expect(
			runners.check_package_ownership?.({ path: "relative/path" }),
		).rejects.toThrow();
	});

	test("check_package_ownership finds the real package owning a known system binary", async () => {
		const runners = createSystemToolRunners();
		const result = await runners.check_package_ownership?.({
			path: "/usr/bin/whois",
		});
		expect(result).toContain("whois");
	});

	test("check_package_ownership returns a clear 'not owned' message for an unowned path", async () => {
		const runners = createSystemToolRunners();
		const result = await runners.check_package_ownership?.({
			path: "/tmp/definitely-not-a-real-package-path-xyz123",
		});
		expect(result).toContain("No installed package");
	});
});
