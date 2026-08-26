import { existsSync } from "node:fs";
import Anthropic from "@anthropic-ai/sdk";
import { loadEnv } from "../alert/email.ts";
import type { Finding } from "../alert/policy.ts";
import type { Module, ModuleContext } from "../modules/types.ts";
import { type Alert, getAlerts } from "../state/history-db.ts";
import {
	getTriagedAlertIds,
	insertVerdict,
	type Verdict,
} from "../state/triage-store.ts";

/**
 * The AI triage layer: reviews warning/info findings that AlertRecorder never emails (see
 * src/alert/policy.ts's severity gate), applies the same judgment framework the archived
 * hids-emails skill used (archive/hids-alert-triage-archived-20260805.md), and escalates
 * genuinely alarming ones to email. Critical findings are also reviewed, but only for
 * dashboard-visible reasoning — they're already emailed instantly by record()/flush(), and this
 * module must never touch that path (async design, confirmed 2026-08-23).
 *
 * Has three real tools available (added 2026-08-23): whois_lookup and reverse_dns_lookup, for
 * checking who/what a public IP resolves to before judging a network finding, and
 * check_package_ownership, for checking whether a suspicious file path belongs to an installed
 * system package before judging a process/fim finding. The model decides when to use each; the
 * *tool-execution* layer (createSystemToolRunners below), not the model's judgment, enforces that
 * inputs actually look like what they claim to be (a real IP, a plausible absolute path) before
 * anything reaches a shell-out process — this matters because alert `detail` fields (and therefore
 * what the model sees) can contain attacker-influenced content, the same prompt-injection surface
 * documented in the SX-AIE plan's Phase 2. Uncertainty that survives a lookup (or a failed lookup)
 * is still explicitly biased toward ALARMING in the prompt below — a false positive costs one
 * extra email, a false negative costs a missed compromise.
 */

const TRIAGE_SYSTEM_PROMPT = `You are a security analyst reviewing findings from a personal Host Intrusion Detection System (HIDS). You have three tools available — whois_lookup and reverse_dns_lookup (who a public IP is registered to / what hostname it resolves to) and check_package_ownership (whether a file path belongs to an installed system package). Use them whenever they would let you decide from real evidence instead of guessing — that's the whole point of having them. For each finding, decide ALARMING or BENIGN using this judgment, most-trusted-first:

- auth module, any finding (failed SSH, accepted SSH, failed sudo): always ALARMING. This host doesn't expect remote logins.
- fim module, tamper-detected finding (a trusted binary's hash changed, or a static watch-path file was modified unexpectedly): always ALARMING. If the finding involves a specific file path, you may use check_package_ownership to see whether that path currently belongs to a legitimate installed package (e.g. reflecting a legitimate reinstall/upgrade) before finalizing your reasoning — but tamper detections stay ALARMING regardless, this only informs your explanation.
- process module (new process from /tmp, /dev/shm, /var/tmp, or a deleted-on-disk binary): default ALARMING unless the finding's own detail concretely explains it. Use check_package_ownership on the binary's path if you have one — a path owned by a legitimate installed package is a strong signal toward BENIGN; a path owned by no package strengthens ALARMING. If you can't verify it concretely, it's ALARMING, not benign-by-assumption.
- network module — the hardest judgment call:
  - A recognized system/desktop component or browser reaching a destination plausible for its own function, with nothing else off about it, is BENIGN.
  - "Known process contacting a new destination" findings deserve real scrutiny — designed to catch a compromised-but-familiar binary, not a rubber stamp.
  - Use whois_lookup and/or reverse_dns_lookup before concluding an unfamiliar network destination is illegitimate — reverse DNS is often more immediately readable (e.g. "resolves to googleusercontent.com"), WHOIS gives you the registrant/organization. If the destination still can't be established as legitimate after checking — or a lookup fails — treat that as ALARMING, not BENIGN. The cost of a false positive is one extra email; the cost of a false negative is a missed compromise.

Once you have enough information to decide, respond with ONLY a JSON object, no other text, no markdown formatting, no code fences:
{"verdict": "alarming" or "benign", "reasoning": "a newline-separated list of short bullet points explaining your judgment, each starting with '- ' — one point per distinct piece of evidence (e.g. one line for what a tool result showed, one line for the module's own judgment rule, etc). A single-point judgment is still one bullet, not a paragraph.", "suggestions": "what to look for or check next, or an empty string if there's nothing further to add"}`;

export interface TriageResult {
	verdict: Extract<Verdict, "alarming" | "benign">;
	reasoning: string;
	suggestions: string;
}

export interface TriageClient {
	judge(alert: Alert): Promise<TriageResult>;
}

export function buildUserMessage(alert: Alert): string {
	return [
		`Module: ${alert.module}`,
		`Severity: ${alert.severity}`,
		`Summary: ${alert.summary}`,
		`Detail: ${JSON.stringify(alert.detail)}`,
	].join("\n");
}

/** Strips optional markdown code fences (models sometimes wrap JSON in ```json...``` despite
 * instructions not to) before parsing, and validates the resulting shape strictly — any
 * deviation returns null, which the caller treats as a fail-safe "unreviewed" verdict rather
 * than guessing at a partial/malformed response. */
export function parseVerdict(raw: string): TriageResult | null {
	const stripped = raw
		.trim()
		.replace(/^```(?:json)?\n?/, "")
		.replace(/\n?```$/, "");

	let parsed: unknown;
	try {
		parsed = JSON.parse(stripped);
	} catch {
		return null;
	}

	if (typeof parsed !== "object" || parsed === null) return null;
	const { verdict, reasoning, suggestions } = parsed as Record<string, unknown>;

	if (verdict !== "alarming" && verdict !== "benign") return null;
	if (typeof reasoning !== "string" || reasoning.length === 0) return null;

	return {
		verdict,
		reasoning,
		suggestions: typeof suggestions === "string" ? suggestions : "",
	};
}

/** Basic IPv4/IPv6 shape validation — this is the real security boundary, not a formality. Called
 * before any string reaches `Bun.spawnSync(["whois", ip])`; rejects hostnames, shell-metacharacter-
 * bearing strings, and anything else that isn't a plausible IP, regardless of how the model arrived
 * at that string. */
export function isValidIp(s: string): boolean {
	const ipv4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
	const v4Match = s.match(ipv4);
	if (v4Match) {
		return v4Match.slice(1, 5).every((octet) => Number(octet) <= 255);
	}
	// Simplified IPv6: hex groups and ":" only, at least one "::" or enough groups — good enough
	// to reject non-IP input without implementing the full RFC 4291 compression grammar.
	const ipv6 = /^[0-9a-fA-F:]+$/;
	return ipv6.test(s) && s.includes(":") && s.length >= 3;
}

/** Sanity check before a path reaches `Bun.spawnSync(["dpkg", "-S", path])` — not primarily a
 * shell-injection concern (args array, not a shell string, is already immune to that), but bounds
 * length and requires an absolute path so the tool does only what it's for. Rejects null bytes
 * outright, since those are never valid in a real filesystem path and Bun.spawnSync (like Node)
 * throws on them anyway — better to fail with a clear "invalid tool input" than a cryptic runtime
 * error deeper in the call stack. */
export function isPlausiblePath(s: string): boolean {
	if (s.length === 0 || s.length > 4096) return false;
	if (s.includes("\0")) return false;
	return s.startsWith("/");
}

/** A tool runner receives the model's raw tool-call input and returns the text to feed back into
 * the conversation. Each runner owns its own input validation — the loop below never inspects
 * `input` itself, it only dispatches by tool name. */
export type ToolRunners = Record<
	string,
	(input: Record<string, unknown>) => Promise<string>
>;

const WHOIS_OUTPUT_MAX_CHARS = 2000;
const DPKG_OUTPUT_MAX_CHARS = 500;

/** The real, system-calling implementations — shells out to `whois`/`dpkg` (matching the existing
 * codebase convention of shelling out to system tools, e.g. `network.ts`'s `ss`, `auth.ts`'s
 * `journalctl`) and uses Node's built-in `dns` module for reverse lookups (no subprocess needed).
 * Kept separate from `runTriageConversation`'s dispatch loop so tests can inject fakes instead. */
export function createSystemToolRunners(): ToolRunners {
	return {
		async whois_lookup(input): Promise<string> {
			const ip = input.ip;
			if (typeof ip !== "string" || !isValidIp(ip)) {
				throw new Error(`Refusing WHOIS lookup on non-IP input: ${String(ip)}`);
			}
			const result = Bun.spawnSync(["whois", ip], { timeout: 10_000 });
			const output = result.stdout.toString();
			return output.length > WHOIS_OUTPUT_MAX_CHARS
				? `${output.slice(0, WHOIS_OUTPUT_MAX_CHARS)}\n...(truncated)`
				: output;
		},

		async reverse_dns_lookup(input): Promise<string> {
			const ip = input.ip;
			if (typeof ip !== "string" || !isValidIp(ip)) {
				throw new Error(
					`Refusing reverse DNS lookup on non-IP input: ${String(ip)}`,
				);
			}
			const dns = await import("node:dns");
			try {
				const hostnames = await dns.promises.reverse(ip);
				return hostnames.length > 0
					? hostnames.join(", ")
					: "No PTR record found for this IP.";
			} catch (err) {
				const code = (err as { code?: string } | undefined)?.code;
				if (code === "ENOTFOUND" || code === "ENODATA") {
					return "No PTR record found for this IP (no reverse DNS entry).";
				}
				throw err;
			}
		},

		async check_package_ownership(input): Promise<string> {
			const path = input.path;
			if (typeof path !== "string" || !isPlausiblePath(path)) {
				throw new Error(
					`Refusing package-ownership check on implausible path: ${String(path)}`,
				);
			}
			const result = Bun.spawnSync(["dpkg", "-S", path], { timeout: 10_000 });
			if (result.exitCode !== 0) {
				return "No installed package owns this path (dpkg -S found no match).";
			}
			const output = result.stdout.toString().trim();
			return output.length > DPKG_OUTPUT_MAX_CHARS
				? `${output.slice(0, DPKG_OUTPUT_MAX_CHARS)}\n...(truncated)`
				: output;
		},
	};
}

const WHOIS_TOOL = {
	name: "whois_lookup",
	description:
		"Look up WHOIS registration details for a public IP address — who it's registered to, what organization/country, hosting vs residential. Use this when you cannot judge whether a network destination is legitimate from the finding's own detail alone.",
	input_schema: {
		type: "object" as const,
		properties: {
			ip: { type: "string" as const, description: "The IP address to look up" },
		},
		required: ["ip"],
	},
};

const DNS_TOOL = {
	name: "reverse_dns_lookup",
	description:
		"Look up the reverse DNS (PTR) hostname for a public IP address — often more immediately readable than raw WHOIS data (e.g. 'googleusercontent.com'). Use alongside or instead of whois_lookup when judging an unfamiliar network destination.",
	input_schema: {
		type: "object" as const,
		properties: {
			ip: { type: "string" as const, description: "The IP address to look up" },
		},
		required: ["ip"],
	},
};

const PACKAGE_TOOL = {
	name: "check_package_ownership",
	description:
		"Check whether a file path is owned by an installed system package (via dpkg). Use this for process or file-integrity findings involving an unfamiliar binary path — if a legitimate installed package owns it, that's a strong signal it isn't malicious; if no package owns it, that strengthens suspicion.",
	input_schema: {
		type: "object" as const,
		properties: {
			path: {
				type: "string" as const,
				description: "The absolute file path to check",
			},
		},
		required: ["path"],
	},
};

const ALL_TOOLS = [WHOIS_TOOL, DNS_TOOL, PACKAGE_TOOL];

/** Minimal shape of what this module actually reads from an Anthropic API response — deliberately
 * looser than the SDK's own `Message` type so tests can script fake multi-turn responses without
 * satisfying every field the real SDK type requires. The real `Anthropic` client's `.messages`
 * structurally satisfies this (its responses are a superset). */
export interface MessagesLike {
	create(params: {
		model: string;
		max_tokens: number;
		system: string;
		tools: unknown[];
		messages: Array<{ role: string; content: unknown }>;
	}): Promise<{ content: Array<Record<string, unknown>> }>;
}

const MAX_TOOL_ROUNDS = 3;

/** The actual tool-calling loop: reasons about a finding, optionally calls one of the available
 * tools one or more times (fed back into the conversation), and returns once the model gives a
 * final verdict with no further tool requests. Exported so tests can inject a fake `messagesApi`
 * and fake tool runners and exercise the loop's turn-taking without touching the real SDK or real
 * system commands. Dispatches purely by tool name — adding a new tool means adding it to
 * `ALL_TOOLS` and to whatever `ToolRunners` map gets passed in, nothing in this loop changes. */
export async function runTriageConversation(
	messagesApi: MessagesLike,
	model: string,
	tools: ToolRunners,
	alert: Alert,
): Promise<TriageResult> {
	const messages: Array<{ role: string; content: unknown }> = [
		{ role: "user", content: buildUserMessage(alert) },
	];

	for (let round = 0; round < MAX_TOOL_ROUNDS; round++) {
		const response = await messagesApi.create({
			model,
			max_tokens: 500,
			system: TRIAGE_SYSTEM_PROMPT,
			tools: ALL_TOOLS,
			messages,
		});

		const toolUseBlocks = response.content.filter((b) => b.type === "tool_use");

		if (toolUseBlocks.length === 0) {
			const textBlock = response.content.find((b) => b.type === "text");
			if (!textBlock || typeof textBlock.text !== "string") {
				throw new Error("Anthropic response contained no text content");
			}
			const result = parseVerdict(textBlock.text);
			if (!result) {
				throw new Error(
					`Could not parse model response as a verdict: ${textBlock.text.slice(0, 200)}`,
				);
			}
			return result;
		}

		messages.push({ role: "assistant", content: response.content });

		const toolResults = [];
		for (const block of toolUseBlocks) {
			const name = block.name as string;
			const runner = tools[name];
			const input = (block.input as Record<string, unknown>) ?? {};
			let resultText: string;
			if (!runner) {
				resultText = `Unknown tool: ${name}`;
			} else {
				try {
					resultText = await runner(input);
				} catch (err) {
					resultText = `${name} failed: ${err instanceof Error ? err.message : String(err)}`;
				}
			}
			toolResults.push({
				type: "tool_result",
				tool_use_id: block.id,
				content: resultText,
			});
		}
		messages.push({ role: "user", content: toolResults });
	}

	throw new Error(
		`Triage conversation exceeded ${MAX_TOOL_ROUNDS} tool-call rounds without a final verdict`,
	);
}

function createAnthropicClient(apiKey: string, model: string): TriageClient {
	const client = new Anthropic({ apiKey });
	const tools = createSystemToolRunners();
	return {
		judge: (alert: Alert) =>
			runTriageConversation(
				client.messages as unknown as MessagesLike,
				model,
				tools,
				alert,
			),
	};
}

export function createTriageModule(
	ctx: ModuleContext,
	clientOverride?: TriageClient,
): Module {
	const { config, db, recorder } = ctx;
	let timer: ReturnType<typeof setInterval> | null = null;
	let client = clientOverride ?? null;

	function getClient(): TriageClient {
		if (client) return client;
		if (!existsSync(config.agent.apiKeyEnvPath)) {
			throw new Error(
				`Anthropic credentials file not found at ${config.agent.apiKeyEnvPath} — triage is disabled until this exists.`,
			);
		}
		const apiKey = loadEnv(config.agent.apiKeyEnvPath).ANTHROPIC_API_KEY;
		if (!apiKey) {
			throw new Error(
				`${config.agent.apiKeyEnvPath} is missing ANTHROPIC_API_KEY.`,
			);
		}
		client = createAnthropicClient(apiKey, config.agent.model);
		return client;
	}

	async function scanNow(): Promise<void> {
		const triaged = getTriagedAlertIds(db);
		// getAlerts() defaults to non-suppressed only — whitelisted noise never reaches this loop.
		const untriaged = getAlerts(db, { limit: 200 }).filter(
			(a) => !triaged.has(a.id),
		);

		for (const alert of untriaged) {
			let result: TriageResult;
			try {
				result = await getClient().judge(alert);
			} catch (err) {
				// Fail-safe: an API failure or unparseable response must never silently drop the
				// finding or be treated as implicit BENIGN. Recorded as "unreviewed" so it still
				// reads as needing a human look, same as if this module didn't exist.
				insertVerdict(db, {
					alertId: alert.id,
					verdict: "unreviewed",
					reasoning: err instanceof Error ? err.message : String(err),
					suggestions: "",
				});
				continue;
			}

			insertVerdict(db, {
				alertId: alert.id,
				verdict: result.verdict,
				reasoning: result.reasoning,
				suggestions: result.suggestions,
			});

			// Critical findings were already emailed instantly by record()/flush() before this
			// module ever ran — escalate() here would be a duplicate email. This pass only adds
			// dashboard-visible reasoning for them (async enrichment, confirmed design).
			if (alert.severity !== "critical" && result.verdict === "alarming") {
				const finding: Finding = {
					module: alert.module,
					severity: alert.severity,
					summary: alert.summary,
					detail: alert.detail,
				};
				recorder.escalate(alert.id, finding, result.reasoning);
			}
		}
	}

	function start(): void {
		if (!config.agent.enabled) return;
		timer = setInterval(() => void scanNow(), config.agent.intervalMs);
	}

	function stop(): void {
		if (timer) clearInterval(timer);
	}

	return { scanNow, start, stop };
}
