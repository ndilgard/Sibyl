import { upsertScanStatus } from "../state/history-db.ts";
import { readJson, writeJsonAtomic } from "../state/json-store.ts";
import { noopSignatureDbStore } from "../state/signature-db-store.ts";
import {
	buildSuspiciousFinding,
	checkSuspiciousExePath,
	hashSuspiciousBinary,
	resolveExePath,
} from "./suspicious-process.ts";
import type { Module, ModuleContext } from "./types.ts";

// Linux default ephemeral port range (net.ipv4.ip_local_port_range). This is where WebRTC/QUIC
// and other transient app sockets get assigned from — not configurable-detection here, just the
// common default, documented as an assumption rather than silently hardcoded.
const EPHEMERAL_PORT_MIN = 32768;
const EPHEMERAL_PORT_MAX = 65535;

// A process gets to open this many distinct ephemeral UDP ports (each one alerting normally)
// before the pattern is treated as established repeated churn and further ones are suppressed.
// Deliberately NOT tied to the process module's own known-binary allowlist — that allowlist gets
// populated by an independent 10s poll, so any process (malicious or not) that happens to survive
// one poll before opening its listener would already read as "known," which would make "an
// unrecognized process still alerts" untrustworthy. This counter is self-contained instead: it
// only trusts a process once *this exact behavior* — repeatedly binding new ephemeral UDP ports —
// has actually been observed a few times from it.
const EPHEMERAL_UDP_TRUST_THRESHOLD = 3;

export interface Listener {
	proto: string;
	localAddress: string;
	process: string;
}

export interface OutboundConn {
	proto: string;
	localAddress: string;
	peerAddress: string;
	process: string;
}

export function extractPort(localAddress: string): number | null {
	const parts = localAddress.split(":");
	const port = Number(parts[parts.length - 1]);
	return Number.isFinite(port) ? port : null;
}

export function extractPid(processField: string): number | null {
	const match = processField.match(/pid=(\d+)/);
	return match ? Number(match[1]) : null;
}

/** Strips the port, handling both "1.2.3.4:443" and bracketed IPv6 "[2606:...]:443". */
export function extractDestinationHost(peerAddress: string): string {
	if (peerAddress.startsWith("[")) {
		const closeIdx = peerAddress.indexOf("]");
		return closeIdx === -1 ? peerAddress : peerAddress.slice(1, closeIdx);
	}
	const idx = peerAddress.lastIndexOf(":");
	return idx === -1 ? peerAddress : peerAddress.slice(0, idx);
}

/** Expands "::" shorthand to the full 8 hextets, so a subnet prefix can be read positionally
 * regardless of where the compression happened (e.g. "2600:1901:0:92a9::" vs "2001::1234:5678"). */
export function expandIpv6(address: string): string[] {
	const [head, tail] = address.split("::");
	const headParts = head ? head.split(":").filter(Boolean) : [];
	const tailParts = tail ? tail.split(":").filter(Boolean) : [];
	if (tail === undefined) return headParts; // no "::" present, already fully expanded
	const missing = 8 - headParts.length - tailParts.length;
	return [...headParts, ...Array(Math.max(missing, 0)).fill("0"), ...tailParts];
}

/** Groups a destination IP down to a /24 (IPv4) or /48 (IPv6) subnet key. CDNs (Google, Akamai,
 * GitHub, Azure, etc.) hand a client a different edge IP within the same subnet on practically
 * every connection — tracking trust at the exact-IP level turns that normal churn into a constant
 * stream of "new destination" alerts. Subnet-level grouping is the fix shape flagged as the
 * likely-needed follow-up when this design was first built (see the outbound Layer 2 design notes
 * above); this is that follow-up, applied against the CDN noise actually observed in practice
 * rather than pre-guessed. A genuinely new destination in an already-trusted /24 or /48 still
 * won't alert — that's the accepted tradeoff for killing this specific noise source.
 */
export function toSubnetKey(destinationHost: string): string {
	if (destinationHost.includes(":")) {
		return expandIpv6(destinationHost).slice(0, 3).join(":");
	}
	const octets = destinationHost.split(".");
	return octets.length === 4 ? octets.slice(0, 3).join(".") : destinationHost;
}

export function parseListeners(output: string): Listener[] {
	const lines = output.split("\n").slice(1); // drop header
	const listeners: Listener[] = [];
	for (const line of lines) {
		if (!line.trim()) continue;
		const fields = line.trim().split(/\s+/);
		const [proto, , , , localAddress] = fields;
		if (!proto || !localAddress) continue;
		const process = fields.slice(6).join(" ");
		listeners.push({ proto, localAddress, process });
	}
	return listeners;
}

export function listenerKey(l: Listener): string {
	return `${l.proto}:${l.localAddress}`;
}

/** `ss -tnp state established` — no Netid column (already tcp-only): RecvQ SendQ Local Peer Process */
export function parseEstablishedTcp(output: string): OutboundConn[] {
	const lines = output.split("\n").slice(1);
	const conns: OutboundConn[] = [];
	for (const line of lines) {
		if (!line.trim()) continue;
		const fields = line.trim().split(/\s+/);
		const [, , localAddress, peerAddress] = fields;
		if (!localAddress || !peerAddress) continue;
		conns.push({
			proto: "tcp",
			localAddress,
			peerAddress,
			process: fields.slice(4).join(" "),
		});
	}
	return conns;
}

/** `ss -unp` — same layout, but UDP is connectionless so most rows show peer `*:*` (bind-only,
 * already covered by the listener check above); only rows with a real peer represent a UDP
 * socket actually talking somewhere. */
export function parseConnectedUdp(output: string): OutboundConn[] {
	const lines = output.split("\n").slice(1);
	const conns: OutboundConn[] = [];
	for (const line of lines) {
		if (!line.trim()) continue;
		const fields = line.trim().split(/\s+/);
		// `ss -unp` has the same RecvQ/SendQ leading columns as `ss -tnp` — fields[0]/[1] are queue
		// sizes (usually "0"), not addresses. Indices 2/3 are Local/Peer, matching parseEstablishedTcp.
		const [, , localAddress, peerAddress] = fields;
		if (!localAddress || !peerAddress || peerAddress === "*:*") continue;
		conns.push({
			proto: "udp",
			localAddress,
			peerAddress,
			process: fields.slice(4).join(" "),
		});
	}
	return conns;
}

export function createNetworkModule(ctx: ModuleContext): Module {
	const { config, db, recorder } = ctx;
	const signatureDb = ctx.signatureDb ?? noopSignatureDbStore();
	const baselinePath = `${config.dataDir}/baseline-network.json`;
	const outboundFirstSeenPath = `${config.dataDir}/outbound-first-seen.json`;
	let timer: ReturnType<typeof setInterval> | null = null;

	function checkOutbound(
		conns: OutboundConn[],
		isFirstOutboundRun: boolean,
	): number {
		// Trust is keyed by (exePath, destination subnet), not exePath alone — this is what closes
		// the "trust once forever" gap for a binary that's compromised via process injection (no
		// file ever changes, so FIM's tampering check can't catch it) but starts reaching new
		// infrastructure. Every new destination subnet for a binary alerts, no matter how long that
		// binary has been trusted. Grouped by /24 (v4) or /48 (v6) rather than exact IP — CDN edge-IP
		// churn turned out to be a real noise source in practice (Firefox/Citrix reconnecting to
		// rotating Google/Akamai/GitHub/Azure edge IPs for the same services), so this was tuned
		// against that observed noise rather than pre-guessed away. See toSubnetKey() above.
		const firstSeen = readJson<Record<string, Record<string, true>>>(
			outboundFirstSeenPath,
			{},
		);
		let newPairs = 0;

		for (const conn of conns) {
			const pid = extractPid(conn.process);
			const exePath = pid !== null ? resolveExePath(pid) : null;
			if (pid === null || !exePath) continue; // process exited between listing and resolving — can't attribute

			// Layer 1: a process already suspicious for existing (deleted binary / suspicious path) is
			// ALWAYS alert-worthy the moment it talks to the network, no dedup — same as process.ts
			// never lets a suspicious binary go quiet just because we've seen it before.
			const suspicious = checkSuspiciousExePath(
				exePath,
				config.process.suspiciousDirs,
			);
			if (suspicious.suspicious) {
				const sha256 = hashSuspiciousBinary(pid, suspicious);
				const finding = buildSuspiciousFinding({
					summaryBase: `Suspicious process (${suspicious.reason}) made an outbound connection: ${exePath} -> ${conn.peerAddress} (${conn.proto})`,
					detail: { ...conn, exePath },
					sha256,
					match: sha256 ? signatureDb.lookup(sha256) : null,
				});
				recorder.record({
					module: "network",
					severity: "critical",
					...finding,
				});
				continue;
			}

			// Layer 2: first-ever connection from this exe path to this destination's subnet.
			const destinationHost = extractDestinationHost(conn.peerAddress);
			const subnetKey = toSubnetKey(destinationHost);
			const isNewBinary = !firstSeen[exePath];
			const isNewDestination = isNewBinary || !firstSeen[exePath]![subnetKey];

			if (isNewDestination) {
				firstSeen[exePath] ??= {};
				firstSeen[exePath]![subnetKey] = true;
				newPairs++;
				if (!isFirstOutboundRun) {
					const summary = isNewBinary
						? `New process making outbound connections: ${exePath} -> ${conn.peerAddress} (${conn.proto})`
						: `Known process contacting a new destination: ${exePath} -> ${conn.peerAddress} (${conn.proto})`;
					recorder.record({
						module: "network",
						severity: "warning",
						summary,
						detail: { ...conn, exePath },
					});
				}
			}
		}

		writeJsonAtomic(outboundFirstSeenPath, firstSeen);
		return newPairs;
	}

	async function scanNow(): Promise<void> {
		const known = new Set(readJson<string[]>(baselinePath, []));
		const isFirstRun = known.size === 0;
		const ephemeralUdpCountsPath = `${config.dataDir}/ephemeral-udp-counts.json`;
		const ephemeralUdpCounts = readJson<Record<string, number>>(
			ephemeralUdpCountsPath,
			{},
		);

		const listenResult = Bun.spawnSync(["ss", "-tulnp"]);
		const listeners = parseListeners(listenResult.stdout.toString());
		let newListeners = 0;

		for (const listener of listeners) {
			const key = listenerKey(listener);
			if (!known.has(key)) {
				known.add(key);
				newListeners++;

				// Resolved once per new listener (not just inside the UDP-ephemeral branch below) so
				// it can also be attached to the alert's `detail` — that's what lets the dashboard's
				// whitelist feature match "this process" rather than a raw, pid-bearing `ss` string.
				const listenerPid = extractPid(listener.process);
				const listenerExePath =
					listenerPid !== null ? resolveExePath(listenerPid) : null;

				// UDP "listeners" from `ss` include ephemeral bind()-only sockets ordinary apps open
				// constantly (WebRTC/QUIC/DNS on high ports) — those look identical to a genuine new
				// listener by port number alone. Rather than ignore all UDP (which would blind us to
				// a real UDP-based backdoor), only suppress once a SPECIFIC process has demonstrated
				// this exact pattern — repeatedly binding new ephemeral ports — a few times. The
				// first few ephemeral-UDP binds from any process (known or not) still alert; only
				// after EPHEMERAL_UDP_TRUST_THRESHOLD distinct ports from the same exe path do
				// further ones quiet down. This does NOT depend on the process module's own
				// allowlist (which populates from an independent 10s poll and could make an
				// unrecognized process look "known" before its first UDP bind is even evaluated) —
				// the trust here is earned by this behavior specifically, not borrowed from elsewhere.
				let suppressAsEphemeralNoise = false;
				if (listener.proto === "udp" && !config.network.alertOnUdp) {
					const port = extractPort(listener.localAddress);
					const isEphemeralPort =
						port !== null &&
						port >= EPHEMERAL_PORT_MIN &&
						port <= EPHEMERAL_PORT_MAX;
					if (isEphemeralPort && listenerExePath) {
						const priorCount = ephemeralUdpCounts[listenerExePath] ?? 0;
						ephemeralUdpCounts[listenerExePath] = priorCount + 1;
						suppressAsEphemeralNoise =
							priorCount >= EPHEMERAL_UDP_TRUST_THRESHOLD;
					}
					// exePath unresolved (process already exited, or permissions) — can't establish
					// a trust history, so it stays alert-worthy rather than silently passing through.
				}

				if (
					!isFirstRun &&
					config.network.alertOnNewListener &&
					!suppressAsEphemeralNoise
				) {
					recorder.record({
						module: "network",
						severity: "warning",
						summary: `New listening port: ${listener.proto} ${listener.localAddress} (${listener.process || "unknown process"})`,
						detail: { ...listener, exePath: listenerExePath },
					});
				}
			}
		}

		writeJsonAtomic(baselinePath, [...known]);
		writeJsonAtomic(ephemeralUdpCountsPath, ephemeralUdpCounts);

		// Outbound: C2/exfil/tunneling checks — see checkOutbound() for the two-layer design.
		let outboundNewPairs = 0;
		let outboundConnCount = 0;
		if (config.network.alertOnOutbound) {
			const isFirstOutboundRun =
				Object.keys(
					readJson<Record<string, Record<string, true>>>(
						outboundFirstSeenPath,
						{},
					),
				).length === 0;
			const tcpResult = Bun.spawnSync(["ss", "-tnp", "state", "established"]);
			const udpResult = Bun.spawnSync(["ss", "-unp"]);
			const conns = [
				...parseEstablishedTcp(tcpResult.stdout.toString()),
				...parseConnectedUdp(udpResult.stdout.toString()),
			];
			outboundConnCount = conns.length;
			outboundNewPairs = checkOutbound(conns, isFirstOutboundRun);
		}

		upsertScanStatus(
			db,
			"network",
			isFirstRun
				? `baseline created (${listeners.length} listeners)`
				: `ok (${listeners.length} listeners, +${newListeners} new${
						config.network.alertOnOutbound
							? `, ${outboundConnCount} outbound, +${outboundNewPairs} new process/destination pairs`
							: ""
					})`,
		);
	}

	function start(): void {
		timer = setInterval(() => void scanNow(), config.network.pollIntervalMs);
	}

	function stop(): void {
		if (timer) clearInterval(timer);
	}

	return { scanNow, start, stop };
}
