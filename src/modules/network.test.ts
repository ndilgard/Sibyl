import { describe, expect, test } from "bun:test";
import {
	expandIpv6,
	extractDestinationHost,
	extractPid,
	extractPort,
	listenerKey,
	parseConnectedUdp,
	parseEstablishedTcp,
	parseListeners,
	toSubnetKey,
} from "./network.ts";

describe("parseListeners (ss -tulnp)", () => {
	const header =
		"Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process";

	test("parses a real listener line", () => {
		const output = [
			header,
			'tcp   LISTEN 0      128    127.0.0.1:631      0.0.0.0:*         users:(("cupsd",pid=1234,fd=6))',
		].join("\n");
		expect(parseListeners(output)).toEqual([
			{
				proto: "tcp",
				localAddress: "127.0.0.1:631",
				process: 'users:(("cupsd",pid=1234,fd=6))',
			},
		]);
	});

	test("skips blank lines and lines with no proto/localAddress", () => {
		const output = [header, "", "   ", "malformed line"].join("\n");
		expect(parseListeners(output)).toEqual([]);
	});

	test("parses multiple listeners", () => {
		const output = [
			header,
			'tcp   LISTEN 0 128 127.0.0.1:631  0.0.0.0:* users:(("cupsd",pid=1,fd=1))',
			'udp   UNCONN 0 0   0.0.0.0:68     0.0.0.0:* users:(("dhclient",pid=2,fd=2))',
		].join("\n");
		expect(parseListeners(output)).toHaveLength(2);
	});
});

describe("listenerKey", () => {
	test("combines proto and localAddress", () => {
		expect(
			listenerKey({ proto: "tcp", localAddress: "127.0.0.1:631", process: "" }),
		).toBe("tcp:127.0.0.1:631");
	});
});

describe("parseEstablishedTcp (ss -tnp state established)", () => {
	const header = "Recv-Q Send-Q Local Address:Port Peer Address:Port Process";

	test("parses a real established connection (RecvQ/SendQ leading columns)", () => {
		const output = [
			header,
			'0      0      192.168.1.50:54321  142.250.65.238:443  users:(("firefox",pid=4821,fd=112))',
		].join("\n");
		expect(parseEstablishedTcp(output)).toEqual([
			{
				proto: "tcp",
				localAddress: "192.168.1.50:54321",
				peerAddress: "142.250.65.238:443",
				process: 'users:(("firefox",pid=4821,fd=112))',
			},
		]);
	});

	test("skips blank lines and lines missing local/peer", () => {
		const output = [header, "", "0 0 onlyonefield"].join("\n");
		expect(parseEstablishedTcp(output)).toEqual([]);
	});
});

describe("parseConnectedUdp (ss -unp) — regression test for commit 841710e", () => {
	const header = "Recv-Q Send-Q Local Address:Port Peer Address:Port Process";

	test("extracts the real local/peer address, not the RecvQ/SendQ queue-size columns", () => {
		// Reproduces the exact bug: gvfsd-http's local DNS query to 127.0.0.53:53 used to be
		// parsed as destination "0" because fields[0]/[1] (queue sizes) were read as the
		// addresses instead of fields[2]/[3]. If this regresses, these assertions fail.
		const output = [
			header,
			'0      0      127.0.0.1:52134     127.0.0.53:53       users:(("gvfsd-http",pid=5321,fd=9))',
		].join("\n");
		const result = parseConnectedUdp(output);
		expect(result).toEqual([
			{
				proto: "udp",
				localAddress: "127.0.0.1:52134",
				peerAddress: "127.0.0.53:53",
				process: 'users:(("gvfsd-http",pid=5321,fd=9))',
			},
		]);
		expect(result[0]!.peerAddress).not.toBe("0");
		expect(result[0]!.localAddress).not.toBe("0");
	});

	test("filters out bind-only sockets (peer *:*)", () => {
		const output = [
			header,
			'0      0      0.0.0.0:68          *:*                 users:(("dhclient",pid=2,fd=2))',
		].join("\n");
		expect(parseConnectedUdp(output)).toEqual([]);
	});

	test("skips blank lines and lines missing local/peer", () => {
		const output = [header, "", "0 0 onlyonefield"].join("\n");
		expect(parseConnectedUdp(output)).toEqual([]);
	});
});

describe("extractPort", () => {
	test("extracts the port from an IPv4 address", () => {
		expect(extractPort("127.0.0.1:8080")).toBe(8080);
	});

	test("extracts the port from a bracketed IPv6 address (last colon segment)", () => {
		expect(extractPort("[2606:4700::1]:443")).toBe(443);
	});

	test("returns null when there's no numeric port", () => {
		expect(extractPort("*")).toBeNull();
	});
});

describe("extractPid", () => {
	test("extracts a pid from a users:() process field", () => {
		expect(extractPid('users:(("firefox",pid=4821,fd=112))')).toBe(4821);
	});

	test("returns null when there's no pid", () => {
		expect(extractPid("")).toBeNull();
	});
});

describe("extractDestinationHost", () => {
	test("strips the port from an IPv4 peer address", () => {
		expect(extractDestinationHost("142.250.65.238:443")).toBe("142.250.65.238");
	});

	test("strips the port from a bracketed IPv6 peer address", () => {
		expect(extractDestinationHost("[2606:4700::1]:443")).toBe("2606:4700::1");
	});

	test("returns the input unchanged when there's no colon", () => {
		expect(extractDestinationHost("nohost")).toBe("nohost");
	});
});

describe("expandIpv6", () => {
	test("expands trailing :: compression", () => {
		expect(expandIpv6("2600:1901:0:92a9::")).toEqual([
			"2600",
			"1901",
			"0",
			"92a9",
			"0",
			"0",
			"0",
			"0",
		]);
	});

	test("expands mid-string :: compression", () => {
		expect(expandIpv6("2001::1234:5678")).toEqual([
			"2001",
			"0",
			"0",
			"0",
			"0",
			"0",
			"1234",
			"5678",
		]);
	});

	test("passes through an already-fully-expanded address", () => {
		expect(expandIpv6("2001:db8:1:2:3:4:5:6")).toEqual([
			"2001",
			"db8",
			"1",
			"2",
			"3",
			"4",
			"5",
			"6",
		]);
	});
});

describe("toSubnetKey", () => {
	test("groups an IPv4 address to its /24", () => {
		expect(toSubnetKey("192.168.1.55")).toBe("192.168.1");
	});

	test("groups an IPv6 address to its /48 via expansion", () => {
		expect(toSubnetKey("2600:1901:0:92a9::1234")).toBe("2600:1901:0");
	});

	test("two different IPv4 addresses in the same /24 produce the same key", () => {
		expect(toSubnetKey("142.250.65.10")).toBe(toSubnetKey("142.250.65.238"));
	});
});
