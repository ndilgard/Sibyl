import { describe, expect, test } from "bun:test";
import { signAlertToken, verifyAlertToken } from "./link-auth.ts";

const secret = "test-secret-32-bytes-of-entropy";

describe("signAlertToken / verifyAlertToken", () => {
	test("a token signed for an alertId verifies against that same alertId", () => {
		const token = signAlertToken(secret, "alert-123");
		expect(verifyAlertToken(secret, "alert-123", token)).toBe(true);
	});

	test("signing is deterministic given the same secret+alertId", () => {
		expect(signAlertToken(secret, "alert-123")).toBe(
			signAlertToken(secret, "alert-123"),
		);
	});

	test("fails if the token is replayed against a different alertId", () => {
		const token = signAlertToken(secret, "alert-123");
		expect(verifyAlertToken(secret, "alert-999", token)).toBe(false);
	});

	test("fails if the token bytes are tampered with", () => {
		const token = signAlertToken(secret, "alert-123");
		const tampered = `${token.slice(0, -2)}00`;
		expect(verifyAlertToken(secret, "alert-123", tampered)).toBe(false);
	});

	test("fails against the wrong secret", () => {
		const token = signAlertToken(secret, "alert-123");
		expect(
			verifyAlertToken("a-completely-different-secret", "alert-123", token),
		).toBe(false);
	});

	test("fails safely on a mismatched-length token instead of throwing", () => {
		expect(() => verifyAlertToken(secret, "alert-123", "short")).not.toThrow();
		expect(verifyAlertToken(secret, "alert-123", "short")).toBe(false);
	});

	test("fails safely on an empty token", () => {
		expect(verifyAlertToken(secret, "alert-123", "")).toBe(false);
	});
});
