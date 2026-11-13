import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";

/**
 * Signs alert ids so the "whitelist this" link in an alert email can't be replayed against a
 * different alert, and can't be guessed. Secret lives alongside the rest of HIDS's runtime state
 * (dataDir, same NAS mount) rather than in git — generated once, reused after.
 */

function secretPath(dataDir: string): string {
	return `${dataDir}/link-secret`;
}

export function getOrCreateLinkSecret(dataDir: string): string {
	const path = secretPath(dataDir);
	if (existsSync(path)) return readFileSync(path, "utf-8").trim();
	const secret = randomBytes(32).toString("hex");
	writeFileSync(path, secret);
	return secret;
}

export function signAlertToken(secret: string, alertId: string): string {
	return createHmac("sha256", secret).update(alertId).digest("hex");
}

export function verifyAlertToken(
	secret: string,
	alertId: string,
	token: string,
): boolean {
	const expected = signAlertToken(secret, alertId);
	const expectedBuf = Buffer.from(expected, "hex");
	const tokenBuf = Buffer.from(token, "hex");
	if (expectedBuf.length !== tokenBuf.length) return false;
	return timingSafeEqual(expectedBuf, tokenBuf);
}
