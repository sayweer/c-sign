import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { sessionSecret } from "./config.js";

export const CHALLENGE_TTL_SECONDS = 300;
export const SESSION_TTL_SECONDS = 3600;
export const SESSION_COOKIE = "csign_session";

const b64url = (buf: Buffer | string) => Buffer.from(buf).toString("base64url");
const mac = (payload: string) => createHmac("sha256", sessionSecret()).update(payload).digest();

function sign(payload: string): string {
  return `${b64url(payload)}.${b64url(mac(payload))}`;
}

function open(token: string | undefined): string | null {
  if (!token) return null;
  const [body, tag] = token.split(".");
  if (!body || !tag) return null;
  const payload = Buffer.from(body, "base64url").toString();
  const expected = mac(payload);
  const given = Buffer.from(tag, "base64url");
  return given.length === expected.length && timingSafeEqual(given, expected) ? payload : null;
}

/** A stateless challenge: the server remembers only the nonces already used. */
export function issueChallenge() {
  const nonce = randomBytes(12).toString("hex");
  const issuedAt = Math.floor(Date.now() / 1000);
  return { nonce, issuedAt, token: sign(`challenge|${nonce}|${issuedAt}`) };
}

export function challengeNonce(token: string | undefined): { nonce: string; issuedAt: number } | null {
  const payload = open(token);
  const [kind, nonce, issuedAt] = payload?.split("|") ?? [];
  if (kind !== "challenge" || !nonce) return null;
  if (Date.now() / 1000 - Number(issuedAt) > CHALLENGE_TTL_SECONDS) return null;
  return { nonce, issuedAt: Number(issuedAt) };
}

export function issueSession(account: string): string {
  return sign(`session|${account}|${Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS}`);
}

export function sessionAccount(token: string | undefined): string | null {
  const [kind, account, expires] = open(token)?.split("|") ?? [];
  if (kind !== "session" || !account || Number(expires) < Date.now() / 1000) return null;
  return account;
}

// Used nonces live in memory: a cold start forgets them, but challenges expire
// after five minutes anyway. A production relying party keeps them in a store.
const used = new Map<string, number>();
export function consumeNonce(nonce: string): boolean {
  const now = Date.now();
  for (const [n, t] of used) if (now - t > CHALLENGE_TTL_SECONDS * 2000) used.delete(n);
  if (used.has(nonce)) return false;
  used.set(nonce, now);
  return true;
}
export const nonceUsed = (nonce: string) => used.has(nonce);
