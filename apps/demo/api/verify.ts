import { REFERENCE_WASM_HASH, verifyMessage } from "c-sign";
import { NETWORK_PASSPHRASE, RPC_URL } from "./_lib/config.js";
import { isHttps, json, rateLimited, requestHost } from "./_lib/http.js";
import { SESSION_COOKIE, SESSION_TTL_SECONDS, challengeNonce, consumeNonce, issueSession, nonceUsed } from "./_lib/tokens.js";

type Mode = "signin" | "recheck" | "inspect";

/**
 * - signin: full relying-party check (domain, nonce, age); sets a session cookie.
 * - recheck: an earlier signature for this site, checked again against the account's current rules.
 * - inspect: any signature, domain not enforced (the "verify any signature" tool).
 */
export async function POST(request: Request): Promise<Response> {
  if (rateLimited(request, 60)) return json({ error: "Too many requests" }, 429);
  const body = (await request.json().catch(() => null)) as { signature?: unknown; mode?: unknown; token?: unknown } | null;
  if (!body || typeof body.signature !== "string" || body.signature.length > 16_384) {
    return json({ error: "signature (base64 XDR) is required" }, 400);
  }
  const mode: Mode = body.mode === "recheck" || body.mode === "inspect" ? body.mode : "signin";
  const challenge = mode === "signin" ? challengeNonce(typeof body.token === "string" ? body.token : undefined) : null;
  if (mode === "signin" && !challenge) return json({ error: "Challenge expired or invalid. Request a new one." }, 400);

  const result = await verifyMessage({
    signature: body.signature,
    rpcUrl: RPC_URL,
    networkPassphrase: NETWORK_PASSPHRASE,
    allowedWasmHashes: [REFERENCE_WASM_HASH],
    domain: mode === "inspect" ? undefined : requestHost(request),
    freshness:
      mode === "signin"
        ? { checkNonce: (nonce) => nonce === challenge!.nonce && !nonceUsed(nonce), maxAgeSeconds: 300 }
        : undefined,
  });

  const headers: Record<string, string> = {};
  if (mode === "signin" && result.status === "valid" && result.account && consumeNonce(challenge!.nonce)) {
    const secure = isHttps(request) ? "; Secure" : "";
    headers["set-cookie"] = `${SESSION_COOKIE}=${issueSession(result.account)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_TTL_SECONDS}${secure}`;
  }
  return json(result, 200, headers);
}
