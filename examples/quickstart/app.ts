// The relying party: two Web-standard handlers, (Request) => Response.
// They run as they are in Next.js route handlers, Hono, Bun, Deno or Cloudflare Workers.
import { MemoryNonceStore, TESTNET, createSignInMessage, verifySignIn, type SignedMessage } from "c-sign";

/** Your own domain, from configuration and never from the request: lower-case host, with the port unless it is 443. */
export const DOMAIN = process.env.DOMAIN ?? "localhost:8787";
const STATEMENT = "Sign in to the C-Sign quickstart.";

// One process. With several instances, implement NonceStore on Redis or your database (see the c-sign README).
const nonces = new MemoryNonceStore();

/** GET /challenge -> the message the wallet signs. */
export function challenge(): Response {
  return Response.json(createSignInMessage({ domain: DOMAIN, statement: STATEMENT, ...nonces.issue() }));
}

/**
 * POST /verify -> { status, account }. Start a session only on "valid".
 * C... account: { signature } (the entry carries the message). G... account: { signature, address, message }.
 */
export async function verify(request: Request): Promise<Response> {
  const body = (await request.json().catch(() => null)) as { signature?: unknown; address?: unknown; message?: SignedMessage } | null;
  if (typeof body?.signature !== "string") return Response.json({ error: "signature is required" }, { status: 400 });

  const result = await verifySignIn({
    signature: body.signature,
    address: typeof body.address === "string" ? body.address : undefined,
    message: body.message,
    rpcUrl: TESTNET.rpcUrl,
    networkPassphrase: TESTNET.networkPassphrase,
    domain: DOMAIN,
    nonces,
  });
  // Here a real app sets its session cookie for result.account.
  return Response.json({ status: result.status, reason: result.reason, account: result.account });
}
