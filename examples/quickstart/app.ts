// The relying party: two Web-standard handlers, (Request) => Response.
// They run as they are in Next.js route handlers, Hono, Bun, Deno or Cloudflare Workers.
import { MemoryNonceStore, TESTNET, createSignInMessage, verifySignIn } from "c-sign";

/** Your own domain, from configuration and never from the request: lower-case host, with the port unless it is 443. */
export const DOMAIN = process.env.DOMAIN ?? "localhost:8787";
const STATEMENT = "Sign in to the C-Sign quickstart.";

// One process. With several instances, implement NonceStore on Redis or your database (see the c-sign README).
const nonces = new MemoryNonceStore();

/** GET /challenge -> the message the wallet signs. */
export function challenge(): Response {
  return Response.json(createSignInMessage({ domain: DOMAIN, statement: STATEMENT, ...nonces.issue() }));
}

/** POST /verify { signature } -> { status, account }. Start a session only on "valid". */
export async function verify(request: Request): Promise<Response> {
  const body = (await request.json().catch(() => null)) as { signature?: unknown } | null;
  if (typeof body?.signature !== "string") return Response.json({ error: "signature is required" }, { status: 400 });

  const result = await verifySignIn({
    signature: body.signature,
    rpcUrl: TESTNET.rpcUrl,
    networkPassphrase: TESTNET.networkPassphrase,
    domain: DOMAIN,
    nonces,
  });
  // Here a real app sets its session cookie for result.account.
  return Response.json({ status: result.status, reason: result.reason, account: result.account });
}
