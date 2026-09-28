import { Operation, TransactionBuilder, rpc, xdr } from "@stellar/stellar-sdk";
import { NETWORK_PASSPHRASE, RPC_URL, sponsor } from "./_lib/config.js";
import { admits, authAdmissible } from "./_lib/guard.js";
import { json, rateLimited } from "./_lib/http.js";

/**
 * Fee sponsor for the demo wallet, speaking the smart-account-kit relayer
 * protocol: POST { func, auth } -> { success, data: { hash, status } }.
 * The account's own signatures are in `auth`; the sponsor only pays.
 */
export async function POST(request: Request): Promise<Response> {
  const fail = (error: string, status: number) => json({ success: false, error }, status);
  if (rateLimited(request, 20)) return fail("Too many requests", 429);
  const keypair = sponsor();
  if (!keypair) return fail("Relay is not configured", 503);

  const body = (await request.json().catch(() => null)) as { func?: unknown; auth?: unknown } | null;
  if (!body || typeof body.func !== "string" || !Array.isArray(body.auth) || body.auth.length > 4) {
    return fail("Expected { func, auth }", 400);
  }
  let func: xdr.HostFunction;
  let auth: xdr.SorobanAuthorizationEntry[];
  try {
    func = xdr.HostFunction.fromXDR(body.func, "base64");
    auth = body.auth.map((a) => xdr.SorobanAuthorizationEntry.fromXDR(String(a), "base64"));
  } catch {
    return fail("Malformed XDR", 400);
  }

  const server = new rpc.Server(RPC_URL);
  const refusal = await admits(func, server);
  if (refusal) return fail(refusal, 403);
  if (!authAdmissible(auth, keypair.publicKey())) return fail("Authorization entries must be the account's own", 403);

  try {
    const source = await server.getAccount(keypair.publicKey());
    const tx = new TransactionBuilder(source, { fee: "100000", networkPassphrase: NETWORK_PASSPHRASE })
      .addOperation(Operation.invokeHostFunction({ func, auth }))
      .setTimeout(60)
      .build();
    // Entries are present, so the RPC simulates in enforcing mode and checks the signatures.
    const sim = await server.simulateTransaction(tx);
    if (rpc.Api.isSimulationError(sim)) return fail(`Simulation failed: ${sim.error.split("\n")[0]}`, 400);
    const prepared = rpc.assembleTransaction(tx, sim).build();
    prepared.sign(keypair);
    const sent = await server.sendTransaction(prepared);
    if (sent.status === "ERROR" || sent.status === "TRY_AGAIN_LATER") return fail(`Submission rejected (${sent.status})`, 502);
    const done = await server.pollTransaction(sent.hash, { attempts: 30 });
    if (done.status !== rpc.Api.GetTransactionStatus.SUCCESS) return fail(`Transaction ${done.status} (${sent.hash})`, 502);
    return json({ success: true, data: { hash: sent.hash, status: done.status } });
  } catch (e) {
    return fail(e instanceof Error ? e.message : String(e), 502);
  }
}
