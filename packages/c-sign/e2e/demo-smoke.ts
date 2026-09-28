// Smoke test for the demo backend (apps/demo/api) against a running server.
//
//   BASE_URL=http://localhost:5173 pnpm --filter c-sign exec tsx e2e/demo-smoke.ts
import { Address, Keypair, Operation, TransactionBuilder, authorizeEntry, rpc, xdr } from "@stellar/stellar-sdk";
import { buildMessageEntry, encodeEntry, ozEd25519Signer, signOzEntryWithEd25519 } from "../src/index.js";
import { OZ_ACCOUNT_WASM, deployments, ed25519Key, fundedKeypair, networkPassphrase, server } from "./testnet.js";

const BASE = process.env.BASE_URL ?? "http://localhost:5173";
const host = new URL(BASE).host;
let failures = 0;
const check = (name: string, ok: boolean, detail = "") => {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? `: ${detail}` : ""}`);
  if (!ok) failures++;
};
const post = (path: string, body: unknown, headers: Record<string, string> = {}) =>
  fetch(`${BASE}${path}`, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });

async function main() {
  // 1. Deploy an OpenZeppelin account through the relay. A throwaway deployer
  //    signs the create-contract entry; the relay's sponsor only pays.
  const deployer = await fundedKeypair();
  const key = ed25519Key();
  const op = Operation.createCustomContract({
    address: Address.fromString(deployer.publicKey()),
    wasmHash: Buffer.from(OZ_ACCOUNT_WASM, "hex"),
    salt: Buffer.from(Keypair.random().rawPublicKey()),
    constructorArgs: [xdr.ScVal.scvVec([ozEd25519Signer(key)]), xdr.ScVal.scvMap([])],
  });
  const probe = new TransactionBuilder(await server.getAccount(deployer.publicKey()), { fee: "100", networkPassphrase })
    .addOperation(op)
    .setTimeout(60)
    .build();
  const sim = await server.simulateTransaction(probe);
  if (!rpc.Api.isSimulationSuccess(sim)) throw new Error("deploy simulation failed");
  const func = probe.operations[0].type === "invokeHostFunction" ? (probe.operations[0] as Operation.InvokeHostFunction).func : null;
  const authEntry = sim.result!.auth[0];
  // The deployer is a G account; the relay refuses source-account credentials, so sign as an address.
  const addressEntry = new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(
      new xdr.SorobanAddressCredentials({
        address: Address.fromString(deployer.publicKey()).toScAddress(),
        nonce: xdr.Int64.fromString(String(Date.now())),
        signatureExpirationLedger: 0,
        signature: xdr.ScVal.scvVoid(),
      }),
    ),
    rootInvocation: authEntry.rootInvocation(),
  });
  const signed = await authorizeEntry(addressEntry, deployer, sim.latestLedger + 100, networkPassphrase);
  const relay = await post("/api/relay", { func: func!.toXDR("base64"), auth: [signed.toXDR("base64")] });
  const relayBody = (await relay.json()) as { success: boolean; data?: { hash: string }; error?: string };
  check("relay deploys an OpenZeppelin account", relay.ok && relayBody.success, relayBody.error ?? relayBody.data?.hash);
  const tx = await server.getTransaction(relayBody.data!.hash);
  const account = tx.status === "SUCCESS" && tx.returnValue ? Address.fromScVal(tx.returnValue).toString() : "";
  check("deployed account id", account.startsWith("C"), account);

  // 2. The relay refuses anything outside its allowlist.
  const token = deployments.instances[0];
  const bad = xdr.HostFunction.hostFunctionTypeInvokeContract(
    new xdr.InvokeContractArgs({ contractAddress: Address.fromString(token).toScAddress(), functionName: "verify_message", args: [] }),
  );
  const refused = await post("/api/relay", { func: bad.toXDR("base64"), auth: [] });
  check("relay refuses other calls", refused.status === 403, `${refused.status} ${(await refused.json()).error}`);

  // 3. Sign in: challenge -> sign for this host -> verify sets a session cookie.
  const challenge = (await (await fetch(`${BASE}/api/challenge`)).json()) as { statement: string; nonce: string; issuedAt: number; token: string };
  const latest = (await server.getLatestLedger()).sequence;
  const entry = signOzEntryWithEd25519(
    buildMessageEntry({
      verifierId: deployments.instances[0],
      account,
      message: { version: "1", domain: host, statement: challenge.statement, nonce: challenge.nonce, issuedAt: challenge.issuedAt },
      expirationLedger: latest + 720,
    }),
    [key],
    networkPassphrase,
  );
  const signature = encodeEntry(entry);
  const verify = await post("/api/verify", { signature, token: challenge.token });
  const result = (await verify.json()) as { status: string; reason: string };
  const cookie = verify.headers.get("set-cookie")?.split(";")[0] ?? "";
  check("sign-in is valid", result.status === "valid", result.reason);
  check("session cookie set", cookie.startsWith("csign_session="));

  const session = (await (await fetch(`${BASE}/api/session`, { headers: { cookie } })).json()) as { account: string | null };
  check("session names the account", session.account === account, String(session.account));

  // 4. Replaying the same signature is refused; recheck still says valid.
  const replay = (await (await post("/api/verify", { signature, token: challenge.token })).json()) as { status: string; reason: string };
  check("replay refused", replay.status === "invalid", replay.reason);
  const recheck = (await (await post("/api/verify", { signature, mode: "recheck" })).json()) as { status: string };
  check("recheck valid", recheck.status === "valid");

  // 5. The same signature presented to another host is refused.
  const elsewhere = (await (await post("/api/verify", { signature, mode: "recheck" }, { "x-forwarded-host": "evil.example" })).json()) as {
    status: string;
    reason: string;
  };
  check("other domain refused", elsewhere.status === "invalid", elsewhere.reason);

  console.log(failures ? `\n${failures} check(s) failed` : "\nAll demo checks passed");
  process.exit(failures ? 1 : 0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
