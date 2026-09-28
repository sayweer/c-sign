// Testnet helpers for the end-to-end experiments: a funded sponsor, an
// OpenZeppelin smart account with Ed25519 signers, and transaction submission.
import { readFileSync } from "node:fs";
import {
  Address,
  Keypair,
  Operation,
  TransactionBuilder,
  rpc,
  xdr,
  type Transaction,
} from "@stellar/stellar-sdk";
import { TESTNET, ozEd25519Signer, signOzEntryWithEd25519, type OzEd25519Key } from "../src/index.js";

export const deployments = JSON.parse(
  readFileSync(new URL("../../../deployments/testnet.json", import.meta.url), "utf8"),
) as {
  wasmHash: string;
  instances: string[];
  fakeVerifier: { id: string };
  nonRevertingVerifier: { id: string; wasmHash: string };
};

/** OpenZeppelin smart account and Ed25519 verifier on testnet (smart-account-kit deployments, protocol 27). */
export const OZ_ACCOUNT_WASM = "1b5f4534a76322da2ad7c745f6900857a6802b0ca79850c35a03561df997785a";
export const OZ_ED25519_VERIFIER = "CAAVTMCBXEIBPR64EAASKFXERVPYFZA2JYP5A3BG6PESWEFUJX5IHKN4";

export const networkPassphrase = TESTNET.networkPassphrase;
export const rpcUrl = TESTNET.rpcUrl;
export const server = new rpc.Server(rpcUrl);

export async function fundedKeypair(): Promise<Keypair> {
  const kp = Keypair.random();
  const res = await fetch(`https://friendbot.stellar.org?addr=${kp.publicKey()}`);
  if (!res.ok) throw new Error(`Friendbot failed: ${res.status}`);
  return kp;
}

export const ed25519Key = (): OzEd25519Key => ({ keypair: Keypair.random(), verifierId: OZ_ED25519_VERIFIER });

export interface Submitted {
  hash: string;
  status: string;
  returnValue?: xdr.ScVal;
  resultXdr?: string;
}

export async function submit(tx: Transaction): Promise<Submitted> {
  const sent = await server.sendTransaction(tx);
  if (sent.status === "ERROR") {
    return { hash: sent.hash, status: "REJECTED", resultXdr: sent.errorResult?.toXDR("base64") };
  }
  const got = await server.pollTransaction(sent.hash, { attempts: 30 });
  if (got.status === rpc.Api.GetTransactionStatus.SUCCESS) {
    return { hash: sent.hash, status: got.status, returnValue: got.returnValue };
  }
  if (got.status === rpc.Api.GetTransactionStatus.FAILED) {
    return { hash: sent.hash, status: got.status, resultXdr: got.resultXdr.toXDR("base64") };
  }
  return { hash: sent.hash, status: got.status };
}

async function build(source: Keypair, op: xdr.Operation): Promise<Transaction> {
  const account = await server.getAccount(source.publicKey());
  return new TransactionBuilder(account, { fee: "1000000", networkPassphrase }).addOperation(op).setTimeout(60).build();
}

/** Deploys an OpenZeppelin smart account whose Default rule holds the given Ed25519 keys. */
export async function deployOzAccount(sponsor: Keypair, keys: OzEd25519Key[]): Promise<{ id: string; hash: string }> {
  const salt = Buffer.from(Keypair.random().rawPublicKey());
  const op = Operation.createCustomContract({
    address: Address.fromString(sponsor.publicKey()),
    wasmHash: Buffer.from(OZ_ACCOUNT_WASM, "hex"),
    salt,
    constructorArgs: [xdr.ScVal.scvVec(keys.map(ozEd25519Signer)), xdr.ScVal.scvMap([])],
  });
  const tx = await server.prepareTransaction(await build(sponsor, op));
  tx.sign(sponsor);
  const res = await submit(tx);
  if (res.status !== "SUCCESS" || !res.returnValue) throw new Error(`Account deploy failed: ${res.status} ${res.hash}`);
  return { id: Address.fromScVal(res.returnValue).toString(), hash: res.hash };
}

/**
 * Calls a function on the account itself (add_signer, remove_signer, ...),
 * authorized by the given keys. The sponsor pays.
 */
export async function adminCall(
  sponsor: Keypair,
  accountId: string,
  fn: string,
  args: xdr.ScVal[],
  keys: OzEd25519Key[],
): Promise<Submitted> {
  const op = Operation.invokeContractFunction({ contract: accountId, function: fn, args });
  const sim = await server.simulateTransaction(await build(sponsor, op));
  if (!rpc.Api.isSimulationSuccess(sim)) throw new Error(`Admin simulation failed: ${(sim as { error?: string }).error}`);
  const expiration = sim.latestLedger + 100;
  const auth = (sim.result?.auth ?? []).map((entry) => {
    const c = entry.credentials();
    const creds = c.switch().name === "sorobanCredentialsAddressV2" ? c.addressV2() : c.address();
    creds.signatureExpirationLedger(expiration);
    return signOzEntryWithEd25519(entry, keys, networkPassphrase);
  });
  const signedOp = Operation.invokeContractFunction({ contract: accountId, function: fn, args, auth });
  const tx = await server.prepareTransaction(await build(sponsor, signedOp));
  tx.sign(sponsor);
  return submit(tx);
}

/** Submits `verify_message` with a signed entry, reusing the footprint of an equivalent successful call. */
export async function submitVerifyCall(
  sponsor: Keypair,
  entry: xdr.SorobanAuthorizationEntry,
  sorobanData: xdr.SorobanTransactionData,
): Promise<Submitted> {
  const call = entry.rootInvocation().function().contractFn();
  const op = Operation.invokeHostFunction({ func: xdr.HostFunction.hostFunctionTypeInvokeContract(call), auth: [entry] });
  const account = await server.getAccount(sponsor.publicKey());
  const resourceFee = Number(sorobanData.resourceFee().toString());
  const tx = new TransactionBuilder(account, { fee: String(resourceFee + 100000), networkPassphrase })
    .addOperation(op)
    .setSorobanData(sorobanData)
    .setTimeout(60)
    .build();
  tx.sign(sponsor);
  return submit(tx);
}

/** Ledger key of an auth nonce; the entry exists once the nonce is consumed. */
export function nonceLedgerKey(accountId: string, nonce: xdr.Int64): xdr.LedgerKey {
  return xdr.LedgerKey.contractData(
    new xdr.LedgerKeyContractData({
      contract: Address.fromString(accountId).toScAddress(),
      key: xdr.ScVal.scvLedgerKeyNonce(new xdr.ScNonceKey({ nonce })),
      durability: xdr.ContractDataDurability.temporary(),
    }),
  );
}

export async function nonceConsumed(accountId: string, nonce: xdr.Int64): Promise<boolean> {
  const res = await server.getLedgerEntries(nonceLedgerKey(accountId, nonce));
  return res.entries.length > 0;
}

export const contractInstanceKey = (id: string) =>
  xdr.LedgerKey.contractData(
    new xdr.LedgerKeyContractData({
      contract: Address.fromString(id).toScAddress(),
      key: xdr.ScVal.scvLedgerKeyContractInstance(),
      durability: xdr.ContractDataDurability.persistent(),
    }),
  );

export const contractCodeKey = (wasmHash: string) =>
  xdr.LedgerKey.contractCode(new xdr.LedgerKeyContractCode({ hash: Buffer.from(wasmHash, "hex") }));

/** Summarises a failed transaction's call trace: which contracts ran and which error ended it. */
export async function failureTrace(hash: string): Promise<string> {
  const tx = await server.getTransaction(hash);
  if (tx.status !== rpc.Api.GetTransactionStatus.FAILED) return tx.status;
  const steps: string[] = [];
  for (const d of tx.diagnosticEventsXdr ?? []) {
    const event = d.event();
    const topics = event.body().v0().topics();
    const kind = topics[0]?.switch().name === "scvSymbol" ? topics[0].sym().toString() : "";
    if (kind === "fn_return" && topics[1]?.switch().name === "scvSymbol") {
      steps.push(`${topics[1].sym().toString()} returned`);
    } else if (kind === "error" && topics[1]?.switch().name === "scvError" && event.contractId()) {
      const err = topics[1].error();
      const code = err.switch().name === "sceContract" ? `Contract, #${err.contractCode()}` : err.switch().name;
      steps.push(`${Address.contract(event.contractId() as unknown as Buffer).toString().slice(0, 8)}… raised Error(${code})`);
    }
  }
  return steps.join(" → ");
}
