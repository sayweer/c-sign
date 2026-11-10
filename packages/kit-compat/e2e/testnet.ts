// Testnet helpers on stellar-sdk 16, the SDK the kits use.
import { readFileSync } from "node:fs";
import { Keypair, Operation, TransactionBuilder, rpc, type Transaction, type xdr } from "@stellar/stellar-sdk";
import { TESTNET } from "c-sign";

export const deployments = JSON.parse(readFileSync(new URL("../../../deployments/testnet.json", import.meta.url), "utf8")) as { instances: string[] };

export const networkPassphrase = TESTNET.networkPassphrase;
/** Defaults to SDF's public testnet RPC; set RPC_URL to use another provider. */
export const rpcUrl = process.env.RPC_URL ?? TESTNET.rpcUrl;
export const server = new rpc.Server(rpcUrl);

export interface Submitted {
  hash: string;
  status: string;
  returnValue?: xdr.ScVal;
}

export async function submit(tx: Transaction): Promise<Submitted> {
  const sent = await server.sendTransaction(tx);
  if (sent.status === "ERROR") return { hash: sent.hash, status: "REJECTED" };
  const got = await server.pollTransaction(sent.hash, { attempts: 30 });
  if (got.status === rpc.Api.GetTransactionStatus.SUCCESS) return { hash: sent.hash, status: got.status, returnValue: got.returnValue };
  return { hash: sent.hash, status: got.status };
}

export async function fundedKeypair(): Promise<Keypair> {
  const kp = Keypair.random();
  const res = await fetch(`https://friendbot.stellar.org?addr=${kp.publicKey()}`);
  if (res.ok) return kp;
  // Friendbot is down: an existing account (FUNDER_SECRET) creates the fresh sponsor instead.
  if (!process.env.FUNDER_SECRET) throw new Error(`Friendbot failed: ${res.status}; set FUNDER_SECRET to fund from an existing account`);
  const funder = Keypair.fromSecret(process.env.FUNDER_SECRET);
  const account = await server.getAccount(funder.publicKey());
  const tx = new TransactionBuilder(account, { fee: "1000000", networkPassphrase })
    .addOperation(Operation.createAccount({ destination: kp.publicKey(), startingBalance: "500" }))
    .setTimeout(60)
    .build();
  tx.sign(funder);
  const created = await submit(tx);
  if (created.status !== "SUCCESS") throw new Error(`Funding the sponsor failed: ${created.status} ${created.hash}`);
  return kp;
}
