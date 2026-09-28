import { Keypair } from "@stellar/stellar-sdk";
import { TESTNET } from "c-sign";

export const RPC_URL = process.env.RPC_URL || TESTNET.rpcUrl;
export const NETWORK_PASSPHRASE = TESTNET.networkPassphrase;

/** OpenZeppelin smart-account Wasm the demo wallet deploys (smart-account-kit, protocol 27 testnet). */
export const OZ_ACCOUNT_WASM = "1b5f4534a76322da2ad7c745f6900857a6802b0ca79850c35a03561df997785a";

export function sponsor(): Keypair | null {
  const secret = process.env.SPONSOR_SECRET;
  return secret ? Keypair.fromSecret(secret) : null;
}

export function sessionSecret(): string {
  const secret = process.env.SESSION_SECRET;
  if (!secret || secret.length < 32) throw new Error("SESSION_SECRET must be set (32+ characters)");
  return secret;
}
