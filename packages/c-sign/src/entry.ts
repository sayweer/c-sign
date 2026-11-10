import { Buffer } from "buffer";
import { Address, buildAuthorizationEntryPreimage, hash, rpc, xdr } from "@stellar/stellar-sdk";
import { VERIFY_FUNCTION } from "./constants.js";
import { CSignError } from "./errors.js";
import { messageToScVal, type SignedMessage } from "./message.js";

/** Contract-call arguments of `verify_message(account, msg)` on a verifier instance. */
export function buildVerifyArgs(verifierId: string, account: string, message: SignedMessage): xdr.InvokeContractArgs {
  return new xdr.InvokeContractArgs({
    contractAddress: Address.fromString(verifierId).toScAddress(),
    functionName: VERIFY_FUNCTION,
    args: [Address.fromString(account).toScVal(), messageToScVal(message)],
  });
}

/** The root invocation a C-Sign signature authorizes: one call, no sub-invocations. */
export function buildVerifyInvocation(verifierId: string, account: string, message: SignedMessage): xdr.SorobanAuthorizedInvocation {
  return new xdr.SorobanAuthorizedInvocation({
    function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
      buildVerifyArgs(verifierId, account, message),
    ),
    subInvocations: [],
  });
}

/** A random i64 auth-entry nonce (unrelated to the message nonce). */
export function randomEntryNonce(): xdr.Int64 {
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  return xdr.Int64.fromString(new DataView(bytes.buffer).getBigInt64(0, false).toString());
}

export interface BuildEntryParams {
  verifierId: string;
  account: string;
  message: SignedMessage;
  /** Last ledger at which the signature is valid. */
  expirationLedger: number;
  nonce?: xdr.Int64;
}

/** Builds the unsigned entry with address-bound (V2) credentials. The account's wallet fills in the signature. */
export function buildMessageEntry(p: BuildEntryParams): xdr.SorobanAuthorizationEntry {
  const credentials = new xdr.SorobanAddressCredentials({
    address: Address.fromString(p.account).toScAddress(),
    nonce: p.nonce ?? randomEntryNonce(),
    signatureExpirationLedger: p.expirationLedger,
    signature: xdr.ScVal.scvVoid(),
  });
  return new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsAddressV2(credentials),
    rootInvocation: buildVerifyInvocation(p.verifierId, p.account, p.message),
  });
}

export interface CreateEntryParams {
  verifierId: string;
  account: string;
  message: SignedMessage;
  rpcUrl: string;
  /** Accept a plain `http` RPC URL, for local development. */
  allowHttp?: boolean;
  /** Ledgers the signature stays valid for (default 720, about an hour; at most 17280, about a day). */
  validForLedgers?: number;
}

/**
 * {@link buildMessageEntry} with the expiration set from the RPC's latest ledger.
 * Returns the unsigned entry and its expiration ledger, which some kits ask for again when signing.
 */
export async function createMessageEntry(
  p: CreateEntryParams,
): Promise<{ entry: xdr.SorobanAuthorizationEntry; expirationLedger: number }> {
  const ledgers = p.validForLedgers ?? 720;
  if (!Number.isInteger(ledgers) || ledgers < 1 || ledgers > 17280) {
    throw new CSignError("validForLedgers must be an integer from 1 to 17280");
  }
  const server = new rpc.Server(p.rpcUrl, { allowHttp: p.allowHttp });
  const expirationLedger = (await server.getLatestLedger()).sequence + ledgers;
  const entry = buildMessageEntry({ verifierId: p.verifierId, account: p.account, message: p.message, expirationLedger });
  return { entry, expirationLedger };
}

export function addressCredentials(entry: xdr.SorobanAuthorizationEntry): xdr.SorobanAddressCredentials {
  const c = entry.credentials();
  switch (c.switch().name) {
    case "sorobanCredentialsAddress":
      return c.address();
    case "sorobanCredentialsAddressV2":
      return c.addressV2();
    default:
      throw new Error(`Entry has no address credentials (${c.switch().name})`);
  }
}

/** The 32-byte payload the account's `__check_auth` receives for this entry. */
export function entrySignaturePayload(entry: xdr.SorobanAuthorizationEntry, networkPassphrase: string): Buffer {
  const expiration = addressCredentials(entry).signatureExpirationLedger();
  return hash(buildAuthorizationEntryPreimage(entry, expiration, networkPassphrase).toXDR());
}

export const encodeEntry = (entry: xdr.SorobanAuthorizationEntry): string => entry.toXDR("base64");
export const decodeEntry = (base64: string): xdr.SorobanAuthorizationEntry =>
  xdr.SorobanAuthorizationEntry.fromXDR(base64, "base64");
