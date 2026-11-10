import { Address, hash, xdr } from "@stellar/stellar-sdk";
import { compareBytes, concatBytes } from "../bytes.js";
import { addressCredentials, entrySignaturePayload, toEntry, withSignature, type EntryInput } from "../entry.js";
import { CSignError } from "../errors.js";
import { isMessageEntry, parseMessageEntry } from "../wallet.js";

/**
 * Signing helpers for OpenZeppelin smart accounts.
 *
 * OpenZeppelin accounts do not sign the entry payload directly. In stellar-accounts 0.7.x each signer signs
 * `sha256(payload ‖ xdr(Vec<u32> context_rule_ids))`; from 0.8.0 it signs `sha256(xdr(AuthDigestPreimage))`, which
 * also binds the account address. Either way the entry carries `AuthPayload { context_rule_ids, signers: Map<Signer, Bytes> }`.
 * C-Sign itself does not depend on this format; verification is by simulation.
 */

/** Context rule 0 is the account's Default rule, which covers any call. */
export const DEFAULT_CONTEXT_RULE_IDS = [0];

/** `legacy-concat` = OpenZeppelin stellar-accounts 0.7.x, `preimage-v1` = 0.8.0+ (names follow smart-account-kit). Earlier versions are not supported. */
export type OzDigestScheme = "legacy-concat" | "preimage-v1";

const ruleIdsScVal = (contextRuleIds: number[]) => xdr.ScVal.scvVec(contextRuleIds.map((id) => xdr.ScVal.scvU32(id)));

/**
 * `AuthDigestPreimage { account, signature_payload, context_rule_ids }` as the 0.8.0 account encodes it.
 * Its sha256 is the `preimage-v1` digest; a Delegated signer authorizes `__check_auth` with this struct as its argument.
 */
export function ozAuthDigestPreimage(account: string, signaturePayload: Uint8Array, contextRuleIds: number[]): xdr.ScVal {
  if (signaturePayload.length !== 32) throw new Error("signature_payload must be 32 bytes");
  // Map keys in host (sorted) order.
  return xdr.ScVal.scvMap([
    new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol("account"), val: Address.fromString(account).toScVal() }),
    new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol("context_rule_ids"), val: ruleIdsScVal(contextRuleIds) }),
    new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol("signature_payload"), val: xdr.ScVal.scvBytes(signaturePayload) }),
  ]);
}

/** The digest each signer signs for this entry; the scheme depends on the account's implementation version. */
export function ozAuthDigest(
  entry: EntryInput,
  networkPassphrase: string,
  scheme: OzDigestScheme,
  contextRuleIds: number[] = DEFAULT_CONTEXT_RULE_IDS,
): Uint8Array {
  const payload = entrySignaturePayload(entry, networkPassphrase);
  if (scheme === "legacy-concat") return hash(concatBytes(payload, ruleIdsScVal(contextRuleIds).toXdr()));
  // Plain-JS callers of the old positional API would otherwise land here with a plausible but wrong digest.
  if (scheme !== "preimage-v1") throw new Error(`Unknown OpenZeppelin digest scheme: ${String(scheme)}`);
  const account = Address.fromScAddress(addressCredentials(entry).address).toString();
  return hash(ozAuthDigestPreimage(account, payload, contextRuleIds).toXdr());
}

/** `Signer::External(verifier, key_data)` as the account stores it. */
export function externalSigner(verifierId: string, keyData: Uint8Array): xdr.ScVal {
  return xdr.ScVal.scvVec([
    xdr.ScVal.scvSymbol("External"),
    Address.fromString(verifierId).toScVal(),
    xdr.ScVal.scvBytes(keyData),
  ]);
}

// Host ordering of signer keys (Vec<Symbol, Address, Bytes>): element-wise by content.
function compareSignerKeys(a: xdr.ScVal, b: xdr.ScVal): number {
  const av = a.type === "scvVec" ? (a.vec ?? []) : [];
  const bv = b.type === "scvVec" ? (b.vec ?? []) : [];
  for (let i = 0; i < Math.min(av.length, bv.length); i++) {
    const x = av[i]!;
    const y = bv[i]!;
    let cmp: number;
    if (x.type === "scvBytes" && y.type === "scvBytes") cmp = compareBytes(x.bytes.toBytes(), y.bytes.toBytes());
    else if (x.type === "scvAddress" && y.type === "scvAddress") cmp = compareBytes(x.address.toXdr(), y.address.toXdr());
    else cmp = compareBytes(x.toXdr(), y.toXdr());
    if (cmp !== 0) return cmp;
  }
  return av.length - bv.length;
}

/** Writes `AuthPayload` with signer keys in host order. */
export function ozAuthPayload(contextRuleIds: number[], signatures: { signer: xdr.ScVal; signature: Uint8Array }[]): xdr.ScVal {
  const signers = signatures
    .map(({ signer, signature }) => new xdr.ScMapEntry({ key: signer, val: xdr.ScVal.scvBytes(signature) }))
    .sort((a, b) => compareSignerKeys(a.key, b.key));
  return xdr.ScVal.scvMap([
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol("context_rule_ids"),
      val: ruleIdsScVal(contextRuleIds),
    }),
    new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol("signers"), val: xdr.ScVal.scvMap(signers) }),
  ]);
}

/** The part of a Stellar SDK `Keypair` the signers use; a `Keypair` from any SDK version fits. */
export interface Ed25519Keypair {
  rawPublicKey(): Uint8Array;
  sign(data: Uint8Array): Uint8Array;
}

/** An Ed25519 key registered on an account as `External(ed25519Verifier, publicKey)`. */
export interface OzEd25519Key {
  keypair: Ed25519Keypair;
  verifierId: string;
}

export const ozEd25519Signer = (key: OzEd25519Key): xdr.ScVal =>
  externalSigner(key.verifierId, key.keypair.rawPublicKey());

/**
 * Signs an authorization entry for an OpenZeppelin account whose rule requires
 * exactly these Ed25519 keys. Refuses a `verify_message` entry: a message is
 * signed only in response to a message request (SPEC §5 item 5), with
 * {@link signOzMessageWithEd25519}. Returns a signed copy.
 */
export function signOzEntryWithEd25519(
  entry: EntryInput,
  keys: OzEd25519Key[],
  networkPassphrase: string,
  scheme: OzDigestScheme,
  contextRuleIds: number[] = DEFAULT_CONTEXT_RULE_IDS,
): xdr.SorobanAuthorizationEntry {
  if (isMessageEntry(entry)) throw new CSignError("Refusing to sign a message entry as a generic authorization");
  return unsafeSignOzEntry(entry, keys, networkPassphrase, scheme, contextRuleIds);
}

/**
 * Signs a C-Sign message entry, after the offline checks of {@link parseMessageEntry}.
 * A wallet calls {@link checkMessageRequest} first, for the origin and the verifier.
 */
export function signOzMessageWithEd25519(
  entry: EntryInput,
  keys: OzEd25519Key[],
  networkPassphrase: string,
  scheme: OzDigestScheme,
  contextRuleIds: number[] = DEFAULT_CONTEXT_RULE_IDS,
): xdr.SorobanAuthorizationEntry {
  parseMessageEntry(entry);
  return unsafeSignOzEntry(entry, keys, networkPassphrase, scheme, contextRuleIds);
}

/** Experiments only: signs any address-credential entry, valid or not, without checking it. */
export function unsafeSignOzEntry(
  entry: EntryInput,
  keys: OzEd25519Key[],
  networkPassphrase: string,
  scheme: OzDigestScheme,
  contextRuleIds: number[] = DEFAULT_CONTEXT_RULE_IDS,
): xdr.SorobanAuthorizationEntry {
  const e = toEntry(entry);
  const digest = ozAuthDigest(e, networkPassphrase, scheme, contextRuleIds);
  const payload = ozAuthPayload(
    contextRuleIds,
    keys.map((key) => ({ signer: ozEd25519Signer(key), signature: key.keypair.sign(digest) })),
  );
  return withSignature(e, payload);
}
