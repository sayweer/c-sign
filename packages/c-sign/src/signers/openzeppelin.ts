import { Address, hash, xdr, type Keypair } from "@stellar/stellar-sdk";
import { addressCredentials, entrySignaturePayload } from "../entry.js";

/**
 * Signing helpers for OpenZeppelin smart accounts.
 *
 * OpenZeppelin accounts do not sign the entry payload directly. Up to stellar-accounts 0.7.x each signer signs
 * `sha256(payload ‖ xdr(Vec<u32> context_rule_ids))`; from 0.8.0 it signs `sha256(xdr(AuthDigestPreimage))`, which
 * also binds the account address. Either way the entry carries `AuthPayload { context_rule_ids, signers: Map<Signer, Bytes> }`.
 * C-Sign itself does not depend on this format; verification is by simulation.
 */

/** Context rule 0 is the account's Default rule, which covers any call. */
export const DEFAULT_CONTEXT_RULE_IDS = [0];

/** `legacy-concat` = OpenZeppelin stellar-accounts <= 0.7.x, `preimage-v1` = 0.8.0+ (names follow smart-account-kit). */
export type OzDigestScheme = "legacy-concat" | "preimage-v1";

const ruleIdsScVal = (contextRuleIds: number[]) => xdr.ScVal.scvVec(contextRuleIds.map((id) => xdr.ScVal.scvU32(id)));

/**
 * `AuthDigestPreimage { account, signature_payload, context_rule_ids }` as the 0.8.0 account encodes it.
 * Its sha256 is the `preimage-v1` digest; a Delegated signer authorizes `__check_auth` with this struct as its argument.
 */
export function ozAuthDigestPreimage(account: string, signaturePayload: Buffer, contextRuleIds: number[]): xdr.ScVal {
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
  entry: xdr.SorobanAuthorizationEntry,
  networkPassphrase: string,
  scheme: OzDigestScheme,
  contextRuleIds: number[] = DEFAULT_CONTEXT_RULE_IDS,
): Buffer {
  const payload = entrySignaturePayload(entry, networkPassphrase);
  if (scheme === "legacy-concat") return hash(Buffer.concat([payload, ruleIdsScVal(contextRuleIds).toXDR()]));
  // Plain-JS callers of the old positional API would otherwise land here with a plausible but wrong digest.
  if (scheme !== "preimage-v1") throw new Error(`Unknown OpenZeppelin digest scheme: ${String(scheme)}`);
  const account = Address.fromScAddress(addressCredentials(entry).address()).toString();
  return hash(ozAuthDigestPreimage(account, payload, contextRuleIds).toXDR());
}

/** `Signer::External(verifier, key_data)` as the account stores it. */
export function externalSigner(verifierId: string, keyData: Buffer): xdr.ScVal {
  return xdr.ScVal.scvVec([
    xdr.ScVal.scvSymbol("External"),
    Address.fromString(verifierId).toScVal(),
    xdr.ScVal.scvBytes(keyData),
  ]);
}

// Host ordering of signer keys (Vec<Symbol, Address, Bytes>): element-wise by content.
function compareSignerKeys(a: xdr.ScVal, b: xdr.ScVal): number {
  const av = a.vec() ?? [];
  const bv = b.vec() ?? [];
  for (let i = 0; i < Math.min(av.length, bv.length); i++) {
    const x = av[i];
    const y = bv[i];
    let cmp: number;
    if (x.switch().name === "scvBytes") cmp = Buffer.compare(Buffer.from(x.bytes()), Buffer.from(y.bytes()));
    else if (x.switch().name === "scvAddress") cmp = Buffer.compare(x.address().toXDR(), y.address().toXDR());
    else cmp = Buffer.compare(x.toXDR(), y.toXDR());
    if (cmp !== 0) return cmp;
  }
  return av.length - bv.length;
}

/** Writes `AuthPayload` with signer keys in host order. */
export function ozAuthPayload(contextRuleIds: number[], signatures: { signer: xdr.ScVal; signature: Buffer }[]): xdr.ScVal {
  const signers = signatures
    .map(({ signer, signature }) => new xdr.ScMapEntry({ key: signer, val: xdr.ScVal.scvBytes(signature) }))
    .sort((a, b) => compareSignerKeys(a.key(), b.key()));
  return xdr.ScVal.scvMap([
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol("context_rule_ids"),
      val: ruleIdsScVal(contextRuleIds),
    }),
    new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol("signers"), val: xdr.ScVal.scvMap(signers) }),
  ]);
}

/** An Ed25519 key registered on an account as `External(ed25519Verifier, publicKey)`. */
export interface OzEd25519Key {
  keypair: Keypair;
  verifierId: string;
}

export const ozEd25519Signer = (key: OzEd25519Key): xdr.ScVal =>
  externalSigner(key.verifierId, Buffer.from(key.keypair.rawPublicKey()));

/**
 * Signs an address-credential entry (any function, V1 or V2) for an
 * OpenZeppelin account whose rule requires exactly these Ed25519 keys.
 * Returns a signed copy; the input is left untouched.
 */
export function signOzEntryWithEd25519(
  entry: xdr.SorobanAuthorizationEntry,
  keys: OzEd25519Key[],
  networkPassphrase: string,
  scheme: OzDigestScheme,
  contextRuleIds: number[] = DEFAULT_CONTEXT_RULE_IDS,
): xdr.SorobanAuthorizationEntry {
  const copy = xdr.SorobanAuthorizationEntry.fromXDR(entry.toXDR());
  const digest = ozAuthDigest(copy, networkPassphrase, scheme, contextRuleIds);
  const payload = ozAuthPayload(
    contextRuleIds,
    keys.map((key) => ({ signer: ozEd25519Signer(key), signature: key.keypair.sign(digest) })),
  );
  addressCredentials(copy).signature(payload);
  return copy;
}
