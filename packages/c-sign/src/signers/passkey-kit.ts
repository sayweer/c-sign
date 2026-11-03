import { xdr, type Keypair } from "@stellar/stellar-sdk";
import { addressCredentials, entrySignaturePayload } from "../entry.js";
import { parseMessageEntry } from "../wallet.js";

/**
 * Signing helpers for passkey-kit smart wallets.
 *
 * A passkey-kit signer signs the entry payload directly, with no account-specific
 * digest. The entry carries `Signatures(Map<SignerKey, Signature>)`, encoded as
 * `scvVec([scvMap])`. C-Sign itself does not depend on this format; verification
 * is by simulation.
 */

/** The method of passkey-kit's `PasskeyKit` used here. Tested against 0.14.0 and 0.20.0, which is not a dependency of this package. */
export interface PasskeyKitSigning<Signer> {
  signAuthEntry(entry: xdr.SorobanAuthorizationEntry, signer?: Signer): Promise<xdr.SorobanAuthorizationEntry>;
}

/**
 * Signs a C-Sign message entry through a passkey-kit instance, after the offline
 * checks of {@link parseMessageEntry}. `signer` is one of the kit's signer classes;
 * omitted, the kit prompts for its connected passkey. A wallet calls
 * {@link checkMessageRequest} first, for the origin and the verifier. Returns a signed copy.
 */
export async function signMessageWithPasskeyKit<Signer>(
  kit: PasskeyKitSigning<Signer>,
  entry: xdr.SorobanAuthorizationEntry,
  signer?: Signer,
): Promise<xdr.SorobanAuthorizationEntry> {
  parseMessageEntry(entry);
  const signed = await kit.signAuthEntry(xdr.SorobanAuthorizationEntry.fromXDR(entry.toXDR()), signer);
  // The kit may carry its own copy of the SDK; hand back an entry of this one.
  return xdr.SorobanAuthorizationEntry.fromXDR(signed.toXDR());
}

/**
 * Signs a C-Sign message entry with Ed25519 signers of a passkey-kit wallet, without
 * the kit. Returns a signed copy.
 *
 * A signer whose limits exclude the verifier cannot sign messages: the wallet rejects
 * it and verification returns `invalid`. Keep it that way for recovery keys; adding the
 * verifier to a recovery key's limits turns that key into a sign-in key for every domain.
 */
export function signPasskeyKitMessageWithEd25519(
  entry: xdr.SorobanAuthorizationEntry,
  keys: Keypair[],
  networkPassphrase: string,
): xdr.SorobanAuthorizationEntry {
  parseMessageEntry(entry);
  const copy = xdr.SorobanAuthorizationEntry.fromXDR(entry.toXDR());
  const payload = entrySignaturePayload(copy, networkPassphrase);
  const signatures = [...keys]
    .sort((a, b) => Buffer.compare(a.rawPublicKey(), b.rawPublicKey()))
    .map(
      (key) =>
        new xdr.ScMapEntry({
          key: taggedBytes(Buffer.from(key.rawPublicKey())),
          val: taggedBytes(key.sign(payload)),
        }),
    );
  addressCredentials(copy).signature(xdr.ScVal.scvVec([xdr.ScVal.scvMap(signatures)]));
  return copy;
}

const taggedBytes = (bytes: Buffer) => xdr.ScVal.scvVec([xdr.ScVal.scvSymbol("Ed25519"), xdr.ScVal.scvBytes(bytes)]);
