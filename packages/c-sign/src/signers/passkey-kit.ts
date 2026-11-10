import { xdr } from "@stellar/stellar-sdk";
import { compareBytes } from "../bytes.js";
import { encodeEntry, entrySignaturePayload, toEntry, withSignature, type EntryInput } from "../entry.js";
import { parseMessageEntry } from "../wallet.js";
import type { Ed25519Keypair } from "./openzeppelin.js";

/**
 * Signing helpers for passkey-kit smart wallets.
 *
 * A passkey-kit signer signs the entry payload directly, with no account-specific
 * digest. The entry carries `Signatures(Map<SignerKey, Signature>)`, encoded as
 * `scvVec([scvMap])`. C-Sign itself does not depend on this format; verification
 * is by simulation.
 */

/** The method of passkey-kit's `PasskeyKit` used here. Tested against 0.14.0 and 0.20.0, which are not dependencies of this package. */
export interface PasskeyKitSigning<KitEntry, Signer> {
  signAuthEntry(entry: KitEntry, signer?: Signer): Promise<EntryInput>;
}

export interface PasskeyKitSignOptions<KitEntry, Signer> {
  /** One of the kit's signer classes; omitted, the kit prompts for its connected passkey. */
  signer?: Signer;
  /**
   * Turns base64 XDR into an entry of the SDK the kit uses. Needed when the kit uses a
   * different stellar-sdk major than this library (passkey-kit 0.20 and earlier use 16):
   * `(b64) => xdr.SorobanAuthorizationEntry.fromXDR(b64, "base64")`, with `xdr` imported
   * from that SDK. Defaults to this library's SDK.
   */
  decode?: (base64: string) => KitEntry;
}

/**
 * Signs a C-Sign message entry through a passkey-kit instance, after the offline
 * checks of {@link parseMessageEntry}. A wallet calls {@link checkMessageRequest}
 * first, for the origin and the verifier. Returns a signed copy.
 */
export async function signMessageWithPasskeyKit<KitEntry, Signer>(
  kit: PasskeyKitSigning<KitEntry, Signer>,
  entry: EntryInput,
  options: PasskeyKitSignOptions<KitEntry, Signer> = {},
): Promise<xdr.SorobanAuthorizationEntry> {
  parseMessageEntry(entry);
  const base64 = encodeEntry(entry);
  const forKit = options.decode ? options.decode(base64) : (xdr.SorobanAuthorizationEntry.fromXdr(base64, "base64") as KitEntry);
  return toEntry(await kit.signAuthEntry(forKit, options.signer));
}

/**
 * Signs a C-Sign message entry with Ed25519 signers of a passkey-kit wallet, without
 * the kit. Returns a signed copy.
 *
 * A signer whose limits exclude the verifier cannot sign messages: the wallet rejects
 * it and verification returns `invalid`. Keep it that way for recovery keys; adding the
 * verifier to a recovery key's limits turns that key into a sign-in key for every domain.
 */
export function signPasskeyKitMessageWithEd25519(entry: EntryInput, keys: Ed25519Keypair[], networkPassphrase: string): xdr.SorobanAuthorizationEntry {
  parseMessageEntry(entry);
  const payload = entrySignaturePayload(entry, networkPassphrase);
  const signatures = [...keys]
    .sort((a, b) => compareBytes(a.rawPublicKey(), b.rawPublicKey()))
    .map((key) => new xdr.ScMapEntry({ key: taggedBytes(key.rawPublicKey()), val: taggedBytes(key.sign(payload)) }));
  return withSignature(entry, xdr.ScVal.scvVec([xdr.ScVal.scvMap(signatures)]));
}

const taggedBytes = (bytes: Uint8Array) => xdr.ScVal.scvVec([xdr.ScVal.scvSymbol("Ed25519"), xdr.ScVal.scvBytes(bytes)]);
