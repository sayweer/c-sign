import { Networks, StrKey } from "@stellar/stellar-sdk";
import { CSignError } from "./errors.js";
import { validateMessage, type SignedMessage } from "./message.js";

/**
 * `G…` accounts sign in with SEP-53: the wallet signs a text, and the relying party
 * checks the signature against the account's key. The text is formatted from the
 * structured message, never parsed back: the relying party checks the message fields
 * with the same rules as for a `C…` account, rebuilds the text and verifies the
 * signature over it. Fields cannot contain line breaks (SPEC §2), so the text is
 * unambiguous, and the chain id binds the signature to one network.
 */

const CHAIN_IDS: Record<string, string> = {
  [Networks.PUBLIC]: "stellar:pubnet",
  [Networks.TESTNET]: "stellar:testnet",
  [Networks.FUTURENET]: "stellar:futurenet",
};

/** CAIP-2 chain id of a Stellar network. Throws a `CSignError` for a network without one. */
export function chainId(networkPassphrase: string): string {
  const id = CHAIN_IDS[networkPassphrase];
  if (!id) throw new CSignError(`No CAIP-2 chain id for network "${networkPassphrase}"`);
  return id;
}

const iso = (seconds: number) => new Date(seconds * 1000).toISOString();

/** The CAIP-122 text a `G…` account signs with SEP-53 for this message. Throws a `CSignError` if the message breaks a rule. */
export function signInText(msg: SignedMessage, address: string, networkPassphrase: string): string {
  validateMessage(msg);
  if (!StrKey.isValidEd25519PublicKey(address)) throw new CSignError("address is not a valid G… account");
  const lines = [`${msg.domain} wants you to sign in with your Stellar account:`, address, "", msg.statement, ""];
  if (msg.uri !== undefined) lines.push(`URI: ${msg.uri}`);
  lines.push(`Version: ${msg.version}`, `Chain ID: ${chainId(networkPassphrase)}`, `Nonce: ${msg.nonce}`, `Issued At: ${iso(msg.issuedAt)}`);
  if (msg.expirationTime !== undefined) lines.push(`Expiration Time: ${iso(msg.expirationTime)}`);
  if (msg.notBefore !== undefined) lines.push(`Not Before: ${iso(msg.notBefore)}`);
  if (msg.requestId !== undefined) lines.push(`Request ID: ${msg.requestId}`);
  if (msg.resources?.length) lines.push("Resources:", ...msg.resources.map((r) => `- ${r}`));
  return lines.join("\n");
}

/**
 * Signs {@link signInText} with SEP-53 and returns the base64 signature. A browser wallet
 * does the same with `signMessage(signInText(...))`, for example Freighter's.
 */
export function signSignInWithKeypair(
  msg: SignedMessage,
  keypair: { publicKey(): string; signMessage(message: string): Uint8Array },
  networkPassphrase: string,
): string {
  const signature = keypair.signMessage(signInText(msg, keypair.publicKey(), networkPassphrase));
  return btoa(String.fromCharCode(...signature));
}
