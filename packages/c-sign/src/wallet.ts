import { Address, rpc } from "@stellar/stellar-sdk";
import { bytesEqual } from "./bytes.js";
import { REFERENCE_WASM_HASH, VERIFY_FUNCTION } from "./constants.js";
import { buildVerifyInvocation, toEntry, type EntryInput } from "./entry.js";
import { CSignError } from "./errors.js";
import { isDomainForm, messageFromScVal, type SignedMessage } from "./message.js";
import { instanceWasmHash, readVerifierInstance } from "./verify.js";

/**
 * The `domain` a wallet writes for an origin the platform reports (SPEC §5 item 1).
 * `undefined` means the wallet must not treat this origin as a verified domain.
 */
export function domainFromOrigin(origin: string, opts: { developerMode?: boolean } = {}): string | undefined {
  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    return undefined;
  }
  if (url.username || url.password || url.pathname !== "/" || url.search || url.hash) return undefined;
  const localhost = url.protocol === "http:" && url.hostname === "localhost" && opts.developerMode === true;
  if (url.protocol !== "https:" && !localhost) return undefined;
  return isDomainForm(url.host) ? url.host : undefined;
}

/** True if the entry's root invocation calls a function named `verify_message` (SPEC §5 item 5). */
export function isMessageEntry(entry: EntryInput): boolean {
  const fn = toEntry(entry).rootInvocation.function;
  return fn.type === "sorobanAuthorizedFunctionTypeContractFn" && fn.contractFn.functionName.toString() === VERIFY_FUNCTION;
}

export interface ParsedMessageEntry {
  account: string;
  verifierId: string;
  message: SignedMessage;
  expirationLedger: number;
}

/**
 * Decodes an entry an application asked the wallet to sign, and throws a
 * {@link CSignError} unless it is exactly one C-Sign message call (SPEC §5 item 3).
 * Display what this returns, not the application's copy of the message (§5 item 2).
 */
export function parseMessageEntry(input: EntryInput): ParsedMessageEntry {
  const entry = toEntry(input);
  const root = entry.rootInvocation;
  const fn = root.function;
  if (fn.type !== "sorobanAuthorizedFunctionTypeContractFn" || fn.contractFn.functionName.toString() !== VERIFY_FUNCTION) {
    throw new CSignError(`Entry does not call ${VERIFY_FUNCTION}`);
  }
  if (root.subInvocations.length > 0) throw new CSignError("Entry authorizes sub-invocations");
  const call = fn.contractFn;
  const args = call.args;
  if (args.length !== 2 || args[0]!.type !== "scvAddress") throw new CSignError("Arguments are not (account, msg)");
  const account = Address.fromScVal(args[0]!).toString();
  if (!account.startsWith("C")) throw new CSignError("Signer is not a contract account");
  if (entry.credentials.type !== "sorobanCredentialsAddressV2") throw new CSignError("Credentials are not V2");
  const creds = entry.credentials.addressV2;
  if (Address.fromScAddress(creds.address).toString() !== account) throw new CSignError("Credential address differs from the account argument");
  const verifierId = Address.fromScAddress(call.contractAddress).toString();
  const message = messageFromScVal(args[1]!);
  if (!bytesEqual(buildVerifyInvocation(verifierId, account, message).toXdr(), root.toXdr())) {
    throw new CSignError("Signed call differs from the rebuilt call");
  }
  return { account, verifierId, message, expirationLedger: creds.signatureExpirationLedger };
}

export interface CheckMessageRequestOptions {
  entry: EntryInput;
  /** Origin of the requesting application, as the platform reports it, never as the application states it. */
  origin: string;
  developerMode?: boolean;
  /** An RPC the wallet chooses, not one the application supplies. */
  rpcUrl: string;
  allowHttp?: boolean;
  networkPassphrase: string;
  /** Accepted verifier Wasm hashes. Defaults to the reference hash. */
  allowedWasmHashes?: string[];
}

/**
 * Everything a wallet checks before invoking a signer (SPEC §5 items 1 and 3).
 * Throws a {@link CSignError} on a rule violation and on anything it cannot
 * confirm, including RPC failures: when in doubt, the wallet does not sign.
 */
export async function checkMessageRequest(opts: CheckMessageRequestOptions): Promise<ParsedMessageEntry> {
  const parsed = parseMessageEntry(opts.entry);
  const domain = domainFromOrigin(opts.origin, { developerMode: opts.developerMode });
  if (domain === undefined) throw new CSignError(`Origin ${opts.origin} is not a verified domain`);
  if (parsed.message.domain !== domain) throw new CSignError(`Entry is for ${parsed.message.domain}, the request came from ${domain}`);

  let instance: rpc.Api.LedgerEntryResult | undefined;
  let latestLedger: number;
  try {
    const server = new rpc.Server(opts.rpcUrl, { allowHttp: opts.allowHttp });
    const network = await server.getNetwork();
    if (network.passphrase !== opts.networkPassphrase) throw new Error(`RPC serves "${network.passphrase}"`);
    latestLedger = (await server.getLatestLedger()).sequence;
    instance = await readVerifierInstance(server, parsed.verifierId);
  } catch (e) {
    throw new CSignError(`Could not check the verifier: ${e instanceof Error ? e.message : String(e)}`);
  }
  if (!instance) throw new CSignError("No contract at the verifier address");
  if (instance.liveUntilLedgerSeq !== undefined && instance.liveUntilLedgerSeq < latestLedger) throw new CSignError("Verifier instance is archived");
  const wasmHash = instanceWasmHash(instance);
  if (wasmHash === undefined) throw new CSignError("Verifier is not a Wasm contract");
  const allowed = (opts.allowedWasmHashes ?? [REFERENCE_WASM_HASH]).map((h) => h.toLowerCase());
  if (!allowed.includes(wasmHash)) throw new CSignError(`Verifier runs ${wasmHash}, not an accepted hash`);
  return parsed;
}
