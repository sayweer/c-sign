import { Account, Address, Keypair, Operation, TransactionBuilder, rpc, xdr } from "@stellar/stellar-sdk";
import { AUTH_OK, REFERENCE_WASM_HASH, VERIFY_FUNCTION } from "./constants.js";
import { CSignError } from "./errors.js";
import { buildVerifyInvocation } from "./entry.js";
import { MAX_ENTRY_XDR_BYTES, messageFromScVal, type SignedMessage } from "./message.js";

export type VerifyStatus = "valid" | "invalid" | "inconclusive";
export type StepStatus = "pass" | "fail" | "skip" | "error";

export interface VerifyStep {
  id: "decode" | "shape" | "credentials" | "rebuild" | "message" | "domain" | "freshness" | "network" | "expiration" | "pin" | "check_auth" | "consume";
  label: string;
  status: StepStatus;
  detail: string;
}

interface CommonOptions {
  /** Base64 XDR `SorobanAuthorizationEntry`. */
  signature: string;
  rpcUrl: string;
  /** Accept a plain `http` RPC URL, for local development. */
  allowHttp?: boolean;
  networkPassphrase: string;
  /** Expected signer. If omitted, the account named in the entry is reported. */
  address?: string;
  /** Accepted verifier Wasm hashes. Defaults to the reference hash. */
  allowedWasmHashes?: string[];
  /** Allowed clock skew in seconds (default and maximum 60). Does not extend the challenge lifetime. */
  clockSkewSeconds?: number;
  /** Unix seconds; defaults to now. */
  now?: number;
}

export interface VerifyOptions extends CommonOptions {
  /** A domain this verifier accepts for the statement, or `null` for an inspection tool that reports whatever was signed. */
  domain: string | null;
  /** Experiments only: skips Wasm-hash pinning to show why it is required. */
  unsafeSkipPinning?: boolean;
}

/** The relying party's record of the nonces it issued. */
export interface NonceStore {
  /** When this RP issued `nonce` (Unix seconds, on its own clock), or `undefined` if it did not or the nonce is used. */
  issuedAt(nonce: string): number | undefined | Promise<number | undefined>;
  /** Atomically marks `nonce` used. Returns false if it already was. Called only on a `valid` result. */
  consume(nonce: string): boolean | Promise<boolean>;
}

export interface VerifySignInOptions extends CommonOptions {
  /** The relying party's own domain, from its configuration and not from the request. */
  domain: string;
  nonces: NonceStore;
  /** Maximum age of the nonce in seconds (default 300). */
  challengeLifetimeSeconds?: number;
}

export interface VerifyResult {
  status: VerifyStatus;
  reason: string;
  account?: string;
  verifierId?: string;
  message?: SignedMessage;
  steps: VerifyStep[];
  /** Raw simulation error, when the simulation ran. */
  simulationError?: string;
}

const LABELS: Record<VerifyStep["id"], string> = {
  decode: "Decode signature",
  shape: "One call to verify_message, no sub-calls",
  credentials: "Address-bound credentials (V2)",
  rebuild: "Rebuild the signed call",
  message: "Message fields",
  domain: "Domain is this site",
  freshness: "Nonce and issue time",
  network: "RPC serves this network and is current",
  expiration: "Signature expiration",
  pin: "Verifier runs the pinned Wasm",
  check_auth: "Account's __check_auth (enforced simulation)",
  consume: "Mark the nonce used",
};

const ORDER = Object.keys(LABELS) as VerifyStep["id"][];

const MAX_CLOCK_SKEW_SECONDS = 60;

// An RPC whose latest ledger is older than this may be stale or forked off (SPEC §6 step 6).
const MAX_LEDGER_AGE_SECONDS = 30;

// A sign-in entry should not stay usable for more than about a day (SPEC §6 step 2).
const MAX_SIGN_IN_EXPIRATION_LEDGERS = 17280;

// Longest base64 of an entry at the size limit: 4 characters per 3 bytes, rounded up.
const MAX_ENTRY_BASE64_CHARS = Math.ceil(MAX_ENTRY_XDR_BYTES / 3) * 4;

// A pinned instance cannot change its code, so a positive check can be cached.
const pinnedInstances = new Map<string, string>();

/**
 * Checks that the account's current rules authorize a signed message (SPEC §6
 * steps 1 to 7). This is not a sign-in: it does not show when the message was
 * signed or whether it was used before. Use {@link verifySignIn} to log someone in.
 * Never throws: network failures and archived entries are `inconclusive`, rule
 * violations are `invalid`.
 */
export const verifyMessage = (opts: VerifyOptions): Promise<VerifyResult> => run(opts);

/**
 * The full relying-party check (SPEC §6): {@link verifyMessage} plus the nonce,
 * which is consumed atomically on `valid` and left unused on any other result.
 * Never throws; a failing {@link NonceStore} makes the result `inconclusive`.
 */
export const verifySignIn = (opts: VerifySignInOptions): Promise<VerifyResult> => run(opts, opts);

async function run(
  opts: CommonOptions & { domain: string | null; unsafeSkipPinning?: boolean },
  signIn?: Pick<VerifySignInOptions, "nonces" | "challengeLifetimeSeconds">,
): Promise<VerifyResult> {
  const steps: VerifyStep[] = [];
  const result = (status: VerifyStatus, reason: string, extra: Partial<VerifyResult> = {}): VerifyResult => {
    for (const id of ORDER) {
      if (!steps.some((s) => s.id === id)) steps.push({ id, label: LABELS[id], status: "skip", detail: "Not reached" });
    }
    steps.sort((a, b) => ORDER.indexOf(a.id) - ORDER.indexOf(b.id));
    return { status, reason, steps, ...extra };
  };
  const pass = (id: VerifyStep["id"], detail: string) => steps.push({ id, label: LABELS[id], status: "pass", detail });
  const fail = (id: VerifyStep["id"], detail: string, extra: Partial<VerifyResult> = {}) => {
    steps.push({ id, label: LABELS[id], status: "fail", detail });
    return result("invalid", detail, extra);
  };
  const inconclusive = (id: VerifyStep["id"], detail: string, extra: Partial<VerifyResult> = {}) => {
    steps.push({ id, label: LABELS[id], status: "error", detail });
    return result("inconclusive", detail, extra);
  };

  // 1. Decode
  const encoded = opts.signature.trim();
  if (encoded.length > MAX_ENTRY_BASE64_CHARS) return fail("decode", `Signature is longer than ${MAX_ENTRY_BASE64_CHARS} characters`);
  const decoded = Buffer.from(encoded, "base64");
  if (decoded.length > MAX_ENTRY_XDR_BYTES) return fail("decode", `Entry is larger than ${MAX_ENTRY_XDR_BYTES} bytes`);
  let entry: xdr.SorobanAuthorizationEntry;
  try {
    entry = xdr.SorobanAuthorizationEntry.fromXDR(decoded);
  } catch {
    return fail("decode", "Not a base64 XDR SorobanAuthorizationEntry");
  }
  pass("decode", `${entry.toXDR().length} bytes`);

  // 2. Shape
  const root = entry.rootInvocation();
  if (root.function().switch().name !== "sorobanAuthorizedFunctionTypeContractFn") {
    return fail("shape", "Root invocation is not a contract call");
  }
  const call = root.function().contractFn();
  const verifierId = Address.fromScAddress(call.contractAddress()).toString();
  if (call.functionName().toString() !== VERIFY_FUNCTION) {
    return fail("shape", `Calls ${call.functionName().toString()}, not ${VERIFY_FUNCTION}`);
  }
  if (root.subInvocations().length > 0) return fail("shape", "Entry authorizes sub-invocations");
  const args = call.args();
  if (args.length !== 2 || args[0].switch().name !== "scvAddress") return fail("shape", "Arguments are not (account, msg)");
  const account = Address.fromScVal(args[0]).toString();
  pass("shape", `${VERIFY_FUNCTION} on ${verifierId}`);

  // 3. Credentials
  if (entry.credentials().switch().name !== "sorobanCredentialsAddressV2") {
    return fail("credentials", `Credentials are ${entry.credentials().switch().name}, V2 required`, { account, verifierId });
  }
  const creds = entry.credentials().addressV2();
  const signer = Address.fromScAddress(creds.address()).toString();
  if (signer !== account) return fail("credentials", "Credential address differs from the account argument", { account, verifierId });
  if (opts.address && opts.address !== account) {
    return fail("credentials", `Signed by ${account}, expected ${opts.address}`, { account, verifierId });
  }
  if (!account.startsWith("C")) return fail("credentials", "Signer is not a contract account; use SEP-53", { account, verifierId });
  pass("credentials", account);

  // 4. Message decode, then rebuild the invocation from its parts
  let message: SignedMessage;
  try {
    message = messageFromScVal(args[1]);
  } catch (e) {
    steps.push({ id: "rebuild", label: LABELS.rebuild, status: "skip", detail: "Message could not be decoded" });
    return fail("message", e instanceof CSignError ? e.message : "Message could not be decoded", { account, verifierId });
  }
  const rebuilt = buildVerifyInvocation(verifierId, account, message).toXDR();
  if (!rebuilt.equals(root.toXDR())) return fail("rebuild", "Signed call differs from the rebuilt call", { account, verifierId });
  pass("rebuild", "Byte-identical");
  pass("message", `version ${message.version}, ${Object.keys(message).length} fields`);
  const ctx = { account, verifierId, message };

  // 5. Domain and time bounds
  if (opts.domain === null) {
    steps.push({ id: "domain", label: LABELS.domain, status: "skip", detail: `Not checked (signed for ${message.domain})` });
  } else if (message.domain !== opts.domain) {
    return fail("domain", `Signed for ${message.domain}, this site is ${opts.domain}`, ctx);
  } else {
    pass("domain", message.domain);
  }

  const now = opts.now ?? Math.floor(Date.now() / 1000);
  const skew = Math.min(opts.clockSkewSeconds ?? MAX_CLOCK_SKEW_SECONDS, MAX_CLOCK_SKEW_SECONDS);
  if (message.issuedAt > now + skew) return fail("freshness", "issued_at is in the future", ctx);
  if (message.expirationTime !== undefined && now > message.expirationTime + skew) {
    return fail("freshness", "Message expiration_time has passed", ctx);
  }
  if (message.notBefore !== undefined && now + skew < message.notBefore) return fail("freshness", "Message is not valid yet (not_before)", ctx);
  if (signIn) {
    let issuedAt: number | undefined;
    try {
      issuedAt = await signIn.nonces.issuedAt(message.nonce);
    } catch (e) {
      return inconclusive("freshness", `Nonce store failed: ${errorText(e)}`, ctx);
    }
    if (issuedAt === undefined) return fail("freshness", "Nonce was not issued here or was already used", ctx);
    const lifetime = signIn.challengeLifetimeSeconds ?? 300;
    if (now - issuedAt > lifetime) return fail("freshness", `Nonce issued ${now - issuedAt}s ago, max ${lifetime}s`, ctx);
    pass("freshness", `Nonce ${message.nonce} accepted`);
  } else {
    steps.push({ id: "freshness", label: LABELS.freshness, status: "skip", detail: "Not a sign-in: nonce and age not checked" });
  }

  // 6. The RPC: right network, current ledger
  let server: rpc.Server;
  let latestLedger: number;
  try {
    server = new rpc.Server(opts.rpcUrl, { allowHttp: opts.allowHttp });
    const [network, latest] = await Promise.all([server.getNetwork(), server.getLatestLedger()]);
    if (network.passphrase !== opts.networkPassphrase) {
      return inconclusive("network", `RPC serves "${network.passphrase}", expected "${opts.networkPassphrase}"`, ctx);
    }
    const age = now - Number(latest.closeTime);
    if (!(age <= MAX_LEDGER_AGE_SECONDS)) {
      return inconclusive("network", `Latest ledger closed ${age}s ago, max ${MAX_LEDGER_AGE_SECONDS}s`, ctx);
    }
    latestLedger = latest.sequence;
  } catch (e) {
    return inconclusive("network", `RPC unavailable: ${errorText(e)}`, ctx);
  }
  pass("network", `Ledger ${latestLedger} on ${opts.networkPassphrase}`);

  // 7. Expiration
  const expiration = creds.signatureExpirationLedger();
  if (expiration < latestLedger) {
    return fail("expiration", `Expired at ledger ${expiration} (now ${latestLedger})`, ctx);
  }
  if (signIn && expiration - latestLedger > MAX_SIGN_IN_EXPIRATION_LEDGERS) {
    return fail("expiration", `Sign-in entry expires ${expiration - latestLedger} ledgers from now, max ${MAX_SIGN_IN_EXPIRATION_LEDGERS}`, ctx);
  }
  pass("expiration", `Valid until ledger ${expiration} (now ${latestLedger})`);

  // 8. Pin the verifier instance
  const allowed = (opts.allowedWasmHashes ?? [REFERENCE_WASM_HASH]).map((h) => h.toLowerCase());
  if (opts.unsafeSkipPinning) {
    steps.push({ id: "pin", label: LABELS.pin, status: "skip", detail: "UNSAFE: pinning disabled" });
  } else {
    const cacheKey = `${opts.networkPassphrase}|${verifierId}`;
    let wasmHash = pinnedInstances.get(cacheKey);
    if (!wasmHash) {
      try {
        // getLedgerEntries, not getContractData: the latter reports every failure as not found.
        const key = xdr.LedgerKey.contractData(
          new xdr.LedgerKeyContractData({
            contract: Address.fromString(verifierId).toScAddress(),
            key: xdr.ScVal.scvLedgerKeyContractInstance(),
            durability: xdr.ContractDataDurability.persistent(),
          }),
        );
        const [instance] = (await server.getLedgerEntries(key)).entries;
        if (!instance) return fail("pin", "No contract at the verifier address", ctx);
        if (instance.liveUntilLedgerSeq !== undefined && instance.liveUntilLedgerSeq < latestLedger) {
          return inconclusive("pin", "Verifier instance is archived", ctx);
        }
        const executable = instance.val.contractData().val().instance().executable();
        if (executable.switch().name !== "contractExecutableWasm") return fail("pin", "Verifier is not a Wasm contract", ctx);
        wasmHash = Buffer.from(executable.wasmHash()).toString("hex");
      } catch (e) {
        return inconclusive("pin", `Verifier instance not readable: ${errorText(e)}`, ctx);
      }
    }
    if (!allowed.includes(wasmHash)) return fail("pin", `Verifier runs ${wasmHash}, not an accepted hash`, ctx);
    pinnedInstances.set(cacheKey, wasmHash);
    pass("pin", wasmHash);
  }

  // 9. Enforced simulation; the account's __check_auth decides.
  const invoke = xdr.HostFunction.hostFunctionTypeInvokeContract(call);
  const source = new Account(Keypair.random().publicKey(), "0");
  const tx = new TransactionBuilder(source, { fee: "100", networkPassphrase: opts.networkPassphrase })
    .addOperation(Operation.invokeHostFunction({ func: invoke, auth: [entry] }))
    .setTimeout(30)
    .build();
  let sim: rpc.Api.SimulateTransactionResponse;
  try {
    sim = await server.simulateTransaction(tx, undefined, "enforce");
  } catch (e) {
    return inconclusive("check_auth", `Simulation failed to run: ${errorText(e)}`, ctx);
  }
  if (!rpc.Api.isSimulationError(sim)) {
    return inconclusive("check_auth", "The verifier call succeeded, which the reference verifier never does", ctx);
  }
  const simulationError = sim.error;
  const withSim = { ...ctx, simulationError };
  if (simulationError.startsWith(`HostError: Error(Contract, #${AUTH_OK})`) && hasVerifierAuthOk(sim.events, verifierId)) {
    steps.push({ id: "check_auth", label: LABELS.check_auth, status: "pass", detail: `Error(Contract, #${AUTH_OK}) from the verifier: authorized` });
    if (!signIn) return result("valid", "The account authorized this message under its current rules", withSim);
    // 10. Only now, and atomically: a result other than `valid` must leave the nonce unused.
    try {
      if (!(await signIn.nonces.consume(message.nonce))) return fail("consume", "Nonce was already used", withSim);
    } catch (e) {
      return inconclusive("consume", `Nonce store failed: ${errorText(e)}`, withSim);
    }
    pass("consume", `Nonce ${message.nonce} used`);
    return result("valid", "The account authorized this sign-in under its current rules", withSim);
  }
  if (firstLine(simulationError).startsWith("HostError: Error(Auth,")) {
    return fail("check_auth", `Account rejected the signature: ${firstLine(simulationError)}`, withSim);
  }
  return inconclusive("check_auth", `Unexpected simulation result: ${firstLine(simulationError)}`, withSim);
}

/** True if a diagnostic error event from `verifierId` carries contract error AUTH_OK. */
function hasVerifierAuthOk(events: xdr.DiagnosticEvent[], verifierId: string): boolean {
  const target = Address.fromString(verifierId).toBuffer();
  return events.some((d) => {
    const event = d.event();
    const id = event.contractId();
    if (!id || !Buffer.from(id as unknown as Uint8Array).equals(target)) return false;
    const topics = event.body().v0().topics();
    if (topics.length < 2) return false;
    if (topics[0].switch().name !== "scvSymbol" || topics[0].sym().toString() !== "error") return false;
    if (topics[1].switch().name !== "scvError") return false;
    const err = topics[1].error();
    return err.switch().name === "sceContract" && err.contractCode() === AUTH_OK;
  });
}

const firstLine = (s: string) => s.split("\n")[0];
const errorText = (e: unknown) => (e instanceof Error ? e.message : String(e));
