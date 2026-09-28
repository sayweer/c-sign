import { Account, Address, Keypair, Operation, TransactionBuilder, rpc, xdr } from "@stellar/stellar-sdk";
import { AUTH_OK, REFERENCE_WASM_HASH, VERIFY_FUNCTION } from "./constants.js";
import { CSignError } from "./errors.js";
import { buildVerifyInvocation } from "./entry.js";
import { messageFromScVal, type SignedMessage } from "./message.js";

export type VerifyStatus = "valid" | "invalid" | "inconclusive";
export type StepStatus = "pass" | "fail" | "skip" | "error";

export interface VerifyStep {
  id: "decode" | "shape" | "credentials" | "rebuild" | "message" | "domain" | "freshness" | "expiration" | "pin" | "check_auth";
  label: string;
  status: StepStatus;
  detail: string;
}

export interface VerifyOptions {
  /** Base64 XDR `SorobanAuthorizationEntry`. */
  signature: string;
  rpcUrl: string;
  networkPassphrase: string;
  /** Expected signer. If omitted, the account named in the entry is reported. */
  address?: string;
  /** The relying party's own domain. Omit only for inspection tools; a sign-in MUST set it. */
  domain?: string;
  /** Accepted verifier Wasm hashes. Defaults to the reference hash. */
  allowedWasmHashes?: string[];
  /** Freshness for sign-in: nonce ownership/unused check and maximum age of `issued_at`. */
  freshness?: {
    checkNonce: (nonce: string) => boolean | Promise<boolean>;
    maxAgeSeconds?: number;
  };
  /** Allowed clock skew in seconds (default 300). */
  clockSkewSeconds?: number;
  /** Unix seconds; defaults to now. */
  now?: number;
  /** Experiments only: skips Wasm-hash pinning to show why it is required. */
  unsafeSkipPinning?: boolean;
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
  expiration: "Signature expiration",
  pin: "Verifier runs the pinned Wasm",
  check_auth: "Account's __check_auth (enforced simulation)",
};

const ORDER = Object.keys(LABELS) as VerifyStep["id"][];

// A pinned instance cannot change its code, so a positive check can be cached.
const pinnedInstances = new Map<string, string>();

/**
 * Verifies a C-Sign signature (SPEC §6). Never throws: network failures and
 * archived entries are `inconclusive`, rule violations are `invalid`.
 */
export async function verifyMessage(opts: VerifyOptions): Promise<VerifyResult> {
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
  let entry: xdr.SorobanAuthorizationEntry;
  try {
    entry = xdr.SorobanAuthorizationEntry.fromXDR(opts.signature.trim(), "base64");
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
  if (opts.domain === undefined) {
    steps.push({ id: "domain", label: LABELS.domain, status: "skip", detail: `Not checked (signed for ${message.domain})` });
  } else if (message.domain !== opts.domain) {
    return fail("domain", `Signed for ${message.domain}, this site is ${opts.domain}`, ctx);
  } else {
    pass("domain", message.domain);
  }

  const now = opts.now ?? Math.floor(Date.now() / 1000);
  const skew = opts.clockSkewSeconds ?? 300;
  if (message.issuedAt > now + skew) return fail("freshness", "issued_at is in the future", ctx);
  if (message.expirationTime !== undefined && now > message.expirationTime + skew) {
    return fail("freshness", "Message expiration_time has passed", ctx);
  }
  if (message.notBefore !== undefined && now + skew < message.notBefore) return fail("freshness", "Message is not valid yet (not_before)", ctx);
  if (opts.freshness) {
    const maxAge = opts.freshness.maxAgeSeconds ?? 300;
    if (now - message.issuedAt > maxAge + skew) return fail("freshness", `Issued ${now - message.issuedAt}s ago, max ${maxAge}s`, ctx);
    if (!(await opts.freshness.checkNonce(message.nonce))) return fail("freshness", "Nonce was not issued here or was already used", ctx);
    pass("freshness", `Nonce ${message.nonce} accepted`);
  } else {
    steps.push({ id: "freshness", label: LABELS.freshness, status: "skip", detail: "Not a sign-in: nonce and age not checked" });
  }

  const server = new rpc.Server(opts.rpcUrl, { allowHttp: opts.rpcUrl.startsWith("http://") });

  // 6. Expiration
  let latestLedger: number;
  try {
    latestLedger = (await server.getLatestLedger()).sequence;
  } catch (e) {
    return inconclusive("expiration", `RPC unavailable: ${errorText(e)}`, ctx);
  }
  const expiration = creds.signatureExpirationLedger();
  if (expiration < latestLedger) {
    return fail("expiration", `Expired at ledger ${expiration} (now ${latestLedger})`, ctx);
  }
  pass("expiration", `Valid until ledger ${expiration} (now ${latestLedger})`);

  // 7. Pin the verifier instance
  const allowed = (opts.allowedWasmHashes ?? [REFERENCE_WASM_HASH]).map((h) => h.toLowerCase());
  if (opts.unsafeSkipPinning) {
    steps.push({ id: "pin", label: LABELS.pin, status: "skip", detail: "UNSAFE: pinning disabled" });
  } else {
    const cacheKey = `${opts.networkPassphrase}|${verifierId}`;
    let wasmHash = pinnedInstances.get(cacheKey);
    if (!wasmHash) {
      try {
        const instance = await server.getContractData(verifierId, xdr.ScVal.scvLedgerKeyContractInstance(), rpc.Durability.Persistent);
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

  // 8. Enforced simulation; the account's __check_auth decides.
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
    return result("valid", "The account authorized this message under its current rules", withSim);
  }
  if (simulationError.includes("Error(Auth,")) {
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
