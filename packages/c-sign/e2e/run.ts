// End-to-end experiments on Stellar testnet. Writes docs/EXPERIMENTS.md.
//
//   pnpm e2e
//
// Every account, key and sponsor is created fresh, so the run is repeatable.
import { writeFileSync } from "node:fs";
import { Account, Address, Keypair, Operation, SorobanDataBuilder, TransactionBuilder, rpc, xdr, type Transaction } from "@stellar/stellar-sdk";
import {
  DEFAULT_CONTEXT_RULE_IDS,
  buildMessageEntry,
  encodeEntry,
  entrySignaturePayload,
  messageToScVal,
  ozAuthDigest,
  ozAuthDigestPreimage,
  ozEd25519Signer,
  randomEntryNonce,
  signOzEntryWithEd25519,
  verifyMessage,
  type OzDigestScheme,
  type OzEd25519Key,
  type SignedMessage,
  type VerifyOptions,
  type VerifyResult,
} from "../src/index.js";
import {
  OZ_ACCOUNT_WASM,
  OZ_ACCOUNT_WASM_V08,
  OZ_ED25519_VERIFIER,
  OZ_THRESHOLD_POLICY,
  adminCall,
  contractCodeKey,
  contractInstanceKey,
  deployEd25519Account,
  deployOzAccount,
  deployments,
  ed25519Key,
  fundedKeypair,
  networkPassphrase,
  nonceConsumed,
  readContract,
  rpcUrl,
  server,
  signEd25519AccountEntry,
  failureTrace,
  submit,
  submitVerifyCall,
  thresholdPolicies,
} from "./testnet.js";

const DOMAIN = "demo.c-sign.dev";
const [VERIFIER_A, VERIFIER_B] = deployments.instances;
const FAKE = deployments.fakeVerifier.id;
const NONREV = deployments.nonRevertingVerifier.id;

interface Row {
  id: string;
  experiment: string;
  expected: string;
  observed: string;
  pass: boolean;
  evidence?: string;
}
const rows: Row[] = [];
const txLink = (hash: string) => `[\`${hash.slice(0, 8)}…\`](https://stellar.expert/explorer/testnet/tx/${hash})`;
const contractLink = (id: string) => `[\`${id.slice(0, 8)}…\`](https://stellar.expert/explorer/testnet/contract/${id})`;

function record(row: Row) {
  rows.push(row);
  console.log(`${row.pass ? "PASS" : "FAIL"}  ${row.id}  ${row.experiment}: ${row.observed}`);
}

function message(statement: string): SignedMessage {
  const nonce = Buffer.from(Keypair.random().rawPublicKey()).toString("hex").slice(0, 16);
  return { version: "1", domain: DOMAIN, statement, nonce, issuedAt: Math.floor(Date.now() / 1000) };
}

async function sign(
  account: string,
  keys: OzEd25519Key[],
  msg: SignedMessage,
  opts: { verifierId?: string; nonce?: xdr.Int64; expirationLedger?: number; scheme?: OzDigestScheme } = {},
): Promise<xdr.SorobanAuthorizationEntry> {
  const latest = (await server.getLatestLedger()).sequence;
  const entry = buildMessageEntry({
    verifierId: opts.verifierId ?? VERIFIER_A,
    account,
    message: msg,
    expirationLedger: opts.expirationLedger ?? latest + 720,
    nonce: opts.nonce,
  });
  return signOzEntryWithEd25519(entry, keys, networkPassphrase, opts.scheme ?? "legacy-concat");
}

const verify = (entry: xdr.SorobanAuthorizationEntry | string, extra: Partial<VerifyOptions> = {}): Promise<VerifyResult> =>
  verifyMessage({
    signature: typeof entry === "string" ? entry : encodeEntry(entry),
    rpcUrl,
    networkPassphrase,
    domain: DOMAIN,
    ...extra,
  });

const describe = (r: VerifyResult) =>
  r.status === "valid" ? "valid" : `${r.status} (${r.steps.find((s) => s.status === "fail" || s.status === "error")?.id}: ${r.reason})`;

/**
 * Largest statement, in bytes, that the account still authorizes. Bypasses the
 * library's provisional size checks on purpose and bisects on the enforcing
 * simulation; "authorized" means the verifier raised its success code.
 */
async function maxStatementBytes(
  account: string,
  keys: OzEd25519Key[],
): Promise<{ bytes: number; msgBytes: number; requestBytes: number; failure: string }> {
  const latest = (await server.getLatestLedger()).sequence;
  const base = message("x");
  const attempt = async (n: number) => {
    const raw = messageToScVal({ ...base, statement: "a".repeat(n) }, false);
    const entry = buildMessageEntry({ verifierId: VERIFIER_A, account, message: base, expirationLedger: latest + 720 });
    const call = entry.rootInvocation().function().contractFn();
    call.args([call.args()[0], raw]);
    const signed = signOzEntryWithEd25519(entry, keys, networkPassphrase, "legacy-concat");
    const tx = new TransactionBuilder(new Account(Keypair.random().publicKey(), "0"), { fee: "100", networkPassphrase })
      .addOperation(Operation.invokeHostFunction({ func: xdr.HostFunction.hostFunctionTypeInvokeContract(call), auth: [signed] }))
      .setTimeout(60)
      .build();
    // Raw JSON-RPC, so a transport refusal (such as a request-size cap) is reported verbatim.
    const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "simulateTransaction", params: { transaction: tx.toXDR(), authMode: "enforce" } });
    const text = await (await fetch(rpcUrl, { method: "POST", headers: { "content-type": "application/json" }, body })).text();
    let error: string;
    try {
      const json = JSON.parse(text);
      error = String(json.result?.error ?? json.error?.message ?? "simulation succeeded").split("\n")[0];
    } catch {
      error = `RPC: ${text.trim().slice(0, 80)}`;
    }
    return { ok: error.startsWith("HostError: Error(Contract, #1)"), error, msgBytes: raw.toXDR().length, requestBytes: body.length };
  };
  let lo = 0;
  let hi = 1024 * 1024;
  const top = await attempt(hi);
  if (top.ok) return { bytes: hi, msgBytes: top.msgBytes, requestBytes: top.requestBytes, failure: "none up to the search bound" };
  let failure = top.error;
  while (hi - lo > 1) {
    const mid = Math.floor((lo + hi) / 2);
    const res = await attempt(mid);
    if (res.ok) lo = mid;
    else [hi, failure] = [mid, res.error];
  }
  const last = await attempt(lo);
  return { bytes: lo, msgBytes: last.msgBytes, requestBytes: last.requestBytes, failure };
}

async function main() {
  console.log("Setting up sponsor and accounts on testnet…");
  const sponsor = await fundedKeypair();
  const k1 = ed25519Key();
  const account = await deployOzAccount(sponsor, [k1]);
  const other = await deployOzAccount(sponsor, [ed25519Key()]);
  console.log(`account ${account.id}\nother   ${other.id}`);

  // ---- Positive cases ---------------------------------------------------
  const signIn = message("Sign in to the C-Sign demo");
  const s1 = await sign(account.id, [k1], signIn);
  let r = await verify(s1);
  record({
    id: "P1",
    experiment: "Valid signature, OpenZeppelin account with one Ed25519 signer",
    expected: "valid",
    observed: describe(r),
    pass: r.status === "valid",
    evidence: `account ${contractLink(account.id)}, deployed in ${txLink(account.hash)}; raw: \`${r.simulationError?.split("\n")[0]}\``,
  });

  r = await verify(await sign(account.id, [k1], message("Same account, second instance"), { verifierId: VERIFIER_B }));
  record({
    id: "P2",
    experiment: "Same account signs for verifier instance B (no canonical instance)",
    expected: "valid",
    observed: describe(r),
    pass: r.status === "valid",
    evidence: `instance ${contractLink(VERIFIER_B)}`,
  });

  // ---- E1: hash pinning ---------------------------------------------------
  const attacker = ed25519Key();
  const forged = await sign(account.id, [attacker], message("Forged: signed by a key the account never had"), { verifierId: FAKE });
  const unpinned = await verify(forged, { unsafeSkipPinning: true });
  record({
    id: "E1a",
    experiment: "Forged signature routed through the fake verifier, pinning disabled",
    expected: "valid (the attack works without pinning)",
    observed: describe(unpinned),
    pass: unpinned.status === "valid",
    evidence: `fake verifier ${contractLink(FAKE)} never calls require_auth`,
  });
  const pinned = await verify(forged);
  record({
    id: "E1b",
    experiment: "Same forged signature with Wasm-hash pinning",
    expected: "invalid at pin",
    observed: describe(pinned),
    pass: pinned.status === "invalid" && pinned.steps.find((s) => s.id === "pin")?.status === "fail",
  });

  // ---- E2: nonce on on-chain submission ------------------------------------
  // The reference verifier cannot be simulated to success, so the footprint is
  // taken from the same call on the non-reverting fixture and pointed at A.
  const shared = randomEntryNonce();
  const e2Msg = message("Nonce experiment");
  const real = await sign(account.id, [k1], e2Msg, { nonce: shared });
  const twin = await sign(account.id, [k1], e2Msg, { nonce: shared, verifierId: NONREV });
  const twinCall = twin.rootInvocation().function().contractFn();
  const twinTx = new TransactionBuilder(new Account(sponsor.publicKey(), "0"), { fee: "100", networkPassphrase })
    .addOperation(Operation.invokeHostFunction({ func: xdr.HostFunction.hostFunctionTypeInvokeContract(twinCall), auth: [twin] }))
    .setTimeout(60)
    .build() as Transaction;
  const twinSim = await server.simulateTransaction(twinTx, undefined, "enforce");
  if (!rpc.Api.isSimulationSuccess(twinSim)) throw new Error(`Twin simulation failed: ${(twinSim as { error?: string }).error}`);
  const data = twinSim.transactionData.build();
  const fp = data.resources().footprint();
  const nonrevInstance = contractInstanceKey(NONREV).toXDR("base64");
  const nonrevCode = contractCodeKey(deployments.nonRevertingVerifier.wasmHash).toXDR("base64");
  const readOnly = fp.readOnly().map((k) => {
    const key = k.toXDR("base64");
    if (key === nonrevInstance) return contractInstanceKey(VERIFIER_A);
    if (key === nonrevCode) return contractCodeKey(deployments.wasmHash);
    return k;
  });
  const resources = data.resources();
  const patched = new SorobanDataBuilder(data)
    .setReadOnly(readOnly)
    .setReadWrite(fp.readWrite())
    .setResources(
      Math.ceil(resources.instructions() * 1.5),
      Math.ceil(resources.diskReadBytes() * 1.5) + 4096,
      resources.writeBytes() + 1024,
    )
    .setResourceFee(BigInt(data.resourceFee().toString()) * 2n + 100000n)
    .build();

  const before = await nonceConsumed(account.id, shared);
  const onchain = await submitVerifyCall(sponsor, real, patched);
  const after = await nonceConsumed(account.id, shared);
  const trace = await failureTrace(onchain.hash);
  record({
    id: "E2a",
    experiment: "Submit a valid signature on-chain to the reference verifier",
    expected: "transaction FAILED, nonce not consumed",
    observed: `transaction ${onchain.status}, nonce consumed before=${before} after=${after}`,
    pass: onchain.status === "FAILED" && !after && trace.includes("__check_auth returned") && trace.endsWith("raised Error(Contract, #1)"),
    evidence: `${txLink(onchain.hash)}; on-chain trace: ${trace}`,
  });
  r = await verify(real);
  record({
    id: "E2b",
    experiment: "Verify the same signature after the on-chain attempt",
    expected: "valid",
    observed: describe(r),
    pass: r.status === "valid",
  });

  const burnNonce = randomEntryNonce();
  const burnMsg = message("Nonce experiment, non-reverting verifier");
  const burn = await sign(account.id, [k1], burnMsg, { nonce: burnNonce, verifierId: NONREV });
  const burnCall = burn.rootInvocation().function().contractFn();
  const burnTx = new TransactionBuilder(await server.getAccount(sponsor.publicKey()), { fee: "1000000", networkPassphrase })
    .addOperation(Operation.invokeHostFunction({ func: xdr.HostFunction.hostFunctionTypeInvokeContract(burnCall), auth: [burn] }))
    .setTimeout(60)
    .build();
  const preparedBurn = await server.prepareTransaction(burnTx);
  preparedBurn.sign(sponsor);
  const burned = await submit(preparedBurn);
  const burnedNonce = await nonceConsumed(account.id, burnNonce);
  const resim = await server.simulateTransaction(
    new TransactionBuilder(new Account(sponsor.publicKey(), "0"), { fee: "100", networkPassphrase })
      .addOperation(Operation.invokeHostFunction({ func: xdr.HostFunction.hostFunctionTypeInvokeContract(burnCall), auth: [burn] }))
      .setTimeout(60)
      .build(),
    undefined,
    "enforce",
  );
  const resimError = rpc.Api.isSimulationError(resim) ? resim.error.split("\n")[0] : "simulation succeeded";
  record({
    id: "E2c",
    experiment: "Comparison: submit a signature to the non-reverting fixture",
    expected: "transaction SUCCESS, nonce consumed, signature no longer verifies",
    observed: `transaction ${burned.status}, nonce consumed=${burnedNonce}, re-simulation: ${resimError}`,
    pass: burned.status === "SUCCESS" && burnedNonce && rpc.Api.isSimulationError(resim),
    evidence: txLink(burned.hash),
  });

  // ---- Negative cases ------------------------------------------------------
  const tampered = xdr.SorobanAuthorizationEntry.fromXDR(s1.toXDR());
  const args = tampered.rootInvocation().function().contractFn().args();
  args[1] = messageToScVal({ ...signIn, statement: "Transfer everything" });
  tampered.rootInvocation().function().contractFn().args(args);
  r = await verify(tampered);
  record({ id: "N1", experiment: "Tampered statement", expected: "invalid at check_auth", observed: describe(r), pass: r.status === "invalid" });

  r = await verify(s1, { domain: "evil.example" });
  record({ id: "N2", experiment: "Signature presented to another domain", expected: "invalid at domain", observed: describe(r), pass: r.status === "invalid" });

  r = await verify(await sign(other.id, [k1], message("Signed by a key the other account does not have")));
  record({
    id: "N3",
    experiment: "Entry for another account, signed with this account's key",
    expected: "invalid at check_auth",
    observed: describe(r),
    pass: r.status === "invalid",
  });

  const latest = (await server.getLatestLedger()).sequence;
  r = await verify(await sign(account.id, [k1], message("Expired"), { expirationLedger: latest - 1 }));
  record({ id: "N4", experiment: "Expired signature", expected: "invalid at expiration", observed: describe(r), pass: r.status === "invalid" });

  r = await verify(s1, { freshness: { checkNonce: () => false } });
  record({ id: "N5", experiment: "Reused sign-in nonce", expected: "invalid at freshness", observed: describe(r), pass: r.status === "invalid" });

  // ---- Key rotation: validity follows the account's current rules ------------
  const k2 = ed25519Key();
  const added = await adminCall(sponsor, account.id, "add_signer", [xdr.ScVal.scvU32(0), ozEd25519Signer(k2)], [k1]);
  r = await verify(s1);
  record({
    id: "R1",
    experiment: "Add a second signer (policy-less rule now needs both)",
    expected: "old one-signer signature becomes invalid",
    observed: `add_signer ${added.status}; old signature ${describe(r)}`,
    pass: added.status === "SUCCESS" && r.status === "invalid",
    evidence: txLink(added.hash),
  });

  const removed = await adminCall(sponsor, account.id, "remove_signer", [xdr.ScVal.scvU32(0), xdr.ScVal.scvU32(0)], [k1, k2]);
  const oldAgain = await verify(s1);
  const fresh = await verify(await sign(account.id, [k2], message("Signed with the rotated key")));
  record({
    id: "R2",
    experiment: "Remove the original signer; sign with the new key",
    expected: "old signature invalid, new signature valid",
    observed: `remove_signer ${removed.status}; old ${describe(oldAgain)}; new ${describe(fresh)}`,
    pass: removed.status === "SUCCESS" && oldAgain.status === "invalid" && fresh.status === "valid",
    evidence: txLink(removed.hash),
  });

  // ---- Threshold policy: validity follows policy state, not only the signer set ----
  const [t1, t2, t3] = [ed25519Key(), ed25519Key(), ed25519Key()];
  const multisig = await deployOzAccount(sponsor, [t1, t2, t3], thresholdPolicies(2));
  console.log(`multisig ${multisig.id}`);
  const twoOfThree = await sign(multisig.id, [t1, t3], message("Approve with two of three keys"));
  r = await verify(twoOfThree);
  record({
    id: "T1",
    experiment: "OpenZeppelin account, 2-of-3 threshold policy: two keys sign",
    expected: "valid",
    observed: describe(r),
    pass: r.status === "valid",
    evidence: `account ${contractLink(multisig.id)}, deployed in ${txLink(multisig.hash)}`,
  });

  r = await verify(await sign(multisig.id, [t2], message("Approve with one key")));
  record({
    id: "T2",
    experiment: "Same account: one key signs",
    expected: "invalid at check_auth",
    observed: describe(r),
    pass: r.status === "invalid" && r.steps.find((s) => s.id === "check_auth")?.status === "fail",
  });

  // set_threshold takes the rule as stored; the account calls the policy through execute().
  const rule = await readContract(multisig.id, "get_context_rule", [xdr.ScVal.scvU32(0)]);
  const raised = await adminCall(
    sponsor,
    multisig.id,
    "execute",
    [
      Address.fromString(OZ_THRESHOLD_POLICY).toScVal(),
      xdr.ScVal.scvSymbol("set_threshold"),
      xdr.ScVal.scvVec([xdr.ScVal.scvU32(3), rule, Address.fromString(multisig.id).toScVal()]),
    ],
    [t1, t2],
  );
  const oldTwo = await verify(twoOfThree);
  const allThree = await verify(await sign(multisig.id, [t1, t2, t3], message("Approve with all three keys")));
  record({
    id: "T3",
    experiment: "Raise the threshold to 3 (policy state only; signers unchanged)",
    expected: "old two-key signature invalid, three-key signature valid",
    observed: `set_threshold ${raised.status}; old ${describe(oldTwo)}; three keys ${describe(allThree)}`,
    pass: raised.status === "SUCCESS" && oldTwo.status === "invalid" && allThree.status === "valid",
    evidence: txLink(raised.hash),
  });

  // ---- Minimal ed25519 account: another signing format, same verification ----
  const plainKey = Keypair.random();
  const plain = await deployEd25519Account(sponsor, plainKey);
  console.log(`ed25519  ${plain.id}`);
  const plainEntry = async (key: Keypair, statement: string) => {
    const latestLedger = (await server.getLatestLedger()).sequence;
    const unsigned = buildMessageEntry({ verifierId: VERIFIER_A, account: plain.id, message: message(statement), expirationLedger: latestLedger + 720 });
    return signEd25519AccountEntry(unsigned, key);
  };
  r = await verify(await plainEntry(plainKey, "Sign in with a minimal ed25519 account"));
  record({
    id: "M1",
    experiment: "Minimal ed25519 account (bare signature over the payload, no rules or policies)",
    expected: "valid",
    observed: describe(r),
    pass: r.status === "valid",
    evidence: `account ${contractLink(plain.id)}, deployed in ${txLink(plain.hash)}`,
  });
  r = await verify(await plainEntry(Keypair.random(), "Signed with a key the account does not have"));
  record({
    id: "M2",
    experiment: "Same account, signed with another key",
    expected: "invalid at check_auth",
    observed: describe(r),
    pass: r.status === "invalid" && r.steps.find((s) => s.id === "check_auth")?.status === "fail",
  });

  // ---- OpenZeppelin stellar-accounts 0.8.0: the digest also binds the account ----
  const v08Key = ed25519Key();
  const v08 = await deployOzAccount(sponsor, [v08Key], undefined, OZ_ACCOUNT_WASM_V08);
  console.log(`oz 0.8.0 ${v08.id}`);
  const o1 = await sign(v08.id, [v08Key], message("Sign in with an OpenZeppelin 0.8.0 account"), { scheme: "preimage-v1" });
  r = await verify(o1);
  record({
    id: "O1",
    experiment: "OpenZeppelin 0.8.0 account with one Ed25519 signer, `preimage-v1` digest",
    expected: "valid",
    observed: describe(r),
    pass: r.status === "valid",
    evidence: `account ${contractLink(v08.id)}, deployed in ${txLink(v08.hash)}`,
  });
  r = await verify(await sign(v08.id, [v08Key], message("Same account, pre-0.8 digest"), { scheme: "legacy-concat" }));
  record({
    id: "O2",
    experiment: "Same account, signed with the pre-0.8 `legacy-concat` digest",
    expected: "invalid at check_auth",
    observed: describe(r),
    pass: r.status === "invalid" && r.steps.find((s) => s.id === "check_auth")?.status === "fail",
  });
  const preimage = ozAuthDigestPreimage(v08.id, entrySignaturePayload(o1, networkPassphrase), DEFAULT_CONTEXT_RULE_IDS);
  const onchainDigest = Buffer.from((await readContract(v08.id, "auth_digest", [preimage])).bytes());
  const localDigest = ozAuthDigest(o1, networkPassphrase, "preimage-v1");
  record({
    id: "O3",
    experiment: "The account's `auth_digest` for the O1 entry, against the library's `preimage-v1` digest",
    expected: "equal",
    observed: `auth_digest \`${onchainDigest.toString("hex").slice(0, 16)}…\`, library \`${localDigest.toString("hex").slice(0, 16)}…\`: ${onchainDigest.equals(localDigest) ? "equal" : "different"}`,
    pass: onchainDigest.equals(localDigest),
  });

  // ---- Size limits: the largest statement each account type authorizes ---------
  for (const [id, label, acct, keys] of [
    ["S1", "OpenZeppelin account, no policy", account.id, [k2]],
    ["S2", "OpenZeppelin account with the threshold policy (its enforce() emits the call context as an event)", multisig.id, [t1, t2, t3]],
  ] as const) {
    const size = await maxStatementBytes(acct, [...keys]);
    record({
      id,
      experiment: `Size limit, ${label}`,
      expected: "at least 1024 bytes (the provisional statement limit)",
      observed: `largest statement ${size.bytes} bytes (msg ${size.msgBytes} bytes as XDR, simulation request ${size.requestBytes} bytes); one byte more: \`${size.failure}\``,
      pass: size.bytes >= 1024,
    });
  }

  // ---- Latency ---------------------------------------------------------------
  const sample = await sign(account.id, [k2], message("Latency sample"));
  const times: number[] = [];
  for (let i = 0; i < 20; i++) {
    const t = performance.now();
    const res = await verify(sample);
    times.push(performance.now() - t);
    if (res.status !== "valid") throw new Error(`Latency run ${i} was ${res.status}`);
  }
  times.sort((a, b) => a - b);
  const median = (times[9] + times[10]) / 2;
  record({
    id: "L1",
    experiment: `Verification latency, public testnet RPC (${new URL(rpcUrl).host}), 20 runs`,
    expected: "median under 2 s",
    observed: `median ${Math.round(median)} ms, max ${Math.round(times[19])} ms`,
    pass: median < 2000,
  });

  writeReport(account.id, other.id, multisig.id, plain.id, v08.id);
  writeFileSync(new URL("./.last-run.json", import.meta.url), JSON.stringify({ account: account.id, validSignature: encodeEntry(fresh.status === "valid" ? sample : s1) }, null, 2));
  const failed = rows.filter((row) => !row.pass);
  console.log(failed.length ? `\n${failed.length} experiment(s) failed` : "\nAll experiments passed");
  process.exit(failed.length ? 1 : 0);
}

function writeReport(accountId: string, otherId: string, multisigId: string, plainId: string, v08Id: string) {
  const date = new Date().toISOString().replace("T", " ").slice(0, 16) + " UTC";
  const md = [
    "# Testnet experiments",
    "",
    `Generated by \`pnpm e2e\` (\`packages/c-sign/e2e/run.ts\`) on ${date}. Every run creates fresh keys, a fresh sponsor and fresh OpenZeppelin smart accounts (Wasm \`${OZ_ACCOUNT_WASM.slice(0, 8)}…\`, stellar-accounts before 0.8.0, signed with the \`legacy-concat\` digest; O1 to O3 use stellar-accounts 0.8.0, Wasm \`${OZ_ACCOUNT_WASM_V08.slice(0, 8)}…\`, \`preimage-v1\` digest; Ed25519 verifier ${contractLink(OZ_ED25519_VERIFIER)}, threshold policy ${contractLink(OZ_THRESHOLD_POLICY)}). RPC: \`${rpcUrl}\`.`,
    "",
    `- Account under test: ${contractLink(accountId)}; second account: ${contractLink(otherId)}; 2-of-3 account: ${contractLink(multisigId)}; minimal ed25519 account: ${contractLink(plainId)} (Wasm \`${deployments.ed25519Account.wasmHash.slice(0, 8)}…\`, [source](../experiments/contracts/ed25519-account)); OpenZeppelin 0.8.0 account: ${contractLink(v08Id)} (Wasm \`${OZ_ACCOUNT_WASM_V08}\`, built from stellar-contracts v0.8.0 \`examples/multisig-smart-account/account\`)`,
    `- Reference verifier instances: ${contractLink(VERIFIER_A)}, ${contractLink(VERIFIER_B)} (Wasm \`${deployments.wasmHash.slice(0, 8)}…\`)`,
    `- Fixtures: fake verifier ${contractLink(FAKE)}, non-reverting verifier ${contractLink(NONREV)}`,
    "",
    "| # | Experiment | Expected | Observed | Result | Evidence |",
    "|---|---|---|---|---|---|",
    ...rows.map((row) => `| ${row.id} | ${row.experiment} | ${row.expected} | ${row.observed.replace(/\|/g, "\\|")} | ${row.pass ? "pass" : "**FAIL**"} | ${row.evidence ?? ""} |`),
    "",
    "## What this shows",
    "",
    "- **P1, P2:** an unmodified OpenZeppelin smart account signs a message with its existing signer, and any instance of the reference Wasm works.",
    "- **E1:** without Wasm-hash pinning, a fake verifier lets anyone \"sign\" for any account. Pinning rejects it before simulation.",
    "- **E2:** submitting a signature on-chain fails and leaves the account's nonce unused, so the signature stays verifiable. The same experiment with a verifier that succeeds burns the nonce. This answers the nonce question raised in stellar-protocol#2027.",
    "- **N1 to N5:** tampering, cross-domain use, cross-account use, expiry and nonce replay are rejected.",
    "- **R1, R2:** validity follows the account's current rules, as with ERC-1271: after key rotation the old signature no longer verifies and the new key does.",
    "- **T1 to T3:** a threshold policy decides as well: two of three keys verify, one does not, and after the threshold is raised to three the same two-key signature stops verifying while a three-key signature verifies. Verification never re-implements signer or policy logic.",
    "- **M1, M2:** a minimal non-OpenZeppelin account, which signs the raw payload instead of an OpenZeppelin auth digest, verifies through the same path. The SEP standardizes the entry, not the account's signature format.",
    "- **O1 to O3:** OpenZeppelin stellar-accounts 0.8.0 changed what its signers sign: `sha256(xdr(AuthDigestPreimage { account, signature_payload, context_rule_ids }))`, which also binds the account address. A 0.8.0 account verifies through the same path once the wallet signs the new digest, a signature over the pre-0.8 digest is rejected by the account, and the library's digest equals the one the deployed account computes. Only the wallet's signing step depends on the account version; the verifier and the entry are unchanged.",
    "- **S1, S2:** the largest statement each account authorizes, found by bisection on the enforcing simulation with the library's provisional limits bypassed. The host accepts statements far beyond the SEP limits, with or without the threshold policy: the policy's events are rolled back with the failing verifier call, so event-size limits never apply. What stops verification is the RPC's request-size cap, which depends on the provider. The SEP limits are therefore a display and transport choice, not a host constraint.",
    "",
  ].join("\n");
  writeFileSync(new URL("../../../docs/EXPERIMENTS.md", import.meta.url), md);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
