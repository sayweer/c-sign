import { readFileSync } from "node:fs";
import { afterAll, describe, expect, it, vi } from "vitest";
import { Address, Keypair, StrKey, hash, rpc, xdr } from "@stellar/stellar-sdk";
import * as lib from "../src/index.js";
import {
  decodeEntry,
  entrySignaturePayload,
  messageFromScVal,
  ozAuthDigest,
  ozAuthDigestPreimage,
  verifyMessage,
  type VerifyResult,
} from "../src/index.js";
import { VECTORS_PATH, buildVectors, serializeVectors } from "../scripts/vectors.js";

const vectors = buildVectors();

/**
 * Vector cases the library does not pass yet, keyed `section/case`, with the row of the
 * Known gaps table in docs/THREAT-MODEL.md that closes them (library v0.2). A listed case
 * that starts passing fails the test, so the list only shrinks.
 */
const KNOWN_GAPS: Record<string, string> = {
  ...Object.fromEntries(
    [
      "statement_line_feed",
      "statement_line_separator",
      "statement_bidi_override",
      "statement_zero_width_space",
      "resource_tab",
      "statement_invalid_utf8",
      "domain_uppercase",
      "domain_trailing_dot",
      "domain_default_port",
      "domain_with_scheme",
      "domain_with_path",
      "domain_with_userinfo",
      "domain_u_label",
    ].map((name) => [`messages.invalid/${name}`, "Characters and domain form"]),
  ),
  "structural/oversized_signature": "Input size",
  "structural/message_control_character": "Characters and domain form",
  "structural/issued_in_future": "Time",
  "structural/message_expired": "Time",
  "structural/message_not_yet_valid": "Time",
  "structural/stale_sign_in": "Time",
  "verification/sign_in_expiration_too_far": "Expiration",
  "verification/instance_missing": "Missing verifier instance",
  "verification/rpc_other_network": "Network and RPC",
  "verification/rpc_stale": "Network and RPC",
  "verification/auth_error_after_first_line": "Decision",
  "verification/valid_sign_in#nonce": "Nonce",
  "verification/sign_in_expiration_too_far#nonce": "Nonce",
  "verification/account_rejects#nonce": "Nonce",
  "verification/other_host_error#nonce": "Nonce",
  ...Object.fromEntries(vectors.wallet_domain.cases.map((c) => [`wallet_domain/${c.name}`, "Wallet side"])),
};

const results = new Map<string, boolean>();
const record = (key: string, passes: boolean) => results.set(key, passes);

const stepOf = (r: VerifyResult) => r.steps.find((s) => s.status === "fail" || s.status === "error")?.id;

describe("test vectors", () => {
  it("checked-in file matches the generator (run `pnpm --filter c-sign vectors`)", () => {
    expect(readFileSync(VECTORS_PATH, "utf8")).toBe(serializeVectors());
  });

  it("decodes every valid message back to its fields", () => {
    for (const v of vectors.messages.valid) {
      expect(() => messageFromScVal(xdr.ScVal.fromXDR(v.msg_xdr, "base64")), v.name).not.toThrow();
    }
  });

  it("invalid messages", () => {
    for (const v of vectors.messages.invalid) {
      let rejected = false;
      try {
        messageFromScVal(xdr.ScVal.fromXDR(v.msg_xdr, "base64"));
      } catch {
        rejected = true;
      }
      record(`messages.invalid/${v.name}`, rejected);
    }
  });

  it("signature payload is sha256 of the preimage", () => {
    for (const v of vectors.entries.cases) {
      const payload = entrySignaturePayload(decodeEntry(v.unsigned_entry_xdr), v.input.network_passphrase);
      expect(payload.toString("hex"), v.name).toBe(v.signature_payload_hex);
    }
  });

  it("oz_signing: digest and preimage recompute from the inputs, and every signature verifies against the digest", () => {
    for (const v of vectors.oz_signing.cases) {
      const { unsigned_entry_xdr, network_passphrase, context_rule_ids } = v.input;
      const entry = decodeEntry(unsigned_entry_xdr);
      const digest = ozAuthDigest(entry, network_passphrase, v.scheme, context_rule_ids);
      expect(digest.toString("hex"), v.name).toBe(v.auth_digest_hex);
      if (v.auth_digest_preimage_xdr !== undefined) {
        const preimage = ozAuthDigestPreimage(vectors.fixtures.account, entrySignaturePayload(entry, network_passphrase), context_rule_ids);
        expect(preimage.toXDR("base64"), v.name).toBe(v.auth_digest_preimage_xdr);
        expect(hash(Buffer.from(v.auth_digest_preimage_xdr, "base64")).toString("hex"), v.name).toBe(v.auth_digest_hex);
      }
      for (const s of v.signatures) {
        const publicKey = StrKey.encodeEd25519PublicKey(Buffer.from(vectors.fixtures.keys[s.key - 1].public_key_hex, "hex"));
        expect(Keypair.fromPublicKey(publicKey).verify(digest, Buffer.from(s.signature_hex, "hex")), `${v.name} key ${s.key}`).toBe(true);
      }
    }
  });

  it("structural cases, offline", async () => {
    for (const v of vectors.structural.cases) {
      const { domain, now, address, issued_nonces } = v.context;
      const r = await verifyMessage({
        signature: v.signature,
        rpcUrl: "http://127.0.0.1:1", // unreachable on purpose
        networkPassphrase: vectors.fixtures.network_passphrase,
        domain,
        now,
        address,
        freshness: issued_nonces && { checkNonce: (n) => issued_nonces.some((i) => i.nonce === n) },
      });
      record(`structural/${v.name}`, r.status === v.expected.status && stepOf(r) === v.expected.step);
    }
  });

  it("verification cases, against a stubbed RPC", async () => {
    for (const v of vectors.verification.cases) {
      stubRpc(v.rpc, v.verifier);
      const { domain, now, address, issued_nonces } = v.context;
      const r = await verifyMessage({
        signature: v.signature,
        rpcUrl: "http://127.0.0.1:1",
        networkPassphrase: vectors.fixtures.network_passphrase,
        domain,
        now,
        address,
        freshness: issued_nonces && { checkNonce: (n) => issued_nonces.some((i) => i.nonce === n) },
      });
      const expected: { status: string; step?: string; nonce_consumed?: boolean } = v.expected;
      record(`verification/${v.name}`, r.status === expected.status && (expected.step === undefined || stepOf(r) === expected.step));
      // The library has no nonce-consumption hook yet, so these cannot pass.
      if (expected.nonce_consumed !== undefined) record(`verification/${v.name}#nonce`, false);
    }
    vi.restoreAllMocks();
  });

  it("wallet domain cases", () => {
    const domainFromOrigin = (lib as Record<string, unknown>).domainFromOrigin as
      | ((origin: string, opts?: { developerMode?: boolean }) => string | undefined)
      | undefined;
    for (const v of vectors.wallet_domain.cases) {
      const got = domainFromOrigin?.(v.origin, { developerMode: v.developer_mode });
      const want = "domain" in v.expected ? v.expected.domain : undefined;
      record(`wallet_domain/${v.name}`, domainFromOrigin !== undefined && got === want);
    }
  });

  afterAll(() => {
    // Runs after every case was recorded: each case passes unless it is a known gap, and no known gap passes.
    const failing = [...results].filter(([key, passes]) => !passes && !(key in KNOWN_GAPS)).map(([key]) => key);
    const closed = Object.keys(KNOWN_GAPS).filter((key) => results.get(key) === true);
    const stale = Object.keys(KNOWN_GAPS).filter((key) => !results.has(key));
    expect({ failing, closed, stale }).toEqual({ failing: [], closed: [], stale: [] });
  });
});

/** Answers the library's RPC calls from a vector's `rpc` state. */
function stubRpc(state: (typeof vectors.verification.cases)[number]["rpc"], verifier: string) {
  vi.restoreAllMocks();
  const proto = rpc.Server.prototype;
  vi.spyOn(proto, "getNetwork").mockResolvedValue({ passphrase: state.network_passphrase, protocolVersion: "25" } as never);
  vi.spyOn(proto, "getLatestLedger").mockResolvedValue({
    id: "00".repeat(32),
    sequence: state.latest_ledger,
    protocolVersion: "25",
    closeTime: String(state.latest_ledger_close_time),
  } as never);
  // getContractData goes through this private method, so a missing entry looks as it does on a real RPC.
  const ledgerEntries = proto as unknown as { _getLedgerEntries: (...keys: xdr.LedgerKey[]) => Promise<unknown> };
  vi.spyOn(ledgerEntries, "_getLedgerEntries").mockImplementation(async (...keys) => {
    const instance = state.verifier_instance;
    if (instance.state === "missing") return { entries: [], latestLedger: state.latest_ledger };
    const executable =
      instance.state === "external_ref"
        ? xdr.ContractExecutable.contractExecutableExternalRef(
            new xdr.ContractExecutableExternalRef({ executableOwner: Address.fromString(vectors.fixtures.other_account).toScAddress(), tag: "verifier" }),
          )
        : xdr.ContractExecutable.contractExecutableWasm(Buffer.from("wasm_hash" in instance ? instance.wasm_hash : REFERENCE_WASM_HASH, "hex"));
    const data = xdr.LedgerEntryData.contractData(
      new xdr.ContractDataEntry({
        ext: new xdr.ExtensionPoint(0),
        contract: Address.fromString(verifier).toScAddress(),
        key: xdr.ScVal.scvLedgerKeyContractInstance(),
        durability: xdr.ContractDataDurability.persistent(),
        val: xdr.ScVal.scvContractInstance(new xdr.ScContractInstance({ executable, storage: null })),
      }),
    );
    return {
      latestLedger: state.latest_ledger,
      entries: [
        {
          key: keys[0].toXDR("base64"),
          xdr: data.toXDR("base64"),
          lastModifiedLedgerSeq: 1,
          liveUntilLedgerSeq: instance.state === "archived" ? state.latest_ledger - 1 : state.latest_ledger + 100_000,
        },
      ],
    };
  });
  vi.spyOn(proto, "simulateTransaction").mockImplementation((async () => {
    const sim = state.simulation;
    if ("succeeded" in sim) return { id: "1", latestLedger: state.latest_ledger, events: [], _parsed: true, transactionData: {}, minResourceFee: "0" };
    const events = sim.contract_error_events.map(({ contract, code }) => errorEvent(contract === "verifier" ? verifier : vectors.fixtures.account, code));
    return { id: "1", latestLedger: state.latest_ledger, events, _parsed: true, error: sim.error };
  }) as never);
}

const REFERENCE_WASM_HASH = vectors.reference_wasm_hash;

function errorEvent(contract: string, code: number): xdr.DiagnosticEvent {
  return new xdr.DiagnosticEvent({
    inSuccessfulContractCall: false,
    event: new xdr.ContractEvent({
      ext: new xdr.ExtensionPoint(0),
      contractId: Address.fromString(contract).toScAddress().contractId(),
      type: xdr.ContractEventType.diagnostic(),
      body: new xdr.ContractEventBody(
        0,
        new xdr.ContractEventV0({
          topics: [xdr.ScVal.scvSymbol("error"), xdr.ScVal.scvError(xdr.ScError.sceContract(code))],
          data: xdr.ScVal.scvVoid(),
        }),
      ),
    }),
  });
}
