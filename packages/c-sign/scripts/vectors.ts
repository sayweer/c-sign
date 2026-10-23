/**
 * Generates `vectors/c-sign-v1.json`, the language-neutral test vectors for
 * the draft SEP (docs/SPEC.md). Everything is deterministic: fixed addresses,
 * fixed auth-entry nonces and test-only Ed25519 keys derived from public seeds.
 *
 *   pnpm --filter c-sign vectors
 *
 * `test/vectors.test.ts` fails if the checked-in file drifts from this script.
 */
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Address, Keypair, Networks, StrKey, buildAuthorizationEntryPreimage, hash, xdr } from "@stellar/stellar-sdk";
import {
  REFERENCE_WASM_HASH,
  buildMessageEntry,
  encodeEntry,
  entrySignaturePayload,
  messageToScVal,
  ozAuthDigest,
  ozAuthDigestPreimage,
  ozEd25519Signer,
  signOzEntryWithEd25519,
  type OzDigestScheme,
  type OzEd25519Key,
  type SignedMessage,
} from "../src/index.js";

export const VECTORS_PATH = fileURLToPath(new URL("../../../vectors/c-sign-v1.json", import.meta.url));

const sha256 = (text: string) => hash(Buffer.from(text, "utf8"));
const contractId = (label: string) => StrKey.encodeContract(sha256(label));
const b64 = (val: { toXDR(format: "base64"): string }) => val.toXDR("base64");

const NETWORK = Networks.TESTNET;
const VERIFIER = contractId("c-sign vector verifier");
const ACCOUNT = contractId("c-sign vector account");
const OTHER_ACCOUNT = contractId("c-sign vector other account");
const ED25519_VERIFIER = contractId("c-sign vector ed25519 verifier");
const DOMAIN = "demo.c-sign.dev";
const ISSUED_AT = 1_790_000_000;
const EXPIRATION_LEDGER = 1_000_000;
const SPEC_VERSION = "0.0.2";

const KEY_SEEDS = [1, 2, 3].map((n) => `c-sign test key ${n}`);
const KEYS: OzEd25519Key[] = KEY_SEEDS.map((seed) => ({
  keypair: Keypair.fromRawEd25519Seed(sha256(seed)),
  verifierId: ED25519_VERIFIER,
}));

const MINIMAL: SignedMessage = { version: "1", domain: DOMAIN, statement: "Sign in to C-Sign demo", nonce: "abcDEF123456", issuedAt: ISSUED_AT };

/** Plain JSON view of an encoded message, with the SPEC's key names. */
function fields(val: xdr.ScVal): Record<string, string | number | string[]> {
  const out: Record<string, string | number | string[]> = {};
  for (const e of val.map() ?? []) {
    const v = e.val();
    const kind = v.switch().name;
    out[e.key().sym().toString()] =
      kind === "scvU64" ? Number(v.u64().toString()) : kind === "scvVec" ? (v.vec() ?? []).map((s) => s.str().toString()) : v.str().toString();
  }
  return out;
}

function validMessages() {
  const cases: { name: string; description: string; message: SignedMessage }[] = [
    { name: "minimal", description: "Required keys only", message: MINIMAL },
    {
      name: "all_fields",
      description: "Every key of version 1; note the sorted key order",
      message: {
        ...MINIMAL,
        uri: "https://demo.c-sign.dev/login",
        expirationTime: ISSUED_AT + 600,
        notBefore: ISSUED_AT,
        requestId: "req-42",
        resources: ["https://demo.c-sign.dev/terms", "ipfs://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"],
      },
    },
    { name: "unicode_statement", description: "Statement is UTF-8 (String, not Symbol)", message: { ...MINIMAL, statement: "Giriş yap · 署名 · ✓" } },
    {
      name: "statement_at_limit",
      description: "Statement of exactly 1024 bytes (512 two-byte characters); the limit counts bytes, not characters",
      message: { ...MINIMAL, statement: "ç".repeat(512) },
    },
    { name: "domain_with_port", description: "A port other than 443 is part of domain", message: { ...MINIMAL, domain: "demo.c-sign.dev:8443" } },
    { name: "domain_a_label", description: "An internationalized host (örnek.com) as its A-label", message: { ...MINIMAL, domain: "xn--rnek-4qa.com" } },
  ];
  return cases.map(({ name, description, message }) => {
    const val = messageToScVal(message);
    return { name, description, fields: fields(val), msg_xdr: b64(val), msg_xdr_bytes: val.toXDR().length };
  });
}

function invalidMessages() {
  const raw = (m: SignedMessage) => messageToScVal(m, false);
  const withEntries = (map: (entries: xdr.ScMapEntry[]) => xdr.ScMapEntry[]) => xdr.ScVal.scvMap(map(raw(MINIMAL).map() ?? []));
  const cases: { name: string; description: string; val: xdr.ScVal }[] = [
    {
      name: "unknown_key",
      description: "Key not defined for version 1",
      val: withEntries((e) => [...e, new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol("zzz"), val: xdr.ScVal.scvString("x") })]),
    },
    { name: "unsorted_keys", description: "Keys not in host order", val: withEntries((e) => [...e].reverse()) },
    {
      name: "wrong_type",
      description: "issued_at as String instead of U64",
      val: withEntries((e) =>
        e.map((x) => (x.key().sym().toString() === "issued_at" ? new xdr.ScMapEntry({ key: x.key(), val: xdr.ScVal.scvString("now") }) : x)),
      ),
    },
    { name: "missing_required", description: "nonce missing", val: withEntries((e) => e.filter((x) => x.key().sym().toString() !== "nonce")) },
    { name: "unsupported_version", description: 'version "2"', val: raw({ ...MINIMAL, version: "2" }) },
    { name: "short_nonce", description: "nonce shorter than 8 characters", val: raw({ ...MINIMAL, nonce: "abc123" }) },
    { name: "non_alphanumeric_nonce", description: "nonce with a non-alphanumeric character", val: raw({ ...MINIMAL, nonce: "abcDEF-123456" }) },
    { name: "empty_domain", description: "domain is empty", val: raw({ ...MINIMAL, domain: "" }) },
    { name: "statement_over_limit", description: "Statement of 1025 bytes", val: raw({ ...MINIMAL, statement: "ç".repeat(512) + "x" }) },
    {
      name: "message_over_limit",
      description: "XDR-encoded msg larger than 2048 bytes",
      val: raw({ ...MINIMAL, resources: Array(80).fill("https://example.com/resource") }),
    },
    { name: "statement_line_feed", description: "Control character U+000A (Cc) in statement", val: raw({ ...MINIMAL, statement: "Sign in\nto C-Sign demo" }) },
    { name: "statement_line_separator", description: "Line separator U+2028 (Zl) in statement", val: raw({ ...MINIMAL, statement: "Sign in\u2028to C-Sign demo" }) },
    { name: "statement_bidi_override", description: "Right-to-left override U+202E (Default_Ignorable) in statement", val: raw({ ...MINIMAL, statement: "Sign in \u202enomed" }) },
    { name: "statement_zero_width_space", description: "Zero-width space U+200B (Default_Ignorable) in statement", val: raw({ ...MINIMAL, statement: "Sign\u200bin" }) },
    { name: "resource_tab", description: "Control character U+0009 (Cc) in an element of resources", val: raw({ ...MINIMAL, resources: ["https://demo.c-sign.dev/\tterms"] }) },
    {
      name: "statement_invalid_utf8",
      description: "statement bytes 53 FF 69 are not valid UTF-8",
      val: withEntries((e) =>
        e.map((x) => (x.key().sym().toString() === "statement" ? new xdr.ScMapEntry({ key: x.key(), val: xdr.ScVal.scvString(Buffer.from([0x53, 0xff, 0x69])) }) : x)),
      ),
    },
    { name: "domain_uppercase", description: "domain not in lower case", val: raw({ ...MINIMAL, domain: "Demo.c-sign.dev" }) },
    { name: "domain_trailing_dot", description: "domain with a trailing dot", val: raw({ ...MINIMAL, domain: "demo.c-sign.dev." }) },
    { name: "domain_default_port", description: "domain with :443", val: raw({ ...MINIMAL, domain: "demo.c-sign.dev:443" }) },
    { name: "domain_with_scheme", description: "domain with a scheme", val: raw({ ...MINIMAL, domain: "https://demo.c-sign.dev" }) },
    { name: "domain_with_path", description: "domain with a path", val: raw({ ...MINIMAL, domain: "demo.c-sign.dev/login" }) },
    { name: "domain_with_userinfo", description: "domain with userinfo", val: raw({ ...MINIMAL, domain: "user@demo.c-sign.dev" }) },
    { name: "domain_u_label", description: "Internationalized host as a U-label instead of xn--rnek-4qa.com", val: raw({ ...MINIMAL, domain: "örnek.com" }) },
  ];
  return cases.map(({ name, description, val }) => ({ name, description, msg_xdr: b64(val), expected: "reject" as const }));
}

function entries() {
  const cases = [
    { name: "minimal_testnet", description: "Minimal message on testnet", message: MINIMAL, nonce: "1234567890123456789", network: NETWORK },
    { name: "negative_entry_nonce", description: "The auth-entry nonce is a signed i64", message: MINIMAL, nonce: "-42", network: NETWORK },
    {
      name: "minimal_mainnet",
      description: "Same entry as minimal_testnet on mainnet: only the payload changes (network id is in the preimage)",
      message: MINIMAL,
      nonce: "1234567890123456789",
      network: Networks.PUBLIC as string,
    },
  ];
  return cases.map(({ name, description, message, nonce, network }) => {
    const entry = buildMessageEntry({
      verifierId: VERIFIER,
      account: ACCOUNT,
      message,
      expirationLedger: EXPIRATION_LEDGER,
      nonce: xdr.Int64.fromString(nonce),
    });
    return {
      name,
      description,
      input: {
        network_passphrase: network,
        verifier: VERIFIER,
        account: ACCOUNT,
        msg_xdr: b64(messageToScVal(message)),
        entry_nonce: nonce,
        signature_expiration_ledger: EXPIRATION_LEDGER,
      },
      unsigned_entry_xdr: encodeEntry(entry),
      preimage_xdr: b64(buildAuthorizationEntryPreimage(entry, EXPIRATION_LEDGER, network)),
      signature_payload_hex: entrySignaturePayload(entry, network).toString("hex"),
    };
  });
}

function ozSigning() {
  const entry = buildMessageEntry({
    verifierId: VERIFIER,
    account: ACCOUNT,
    message: MINIMAL,
    expirationLedger: EXPIRATION_LEDGER,
    nonce: xdr.Int64.fromString("1234567890123456789"),
  });
  const cases = [
    { name: "single_signer_default_rule", description: "One Ed25519 signer under the Default rule (id 0)", keys: [KEYS[0]], ruleIds: [0] },
    {
      name: "two_of_three_threshold_rule",
      description:
        "Keys 3 and 1 of a 2-of-3 rule (id 1, threshold policy). Signer keys appear in host order in AuthPayload, regardless of signing order",
      keys: [KEYS[2], KEYS[0]],
      ruleIds: [1],
    },
  ];
  const schemes: { scheme: OzDigestScheme; suffix: string }[] = [
    { scheme: "legacy-concat", suffix: "" },
    { scheme: "preimage-v1", suffix: "_preimage_v1" },
  ];
  return schemes.flatMap(({ scheme, suffix }) =>
    cases.map(({ name, description, keys, ruleIds }) => {
      const digest = ozAuthDigest(entry, NETWORK, scheme, ruleIds);
      const signed = signOzEntryWithEd25519(entry, keys, NETWORK, scheme, ruleIds);
      const creds = signed.credentials().addressV2();
      return {
        name: name + suffix,
        description,
        scheme,
        input: { unsigned_entry_xdr: encodeEntry(entry), network_passphrase: NETWORK, context_rule_ids: ruleIds, signer_keys: keys.map((k) => KEYS.indexOf(k) + 1) },
        ...(scheme === "preimage-v1" && {
          auth_digest_preimage_xdr: b64(ozAuthDigestPreimage(ACCOUNT, entrySignaturePayload(entry, NETWORK), ruleIds)),
        }),
        auth_digest_hex: digest.toString("hex"),
        signatures: keys.map((k) => ({
          key: KEYS.indexOf(k) + 1,
          signer_xdr: b64(ozEd25519Signer(k)),
          signature_hex: k.keypair.sign(digest).toString("hex"),
        })),
        auth_payload_xdr: b64(creds.signature()),
        signed_entry_xdr: encodeEntry(signed),
      };
    }),
  );
}

/** An entry for `message` whose msg is encoded as given, without validating it. */
function rawEntry(message: SignedMessage, verifierId = VERIFIER) {
  const e = buildMessageEntry({ verifierId, account: ACCOUNT, message: MINIMAL, expirationLedger: EXPIRATION_LEDGER, nonce: xdr.Int64.fromString("7") });
  e.rootInvocation().function().contractFn().args([Address.fromString(ACCOUNT).toScVal(), messageToScVal(message, false)]);
  return e;
}

type VerifyContext = { domain: string; now: number; address?: string; issued_nonces?: { nonce: string; issued_at: number }[] };

function structural() {
  const base = () => rawEntry(MINIMAL);
  const mutate = (fn: (e: xdr.SorobanAuthorizationEntry) => void) => {
    const e = base();
    fn(e);
    return encodeEntry(e);
  };
  const context: VerifyContext = { domain: DOMAIN, now: ISSUED_AT };
  const signIn = (now: number): VerifyContext => ({ domain: DOMAIN, now, issued_nonces: [{ nonce: MINIMAL.nonce, issued_at: ISSUED_AT }] });
  const cases: { name: string; description: string; signature: string; context: VerifyContext; step: string }[] = [
    { name: "malformed_xdr", description: "Not a base64 XDR SorobanAuthorizationEntry", signature: "bm90LXhkcg==", context, step: "decode" },
    {
      name: "oversized_signature",
      description: "Well-formed entry of 16388 bytes: its base64 is longer than 21848 characters, rejected before decoding",
      signature: encodeEntry(rawEntry({ ...MINIMAL, resources: [`https://demo.c-sign.dev/${"a".repeat(15960)}`] })),
      context,
      step: "decode",
    },
    {
      name: "wrong_function",
      description: "Root call is not verify_message",
      signature: mutate((e) => e.rootInvocation().function().contractFn().functionName("transfer")),
      context,
      step: "shape",
    },
    {
      name: "sub_invocations",
      description: "Entry authorizes a sub-invocation",
      signature: mutate((e) => e.rootInvocation().subInvocations([base().rootInvocation()])),
      context,
      step: "shape",
    },
    {
      name: "extra_argument",
      description: "verify_message with three arguments",
      signature: mutate((e) => {
        const call = e.rootInvocation().function().contractFn();
        call.args([...call.args(), xdr.ScVal.scvVoid()]);
      }),
      context,
      step: "shape",
    },
    {
      name: "v1_credentials",
      description: "SOROBAN_CREDENTIALS_ADDRESS (V1) instead of V2",
      signature: mutate((e) => e.credentials(xdr.SorobanCredentials.sorobanCredentialsAddress(e.credentials().addressV2()))),
      context,
      step: "credentials",
    },
    {
      name: "delegates_credentials",
      description: "SOROBAN_CREDENTIALS_ADDRESS_WITH_DELEGATES (CAP-71) instead of V2",
      signature: mutate((e) =>
        e.credentials(
          xdr.SorobanCredentials.sorobanCredentialsAddressWithDelegates(
            new xdr.SorobanAddressCredentialsWithDelegates({ addressCredentials: e.credentials().addressV2(), delegates: [] }),
          ),
        ),
      ),
      context,
      step: "credentials",
    },
    {
      name: "credentials_for_other_account",
      description: "credentials.address differs from the account argument",
      signature: mutate((e) => e.credentials().addressV2().address(Address.fromString(OTHER_ACCOUNT).toScAddress())),
      context,
      step: "credentials",
    },
    { name: "unexpected_signer", description: "RP expects another account", signature: encodeEntry(base()), context: { ...context, address: OTHER_ACCOUNT }, step: "credentials" },
    {
      name: "invalid_message",
      description: "msg has an unknown key",
      signature: mutate((e) => {
        const msg = messageToScVal(MINIMAL);
        msg.map()!.push(new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol("zzz"), val: xdr.ScVal.scvVoid() }));
        e.rootInvocation().function().contractFn().args([Address.fromString(ACCOUNT).toScVal(), msg]);
      }),
      context,
      step: "message",
    },
    {
      name: "message_control_character",
      description: "statement contains U+000A",
      signature: encodeEntry(rawEntry({ ...MINIMAL, statement: "Sign in\nto C-Sign demo" })),
      context,
      step: "message",
    },
    { name: "other_domain", description: "Signed for demo.c-sign.dev, presented to evil.example", signature: encodeEntry(base()), context: { ...context, domain: "evil.example" }, step: "domain" },
    { name: "parent_domain", description: "Signed for demo.c-sign.dev, presented to c-sign.dev: no suffix matching", signature: encodeEntry(base()), context: { ...context, domain: "c-sign.dev" }, step: "domain" },
    { name: "issued_in_future", description: "issued_at 61 s in the future, beyond the 60 s skew", signature: encodeEntry(base()), context: { ...context, now: ISSUED_AT - 61 }, step: "freshness" },
    {
      name: "message_expired",
      description: "expiration_time passed 61 s ago",
      signature: encodeEntry(rawEntry({ ...MINIMAL, expirationTime: ISSUED_AT + 600 })),
      context: { ...context, now: ISSUED_AT + 661 },
      step: "freshness",
    },
    {
      name: "message_not_yet_valid",
      description: "not_before is 61 s away",
      signature: encodeEntry(rawEntry({ ...MINIMAL, notBefore: ISSUED_AT + 600 })),
      context: { ...context, now: ISSUED_AT + 539 },
      step: "freshness",
    },
    {
      name: "stale_sign_in",
      description: "Nonce issued 301 s ago: past the 300 s challenge lifetime, which skew does not extend",
      signature: encodeEntry(base()),
      context: signIn(ISSUED_AT + 301),
      step: "freshness",
    },
    {
      name: "nonce_not_issued",
      description: "Nonce not issued by this RP, or already used",
      signature: encodeEntry(base()),
      context: { ...context, issued_nonces: [] },
      step: "freshness",
    },
  ];
  return cases.map(({ step, ...c }) => ({ ...c, expected: { status: "invalid" as const, step } }));
}

type InstanceState = { state: "wasm"; wasm_hash: string } | { state: "external_ref" | "missing" | "archived" };

interface RpcState {
  network_passphrase: string;
  latest_ledger: number;
  latest_ledger_close_time: number;
  verifier_instance: InstanceState;
  simulation: { succeeded: true } | { error: string; contract_error_events: { contract: "verifier" | "account"; code: number }[] };
}

function verification() {
  const now = ISSUED_AT + 10;
  const authOk = (contract: "verifier" | "account" = "verifier") => ({
    error: "HostError: Error(Contract, #1)\n\nEvent log (newest first):\n   0: [Diagnostic Event] topics:[error, Error(Contract, #1)]",
    contract_error_events: [{ contract, code: 1 }],
  });
  const rpc = (over: Partial<RpcState> = {}): RpcState => ({
    network_passphrase: NETWORK,
    latest_ledger: EXPIRATION_LEDGER - 1000,
    latest_ledger_close_time: now - 5,
    verifier_instance: { state: "wasm", wasm_hash: REFERENCE_WASM_HASH },
    simulation: authOk(),
    ...over,
  });
  const context: VerifyContext = { domain: DOMAIN, now };
  const signIn: VerifyContext = { ...context, issued_nonces: [{ nonce: MINIMAL.nonce, issued_at: ISSUED_AT }] };
  type Expected = { status: "valid" | "invalid" | "inconclusive"; step?: string; nonce_consumed?: boolean };
  const cases: { name: string; description: string; requirement?: "SHOULD"; context: VerifyContext; rpc: RpcState; expected: Expected }[] = [
    { name: "valid", description: "Reference Wasm, AuthOk raised by the verifier", context, rpc: rpc(), expected: { status: "valid" } },
    { name: "valid_sign_in", description: "A valid sign-in consumes the nonce", context: signIn, rpc: rpc(), expected: { status: "valid", nonce_consumed: true } },
    {
      name: "expired_entry",
      description: "signature_expiration_ledger is below the latest ledger",
      context,
      rpc: rpc({ latest_ledger: EXPIRATION_LEDGER + 1 }),
      expected: { status: "invalid", step: "expiration" },
    },
    {
      name: "sign_in_expiration_too_far",
      description: "Sign-in entry expiring 17281 ledgers after the latest ledger",
      requirement: "SHOULD",
      context: signIn,
      rpc: rpc({ latest_ledger: EXPIRATION_LEDGER - 17281 }),
      expected: { status: "invalid", step: "expiration", nonce_consumed: false },
    },
    {
      name: "instance_other_wasm",
      description: "Verifier instance runs another Wasm",
      context,
      rpc: rpc({ verifier_instance: { state: "wasm", wasm_hash: "00".repeat(32) } }),
      expected: { status: "invalid", step: "pin" },
    },
    {
      name: "instance_external_ref",
      description: "Verifier executable is CONTRACT_EXECUTABLE_EXTERNAL_REF (CAP-85); never resolved to a hash",
      context,
      rpc: rpc({ verifier_instance: { state: "external_ref" } }),
      expected: { status: "invalid", step: "pin" },
    },
    { name: "instance_missing", description: "No contract at the verifier address", context, rpc: rpc({ verifier_instance: { state: "missing" } }), expected: { status: "invalid", step: "pin" } },
    { name: "instance_archived", description: "Verifier instance is archived", context, rpc: rpc({ verifier_instance: { state: "archived" } }), expected: { status: "inconclusive", step: "pin" } },
    {
      name: "rpc_other_network",
      description: "The RPC serves mainnet, the RP expects testnet",
      context,
      rpc: rpc({ network_passphrase: Networks.PUBLIC }),
      expected: { status: "inconclusive", step: "network" },
    },
    {
      name: "rpc_stale",
      description: "The RPC's latest ledger closed 31 s ago",
      requirement: "SHOULD",
      context,
      rpc: rpc({ latest_ledger_close_time: now - 31 }),
      expected: { status: "inconclusive", step: "network" },
    },
    {
      name: "account_rejects",
      description: "The account's __check_auth fails: invalid, and the nonce stays unused",
      context: signIn,
      rpc: rpc({ simulation: { error: "HostError: Error(Auth, InvalidAction)\n\nEvent log (newest first):\n   0: [Diagnostic Event] ...", contract_error_events: [] } }),
      expected: { status: "invalid", step: "check_auth", nonce_consumed: false },
    },
    {
      name: "auth_error_after_first_line",
      description: "Error(Auth, ...) appears only in later lines (account log output); the first line decides",
      context,
      rpc: rpc({
        simulation: {
          error: 'HostError: Error(WasmVm, InvalidAction)\n\nEvent log (newest first):\n   0: [Diagnostic Event] contract:account, topics:[log], data:"Error(Auth, InvalidAction)"',
          contract_error_events: [],
        },
      }),
      expected: { status: "inconclusive", step: "check_auth" },
    },
    {
      name: "auth_ok_without_event",
      description: "First line is Error(Contract, #1) but no diagnostic error event from the verifier",
      context,
      rpc: rpc({ simulation: { ...authOk(), contract_error_events: [] } }),
      expected: { status: "inconclusive", step: "check_auth" },
    },
    {
      name: "auth_ok_from_account",
      description: "Contract error 1 raised by the account, not by the verifier",
      context,
      rpc: rpc({ simulation: authOk("account") }),
      expected: { status: "inconclusive", step: "check_auth" },
    },
    {
      name: "simulation_succeeded",
      description: "The call succeeded, which the reference verifier never does",
      context,
      rpc: rpc({ simulation: { succeeded: true } }),
      expected: { status: "inconclusive", step: "check_auth" },
    },
    {
      name: "other_host_error",
      description: "Any other error is inconclusive and does not consume the nonce",
      context: signIn,
      rpc: rpc({ simulation: { error: "HostError: Error(Budget, ExceededLimit)", contract_error_events: [] } }),
      expected: { status: "inconclusive", step: "check_auth", nonce_consumed: false },
    },
  ];
  // One verifier address per case, so a cached pin result never carries over between cases.
  return cases.map((c) => {
    const verifier = contractId(`c-sign vector verifier/${c.name}`);
    return { ...c, verifier, signature: encodeEntry(rawEntry(MINIMAL, verifier)) };
  });
}

function walletDomain() {
  const cases: { name: string; origin: string; developer_mode?: boolean; expected: { domain: string } | { refuse: true } }[] = [
    { name: "https", origin: "https://demo.c-sign.dev", expected: { domain: "demo.c-sign.dev" } },
    { name: "upper_case", origin: "https://Demo.C-Sign.DEV", expected: { domain: "demo.c-sign.dev" } },
    { name: "default_port", origin: "https://demo.c-sign.dev:443", expected: { domain: "demo.c-sign.dev" } },
    { name: "other_port", origin: "https://demo.c-sign.dev:8443", expected: { domain: "demo.c-sign.dev:8443" } },
    { name: "internationalized", origin: "https://örnek.com", expected: { domain: "xn--rnek-4qa.com" } },
    { name: "http", origin: "http://demo.c-sign.dev", expected: { refuse: true } },
    { name: "localhost", origin: "http://localhost:5173", expected: { refuse: true } },
    { name: "localhost_developer_mode", origin: "http://localhost:5173", developer_mode: true, expected: { domain: "localhost:5173" } },
  ];
  return cases;
}

export function buildVectors() {
  return {
    $comment:
      "C-Sign test vectors, version 1. Generated by packages/c-sign/scripts/vectors.ts; do not edit by hand. Keys are TEST-ONLY, derived from public seeds. XDR values are base64; hashes and signatures are hex.",
    spec: "docs/SPEC.md",
    spec_version: SPEC_VERSION,
    reference_wasm_hash: REFERENCE_WASM_HASH,
    fixtures: {
      network_passphrase: NETWORK,
      verifier: VERIFIER,
      account: ACCOUNT,
      other_account: OTHER_ACCOUNT,
      ed25519_verifier: ED25519_VERIFIER,
      address_derivation: 'Contract ids are StrKey(sha256(label)), for example sha256("c-sign vector account")',
      keys: KEYS.map((k, i) => ({
        id: i + 1,
        seed: `sha256("${KEY_SEEDS[i]}")`,
        public_key_hex: Buffer.from(k.keypair.rawPublicKey()).toString("hex"),
      })),
    },
    messages: {
      $comment: "SPEC §2. Encoders MUST produce msg_xdr from fields; decoders MUST reject every invalid case.",
      valid: validMessages(),
      invalid: invalidMessages(),
    },
    entries: {
      $comment:
        "SPEC §4. Unsigned SorobanAuthorizationEntry with V2 credentials and signature = Void. signature_payload = sha256(preimage), the bytes the account's __check_auth receives.",
      cases: entries(),
    },
    oz_signing: {
      $comment:
        "Informative: how an OpenZeppelin smart account signs. The scheme is set by the account's implementation version. legacy-concat (stellar-accounts 0.7.x): auth_digest = sha256(signature_payload || XDR(Vec<u32> context_rule_ids)). preimage-v1 (0.8.0+): auth_digest = sha256(XDR(AuthDigestPreimage)), a Map with Symbol keys account (credentials.address), context_rule_ids (Vec<u32>), signature_payload (BytesN<32>). AuthPayload is the same for both. The SEP does not standardize this; verification is by simulation.",
      cases: ozSigning(),
    },
    structural: {
      $comment:
        "SPEC §6 steps 1 to 4: rejected before any network call. now is the RP's clock in Unix seconds. Time checks allow at most 60 s of clock skew; every case here fails under any skew from 0 to 60 s. If issued_nonces is present this is a sign-in: the nonce must be listed, unused, and issued no more than 300 s (the challenge lifetime) before now, with no skew added.",
      cases: structural(),
    },
    verification: {
      $comment:
        "SPEC §6 steps 2 and 5 to 8, against the RPC state in rpc: the network it serves, its latest ledger and that ledger's close time, the verifier instance (wasm with a hash, external_ref, missing or archived) and the enforcing simulation (succeeded, or the error text and the contract error events in its diagnostic events, raised by the verifier or by the account). Each case has its own verifier address, signature_expiration_ledger 1000000 and the minimal message; context is as in structural. requirement SHOULD marks a SHOULD of the SPEC. nonce_consumed is whether the RP marks msg.nonce as used.",
      cases: verification(),
    },
    wallet_domain: {
      $comment:
        "SPEC §5 item 1 and §2: the domain a wallet writes for the origin the platform reports. refuse: the wallet does not sign with this origin as a verified domain.",
      cases: walletDomain(),
    },
  };
}

export const serializeVectors = () => JSON.stringify(buildVectors(), null, 2) + "\n";

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  writeFileSync(VECTORS_PATH, serializeVectors());
  console.log(`wrote ${VECTORS_PATH}`);
}
