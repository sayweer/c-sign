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
  ozEd25519Signer,
  signOzEntryWithEd25519,
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
  return cases.map(({ name, description, keys, ruleIds }) => {
    const digest = ozAuthDigest(entry, NETWORK, ruleIds);
    const signed = signOzEntryWithEd25519(entry, keys, NETWORK, ruleIds);
    const creds = signed.credentials().addressV2();
    return {
      name,
      description,
      input: { unsigned_entry_xdr: encodeEntry(entry), network_passphrase: NETWORK, context_rule_ids: ruleIds, signer_keys: keys.map((k) => KEYS.indexOf(k) + 1) },
      auth_digest_hex: digest.toString("hex"),
      signatures: keys.map((k) => ({
        key: KEYS.indexOf(k) + 1,
        signer_xdr: b64(ozEd25519Signer(k)),
        signature_hex: k.keypair.sign(digest).toString("hex"),
      })),
      auth_payload_xdr: b64(creds.signature()),
      signed_entry_xdr: encodeEntry(signed),
    };
  });
}

function structural() {
  const base = () =>
    buildMessageEntry({ verifierId: VERIFIER, account: ACCOUNT, message: MINIMAL, expirationLedger: EXPIRATION_LEDGER, nonce: xdr.Int64.fromString("7") });
  const mutate = (fn: (e: xdr.SorobanAuthorizationEntry) => void) => {
    const e = base();
    fn(e);
    return encodeEntry(e);
  };
  const context = { domain: DOMAIN, now: ISSUED_AT };
  const cases: {
    name: string;
    description: string;
    signature: string;
    context: { domain: string; now: number; address?: string; issued_nonces?: string[] };
    step: string;
  }[] = [
    { name: "malformed_xdr", description: "Not a base64 XDR SorobanAuthorizationEntry", signature: "bm90LXhkcg==", context, step: "decode" },
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
    { name: "other_domain", description: "Signed for demo.c-sign.dev, presented to evil.example", signature: encodeEntry(base()), context: { ...context, domain: "evil.example" }, step: "domain" },
    { name: "issued_in_future", description: "issued_at beyond the 300 s clock skew", signature: encodeEntry(base()), context: { ...context, now: ISSUED_AT - 301 }, step: "freshness" },
    {
      name: "stale_sign_in",
      description: "Sign-in older than 300 s plus 300 s skew",
      signature: encodeEntry(base()),
      context: { ...context, now: ISSUED_AT + 601, issued_nonces: [MINIMAL.nonce] },
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

export function buildVectors() {
  return {
    $comment:
      "C-Sign test vectors, version 1. Generated by packages/c-sign/scripts/vectors.ts; do not edit by hand. Keys are TEST-ONLY, derived from public seeds. XDR values are base64; hashes and signatures are hex.",
    spec: "docs/SPEC.md",
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
        "Informative: how an OpenZeppelin smart account signs. auth_digest = sha256(signature_payload || XDR(Vec<u32> context_rule_ids)). The SEP does not standardize this; verification is by simulation.",
      cases: ozSigning(),
    },
    structural: {
      $comment:
        "SPEC §6 steps 1 to 4: rejected before any network call. Defaults: clock skew 300 s; if issued_nonces is present this is a sign-in, the nonce must be in it and issued_at at most 300 s old (plus skew).",
      cases: structural(),
    },
  };
}

export const serializeVectors = () => JSON.stringify(buildVectors(), null, 2) + "\n";

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  writeFileSync(VECTORS_PATH, serializeVectors());
  console.log(`wrote ${VECTORS_PATH}`);
}
