// Runs in a real browser with no Buffer polyfill (scripts/browser-smoke.ts).
import { Keypair } from "@stellar/stellar-sdk";
import vectors from "../../../../vectors/c-sign-v1.json" with { type: "json" };
import {
  buildMessageEntry,
  decodeEntry,
  encodeEntry,
  entrySignaturePayload,
  messageFromScVal,
  ozAuthDigest,
  parseMessageEntry,
  signOzMessageWithEd25519,
  signPasskeyKitMessageWithEd25519,
  type OzDigestScheme,
} from "../../src/index.js";

const hex = (bytes: Uint8Array) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

function run(): string[] {
  const failures: string[] = [];
  const check = (name: string, ok: boolean) => ok || failures.push(name);

  for (const v of vectors.entries.cases) {
    const payload = entrySignaturePayload(decodeEntry(v.unsigned_entry_xdr), v.input.network_passphrase);
    check(`entries/${v.name}`, hex(payload) === v.signature_payload_hex);
  }
  for (const v of vectors.oz_signing.cases) {
    const { unsigned_entry_xdr, network_passphrase, context_rule_ids } = v.input;
    const digest = ozAuthDigest(decodeEntry(unsigned_entry_xdr), network_passphrase, v.scheme as OzDigestScheme, context_rule_ids);
    check(`oz_signing/${v.name}`, hex(digest) === v.auth_digest_hex);
  }

  const { input } = vectors.entries.cases[0]!;
  const message = messageFromScVal(decodeEntry(vectors.entries.cases[0]!.unsigned_entry_xdr).rootInvocation().function().contractFn().args()[1]!);
  const entry = buildMessageEntry({ verifierId: input.verifier, account: input.account, message, expirationLedger: 1000 });
  const key = Keypair.random();
  const oz = signOzMessageWithEd25519(entry, [{ keypair: key, verifierId: input.verifier }], input.network_passphrase, "preimage-v1");
  check("sign/openzeppelin", parseMessageEntry(decodeEntry(encodeEntry(oz))).message.nonce === message.nonce);
  const pk = signPasskeyKitMessageWithEd25519(entry, [key], input.network_passphrase);
  check("sign/passkey-kit", parseMessageEntry(decodeEntry(encodeEntry(pk))).account === input.account);
  return failures;
}

let result: string;
try {
  const failures = run();
  result = failures.length ? `FAIL ${failures.join(", ")}` : "PASS";
} catch (e) {
  result = `FAIL ${(e as Error).message}`;
}
document.body.dataset.result = result;
