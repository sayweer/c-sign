import { describe, expect, it } from "vitest";
import { Address, Keypair, Networks, StrKey, hash, xdr } from "@stellar/stellar-sdk";
import {
  addressCredentials,
  buildMessageEntry,
  entrySignaturePayload,
  ozAuthDigest,
  ozAuthDigestPreimage,
  ozEd25519Signer,
  signOzEntryWithEd25519,
  type OzDigestScheme,
  type OzEd25519Key,
} from "../src/index.js";

const ACCOUNT = "CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE";

// Computed independently in Rust with stellar-accounts 0.8.0 (AuthDigestPreimage) and its 0.7.x formula.
const RUST_VECTORS = [
  {
    account: ACCOUNT,
    payload: Buffer.alloc(32, 0x07),
    ids: [0, 1],
    preimageV1: "da044cadae24af970e886e14062e3e0b30707d751dccfbce1b2d22feff7c6713",
    legacy: "89343d895ff3eb8d7c912b9d287e331652a00a36d853181ceb71133935810d30",
  },
  {
    account: ACCOUNT,
    payload: Buffer.alloc(32, 0x00),
    ids: [0],
    preimageV1: "ad4a74f62d6918ac4536d8a1a2012679a859a9e06143b944927ef98f9f233097",
    legacy: "cd8f38f416e883abd1c3fa555bfbe29f70a28c1ec9c1ebab27e0b055829a33ac",
  },
  {
    account: "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN7", // G address: encoding check only
    payload: Buffer.alloc(32, 0xab),
    ids: [3, 0, 2],
    preimageV1: "92a4ab37a4d13d27ade27aa5c45d794ad90877fc5e765a2e3917bf1350c23a90",
    legacy: "d7d4e280b9732469d2aa2df97cb1e3c50d8a85c9a8eab32d280eb8dbd44ae140",
  },
];

const VECTOR_1_PREIMAGE_XDR =
  "0000001100000001000000030000000f000000076163636f756e74000000001200000001363eaa3867841fbad0f4ed88c779e4fe66e56a2470dc98c0ec9c073d05c7b1030000000f00000010636f6e746578745f72756c655f696473000000100000000100000002000000030000000000000003000000010000000f000000117369676e61747572655f7061796c6f61640000000000000d000000200707070707070707070707070707070707070707070707070707070707070707";

const legacyDigest = (payload: Buffer, ids: number[]) =>
  hash(Buffer.concat([payload, xdr.ScVal.scvVec(ids.map((id) => xdr.ScVal.scvU32(id))).toXDR()]));

const networkPassphrase = Networks.TESTNET;
const entry = buildMessageEntry({
  verifierId: StrKey.encodeContract(hash(Buffer.from("oz test verifier"))),
  account: ACCOUNT,
  message: { version: "1", domain: "demo.c-sign.dev", statement: "Sign in", nonce: "abcDEF123456", issuedAt: 1_790_000_000 },
  expirationLedger: 1000,
  nonce: xdr.Int64.fromString("42"),
});
const KEYS: OzEd25519Key[] = [1, 2].map((n) => ({
  keypair: Keypair.fromRawEd25519Seed(hash(Buffer.from(`oz test key ${n}`))),
  verifierId: StrKey.encodeContract(hash(Buffer.from("oz test ed25519 verifier"))),
}));

/** The signature bytes `key` placed in the entry's `AuthPayload`. */
function signatureOf(signed: xdr.SorobanAuthorizationEntry, key: OzEd25519Key): Buffer {
  const signers = addressCredentials(signed)
    .signature()
    .map()!
    .find((e) => e.key().sym().toString() === "signers")!
    .val()
    .map()!;
  const signer = ozEd25519Signer(key).toXDR("base64");
  return Buffer.from(signers.find((e) => e.key().toXDR("base64") === signer)!.val().bytes());
}

describe("OpenZeppelin auth digest", () => {
  it("matches the Rust stellar-accounts vectors for both schemes", () => {
    for (const v of RUST_VECTORS) {
      expect(hash(ozAuthDigestPreimage(v.account, v.payload, v.ids).toXDR()).toString("hex"), v.account).toBe(v.preimageV1);
      expect(legacyDigest(v.payload, v.ids).toString("hex"), v.account).toBe(v.legacy);
    }
  });

  it("encodes AuthDigestPreimage as a sorted Symbol-keyed map", () => {
    const v = RUST_VECTORS[0];
    expect(ozAuthDigestPreimage(v.account, v.payload, v.ids).toXDR("hex")).toBe(VECTOR_1_PREIMAGE_XDR);
  });

  it("binds the entry's credentials address in preimage-v1, and differs from legacy-concat", () => {
    const ids = [0, 2];
    const payload = entrySignaturePayload(entry, networkPassphrase);
    const account = Address.fromScAddress(addressCredentials(entry).address()).toString();
    const v1 = ozAuthDigest(entry, networkPassphrase, "preimage-v1", ids);
    expect(v1).toEqual(hash(ozAuthDigestPreimage(account, payload, ids).toXDR()));
    expect(ozAuthDigest(entry, networkPassphrase, "legacy-concat", ids)).toEqual(legacyDigest(payload, ids));
    expect(v1).not.toEqual(ozAuthDigest(entry, networkPassphrase, "legacy-concat", ids));
  });

  it("signs with the chosen scheme and leaves the input untouched", () => {
    const before = entry.toXDR("base64");
    const schemes: [OzDigestScheme, OzDigestScheme][] = [
      ["legacy-concat", "preimage-v1"],
      ["preimage-v1", "legacy-concat"],
    ];
    for (const [scheme, other] of schemes) {
      const signed = signOzEntryWithEd25519(entry, KEYS, networkPassphrase, scheme);
      const digest = ozAuthDigest(entry, networkPassphrase, scheme);
      const wrong = ozAuthDigest(entry, networkPassphrase, other);
      for (const key of KEYS) {
        const sig = signatureOf(signed, key);
        expect(key.keypair.verify(digest, sig), scheme).toBe(true);
        expect(key.keypair.verify(wrong, sig), scheme).toBe(false);
      }
    }
    expect(entry.toXDR("base64")).toBe(before);
    expect(addressCredentials(entry).signature().switch().name).toBe("scvVoid");
  });

  it("rejects an unknown scheme and a payload that is not 32 bytes", () => {
    // The old positional API put context rule ids where the scheme now goes.
    expect(() => ozAuthDigest(entry, networkPassphrase, [1] as unknown as OzDigestScheme)).toThrow(/Unknown/);
    expect(() => ozAuthDigestPreimage(ACCOUNT, Buffer.alloc(31), [0])).toThrow(/32 bytes/);
  });
});
