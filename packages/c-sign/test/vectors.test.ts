import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { xdr } from "@stellar/stellar-sdk";
import { decodeEntry, entrySignaturePayload, messageFromScVal, verifyMessage } from "../src/index.js";
import { VECTORS_PATH, buildVectors, serializeVectors } from "../scripts/vectors.js";

const vectors = buildVectors();

describe("test vectors", () => {
  it("checked-in file matches the generator (run `pnpm --filter c-sign vectors`)", () => {
    expect(readFileSync(VECTORS_PATH, "utf8")).toBe(serializeVectors());
  });

  it("decodes every valid message back to its fields", () => {
    for (const v of vectors.messages.valid) {
      expect(() => messageFromScVal(xdr.ScVal.fromXDR(v.msg_xdr, "base64")), v.name).not.toThrow();
    }
  });

  it("rejects every invalid message", () => {
    for (const v of vectors.messages.invalid) {
      expect(() => messageFromScVal(xdr.ScVal.fromXDR(v.msg_xdr, "base64")), v.name).toThrow();
    }
  });

  it("signature payload is sha256 of the preimage", () => {
    for (const v of vectors.entries.cases) {
      const payload = entrySignaturePayload(decodeEntry(v.unsigned_entry_xdr), v.input.network_passphrase);
      expect(payload.toString("hex"), v.name).toBe(v.signature_payload_hex);
    }
  });

  it("rejects every structural case at the expected step, offline", async () => {
    for (const v of vectors.structural.cases) {
      const { domain, now, address, issued_nonces } = v.context;
      const r = await verifyMessage({
        signature: v.signature,
        rpcUrl: "http://127.0.0.1:1", // unreachable on purpose
        networkPassphrase: vectors.fixtures.network_passphrase,
        domain,
        now,
        address,
        freshness: issued_nonces && { checkNonce: (n) => issued_nonces.includes(n) },
      });
      expect(r.status, v.name).toBe(v.expected.status);
      expect(r.steps.find((s) => s.status === "fail")?.id, v.name).toBe(v.expected.step);
    }
  });
});
