import { describe, expect, it } from "vitest";
import { xdr } from "@stellar/stellar-sdk";
import { CSignError, messageFromScVal, messageToScVal, toDisplayText, type SignedMessage } from "../src/index.js";

const base: SignedMessage = {
  version: "1",
  domain: "demo.c-sign.dev",
  statement: "Sign in to C-Sign demo",
  nonce: "abcDEF123456",
  issuedAt: 1_790_000_000,
};

describe("message", () => {
  it("round-trips required and optional fields", () => {
    const msg = { ...base, uri: "https://demo.c-sign.dev", expirationTime: 1_790_000_600, resources: ["a", "b"] };
    expect(messageFromScVal(messageToScVal(msg))).toEqual(msg);
  });

  it("encodes keys sorted as the host requires", () => {
    const keys = (messageToScVal(base).map() ?? []).map((e) => e.key().sym().toString());
    expect(keys).toEqual([...keys].sort());
    expect(keys).toEqual(["domain", "issued_at", "nonce", "statement", "version"]);
  });

  it("rejects unknown keys", () => {
    const val = messageToScVal(base);
    val.map()!.push(new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol("zzz"), val: xdr.ScVal.scvString("x") }));
    expect(() => messageFromScVal(val)).toThrow(/unknown message key/);
  });

  it("rejects unsorted keys", () => {
    const val = messageToScVal(base);
    val.map()!.reverse();
    expect(() => messageFromScVal(val)).toThrow(/not sorted/);
  });

  it("rejects wrong types", () => {
    const entries = (messageToScVal(base).map() ?? []).map((e) =>
      e.key().sym().toString() === "issued_at" ? new xdr.ScMapEntry({ key: e.key(), val: xdr.ScVal.scvString("now") }) : e,
    );
    expect(() => messageFromScVal(xdr.ScVal.scvMap(entries))).toThrow(/issued_at must be a U64/);
  });

  it("enforces version, nonce and size rules", () => {
    expect(() => messageToScVal({ ...base, version: "2" })).toThrow(CSignError);
    expect(() => messageToScVal({ ...base, nonce: "short" })).toThrow(/nonce/);
    expect(() => messageToScVal({ ...base, statement: "x".repeat(1025) })).toThrow(/1024/);
    expect(() => messageToScVal({ ...base, resources: Array(80).fill("https://example.com/resource") })).toThrow(/2048/);
  });

  it("renders display text with domain and account", () => {
    const text = toDisplayText(base, "CABC");
    expect(text.split("\n").slice(0, 2)).toEqual(["demo.c-sign.dev wants you to sign in with your Stellar contract account:", "CABC"]);
    expect(text).toContain("Nonce: abcDEF123456");
  });
});
