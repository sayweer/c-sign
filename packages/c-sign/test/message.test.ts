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

  it("accepts only the domain form of SPEC §2", () => {
    for (const domain of ["demo.c-sign.dev", "localhost:5173", "xn--rnek-4qa.com:8443", "127.0.0.1:65535"]) {
      expect(() => messageToScVal({ ...base, domain }), domain).not.toThrow();
    }
    for (const domain of ["a.b:443", "a.b:0", "a.b:080", "a.b:65536", "a..b", "-a.b", "a-.b", "a b", "[::1]:8443"]) {
      expect(() => messageToScVal({ ...base, domain }), domain).toThrow(CSignError);
    }
  });

  it("rejects forbidden characters in every string field, not only the statement", () => {
    for (const bad of ["\u0000", "\u2029", "\u00ad", "\ufeff", "\ud800"]) {
      expect(() => messageToScVal({ ...base, statement: `a${bad}b` }), JSON.stringify(bad)).toThrow(CSignError);
      expect(() => messageToScVal({ ...base, uri: `a${bad}b` }), JSON.stringify(bad)).toThrow(CSignError);
      expect(() => messageToScVal({ ...base, requestId: `a${bad}b` }), JSON.stringify(bad)).toThrow(CSignError);
    }
  });

  it("does not let the decoder hide a leading byte order mark", () => {
    const val = messageToScVal(base, false);
    const statement = (val.map() ?? []).find((e) => e.key().sym().toString() === "statement")!;
    statement.val(xdr.ScVal.scvString(Buffer.from("\ufeffSign in", "utf8")));
    expect(() => messageFromScVal(xdr.ScVal.fromXDR(val.toXDR()))).toThrow(/forbidden character/);
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
