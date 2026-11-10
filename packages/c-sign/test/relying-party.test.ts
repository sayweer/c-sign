import { describe, expect, it } from "vitest";
import { CSignError, MemoryNonceStore, createNonce, createSignInMessage, validateMessage } from "../src/index.js";

describe("createNonce", () => {
  it("is 32 hex characters and differs every time", () => {
    const a = createNonce();
    expect(a).toMatch(/^[0-9a-f]{32}$/);
    expect(createNonce()).not.toBe(a);
  });
});

describe("MemoryNonceStore", () => {
  const clock = (start: number) => {
    let t = start;
    return { now: () => t, advance: (s: number) => (t += s) };
  };

  it("reports when a nonce was issued, once", () => {
    const c = clock(1000);
    const store = new MemoryNonceStore({ now: c.now });
    const { nonce, issuedAt } = store.issue();
    expect(issuedAt).toBe(1000);
    expect(store.issuedAt(nonce)).toBe(1000);
    expect(store.consume(nonce)).toBe(true);
    expect(store.consume(nonce)).toBe(false);
    expect(store.issuedAt(nonce)).toBeUndefined();
  });

  it("does not know nonces it did not issue", () => {
    const store = new MemoryNonceStore();
    expect(store.issuedAt("abcdefgh1234")).toBeUndefined();
    expect(store.consume("abcdefgh1234")).toBe(false);
  });

  it("forgets a nonce after its lifetime", () => {
    const c = clock(1000);
    const store = new MemoryNonceStore({ now: c.now, lifetimeSeconds: 60 });
    const { nonce } = store.issue();
    c.advance(60);
    expect(store.issuedAt(nonce)).toBe(1000);
    c.advance(1);
    expect(store.issuedAt(nonce)).toBeUndefined();
  });

  it("drops the oldest nonce beyond maxEntries", () => {
    const store = new MemoryNonceStore({ maxEntries: 2 });
    const first = store.issue().nonce;
    const second = store.issue().nonce;
    const third = store.issue().nonce;
    expect(store.issuedAt(first)).toBeUndefined();
    expect(store.issuedAt(second)).toBeDefined();
    expect(store.issuedAt(third)).toBeDefined();
  });
});

describe("createSignInMessage", () => {
  it("adds the version and returns a valid message without undefined fields", () => {
    const store = new MemoryNonceStore();
    const message = createSignInMessage({ domain: "example.com", statement: "Sign in to Example", uri: undefined, ...store.issue() });
    expect(message.version).toBe("1");
    expect("uri" in message).toBe(false);
    expect(() => validateMessage(message)).not.toThrow();
  });

  it("rejects a domain that is not a lower-case host", () => {
    expect(() => createSignInMessage({ domain: "https://Example.com", statement: "x", nonce: createNonce(), issuedAt: 1 })).toThrow(CSignError);
  });
});
