import { describe, expect, it } from "vitest";
import { Keypair, Networks } from "@stellar/stellar-sdk";
import {
  CSignError,
  MemoryNonceStore,
  chainId,
  createSignInMessage,
  signInText,
  signSignInWithKeypair,
  verifyMessage,
  verifySignIn,
  type SignedMessage,
} from "../src/index.js";

// G accounts never reach the RPC.
const rpcUrl = "http://127.0.0.1:1";
const networkPassphrase = Networks.TESTNET;
const now = 1_790_000_000;
const domain = "example.com";

describe("SEP-53", () => {
  it("matches the SEP-53 test case", () => {
    const kp = Keypair.fromSecret("SAKICEVQLYWGSOJS4WW7HZJWAHZVEEBS527LHK5V4MLJALYKICQCJXMW");
    expect(kp.publicKey()).toBe("GBXFXNDLV4LSWA4VB7YIL5GBD7BVNR22SGBTDKMO2SBZZHDXSKZYCP7L");
    expect(btoa(String.fromCharCode(...kp.signMessage("Hello, World!")))).toBe(
      "fO5dbYhXUhBMhe6kId/cuVq/AfEnHRHEvsP8vXh03M1uLpi5e46yO2Q8rEBzu3feXQewcQE5GArp88u6ePK6BA==",
    );
  });
});

describe("signInText", () => {
  const address = "GBXFXNDLV4LSWA4VB7YIL5GBD7BVNR22SGBTDKMO2SBZZHDXSKZYCP7L";

  it("formats every field in CAIP-122 order, with the network's chain id", () => {
    const msg: SignedMessage = {
      version: "1",
      domain,
      statement: "Sign in to Example",
      nonce: "abcDEF123456",
      issuedAt: now,
      uri: "https://example.com/login",
      expirationTime: now + 600,
      notBefore: now - 60,
      requestId: "r-1",
      resources: ["https://example.com/terms"],
    };
    expect(signInText(msg, address, networkPassphrase)).toBe(
      [
        "example.com wants you to sign in with your Stellar account:",
        address,
        "",
        "Sign in to Example",
        "",
        "URI: https://example.com/login",
        "Version: 1",
        "Chain ID: stellar:testnet",
        "Nonce: abcDEF123456",
        "Issued At: 2026-09-21T14:13:20.000Z",
        "Expiration Time: 2026-09-21T14:23:20.000Z",
        "Not Before: 2026-09-21T14:12:20.000Z",
        "Request ID: r-1",
        "Resources:",
        "- https://example.com/terms",
      ].join("\n"),
    );
  });

  it("refuses an invalid message, a C address and a network without a chain id", () => {
    const msg: SignedMessage = { version: "1", domain, statement: "a\nb", nonce: "abcDEF123456", issuedAt: now };
    expect(() => signInText(msg, address, networkPassphrase)).toThrow(CSignError);
    expect(() => signInText({ ...msg, statement: "x" }, "CCL5EDN2VGJYHY4BAF2ZXBE7LWP6QJ3TNZ64FLYUCQPRHRUOLIWHNFD5", networkPassphrase)).toThrow(CSignError);
    expect(chainId(Networks.PUBLIC)).toBe("stellar:pubnet");
    expect(() => chainId("Standalone Network ; February 2017")).toThrow(CSignError);
  });
});

describe("verifySignIn for a G account", () => {
  const setup = () => {
    const kp = Keypair.random();
    const nonces = new MemoryNonceStore({ now: () => now });
    const message = createSignInMessage({ domain, statement: "Sign in", ...nonces.issue() });
    const signature = signSignInWithKeypair(message, kp, networkPassphrase);
    const verify = (over: Partial<Parameters<typeof verifySignIn>[0]> = {}) =>
      verifySignIn({ signature, address: kp.publicKey(), message, rpcUrl, allowHttp: true, networkPassphrase, domain, now, nonces, ...over });
    return { kp, nonces, message, signature, verify };
  };
  const failedStep = (r: { steps: { id: string; status: string }[] }) => r.steps.find((s) => s.status === "fail" || s.status === "error")?.id;

  it("is valid once, offline, and a replay is invalid", async () => {
    const { verify, kp } = setup();
    const first = await verify();
    expect(first.status).toBe("valid");
    expect(first.account).toBe(kp.publicKey());
    expect(first.steps.map((s) => s.id)).toEqual(["decode", "message", "domain", "freshness", "sep53", "consume"]);
    const replay = await verify();
    expect(replay.status).toBe("invalid");
    expect(failedStep(replay)).toBe("freshness");
  });

  it("is invalid for another key, another network, a changed message and another domain, and leaves the nonce unused", async () => {
    const { verify, message, nonces } = setup();
    expect(failedStep(await verify({ address: Keypair.random().publicKey() }))).toBe("sep53");
    expect(failedStep(await verify({ networkPassphrase: Networks.PUBLIC }))).toBe("sep53");
    expect(failedStep(await verify({ message: { ...message, statement: "Transfer everything" } }))).toBe("sep53");
    expect(failedStep(await verify({ domain: "evil.example" }))).toBe("domain");
    expect(nonces.issuedAt(message.nonce)).toBe(now);
  });

  it("needs the message and a 64-byte signature", async () => {
    const { verify } = setup();
    expect(failedStep(await verify({ message: undefined }))).toBe("message");
    expect(failedStep(await verify({ signature: btoa("short") }))).toBe("decode");
    expect(failedStep(await verify({ address: "GNOTANADDRESS" }))).toBe("decode");
  });

  it("checks a message without a nonce in verifyMessage", async () => {
    const { kp, message, signature } = setup();
    const r = await verifyMessage({ signature, address: kp.publicKey(), message, rpcUrl, allowHttp: true, networkPassphrase, domain, now });
    expect(r.status).toBe("valid");
    expect(r.steps.find((s) => s.id === "freshness")?.status).toBe("skip");
  });
});
