import { describe, expect, it } from "vitest";
import { Address, Keypair, Networks, StrKey, xdr } from "@stellar/stellar-sdk";
import {
  buildMessageEntry,
  encodeEntry,
  messageToScVal,
  verifyMessage,
  type SignedMessage,
} from "../src/index.js";

// Structural rules are checked before any network call, so these tests run offline.
const rpcUrl = "http://127.0.0.1:1"; // unreachable on purpose
const networkPassphrase = Networks.TESTNET;
const verifierId = "CCL5EDN2VGJYHY4BAF2ZXBE7LWP6QJ3TNZ64FLYUCQPRHRUOLIWHNFD5";
const account = StrKey.encodeContract(Buffer.alloc(32, 7));
const now = 1_790_000_000;
const message: SignedMessage = { version: "1", domain: "demo.c-sign.dev", statement: "Sign in", nonce: "abcDEF123456", issuedAt: now };

const entry = () => buildMessageEntry({ verifierId, account, message, expirationLedger: 1000 });
const verify = (e: xdr.SorobanAuthorizationEntry | string, extra = {}) =>
  verifyMessage({
    signature: typeof e === "string" ? e : encodeEntry(e),
    rpcUrl,
    networkPassphrase,
    domain: "demo.c-sign.dev",
    now,
    ...extra,
  });

const stepStatus = (r: Awaited<ReturnType<typeof verify>>, id: string) => r.steps.find((s) => s.id === id)?.status;

describe("verifyMessage, offline rules", () => {
  it("rejects malformed XDR", async () => {
    const r = await verify("not-xdr");
    expect(r.status).toBe("invalid");
    expect(stepStatus(r, "decode")).toBe("fail");
  });

  it("rejects a call to another function", async () => {
    const e = entry();
    e.rootInvocation().function().contractFn().functionName("transfer");
    expect((await verify(e)).reason).toMatch(/not verify_message/);
  });

  it("rejects sub-invocations", async () => {
    const e = entry();
    e.rootInvocation().subInvocations([entry().rootInvocation()]);
    expect((await verify(e)).reason).toMatch(/sub-invocations/);
  });

  it("rejects V1 credentials", async () => {
    const e = entry();
    e.credentials(xdr.SorobanCredentials.sorobanCredentialsAddress(e.credentials().addressV2()));
    const r = await verify(e);
    expect(r.status).toBe("invalid");
    expect(stepStatus(r, "credentials")).toBe("fail");
  });

  it("rejects credentials for another account", async () => {
    const e = entry();
    e.credentials().addressV2().address(Address.fromString(StrKey.encodeContract(Buffer.alloc(32, 9))).toScAddress());
    expect((await verify(e)).reason).toMatch(/differs from the account/);
  });

  it("rejects an unexpected signer", async () => {
    const r = await verify(entry(), { address: StrKey.encodeContract(Buffer.alloc(32, 1)) });
    expect(r.reason).toMatch(/expected/);
  });

  it("rejects G accounts", async () => {
    const g = Keypair.random().publicKey();
    const e = buildMessageEntry({ verifierId, account: g, message, expirationLedger: 1000 });
    expect((await verify(e)).reason).toMatch(/SEP-53/);
  });

  it("rejects a message with unknown keys", async () => {
    const e = entry();
    const msg = messageToScVal(message);
    msg.map()!.push(new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol("zzz"), val: xdr.ScVal.scvVoid() }));
    e.rootInvocation().function().contractFn().args([Address.fromString(account).toScVal(), msg]);
    const r = await verify(e);
    expect(stepStatus(r, "message")).toBe("fail");
  });

  it("rejects another domain", async () => {
    const r = await verify(entry(), { domain: "evil.example" });
    expect(r.status).toBe("invalid");
    expect(stepStatus(r, "domain")).toBe("fail");
  });

  it("rejects stale or replayed sign-ins", async () => {
    const stale = await verify(entry(), { now: now + 3600, freshness: { checkNonce: () => true } });
    expect(stale.reason).toMatch(/Issued 3600s ago/);
    const replay = await verify(entry(), { freshness: { checkNonce: () => false } });
    expect(replay.reason).toMatch(/Nonce/);
  });

  it("reports RPC failure as inconclusive, never invalid", async () => {
    const r = await verify(entry());
    expect(r.status).toBe("inconclusive");
    expect(stepStatus(r, "expiration")).toBe("error");
    expect(r.steps.map((s) => s.id)).toEqual([
      "decode", "shape", "credentials", "rebuild", "message", "domain", "freshness", "expiration", "pin", "check_auth",
    ]);
  });
});
