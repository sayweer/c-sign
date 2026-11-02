import { afterEach, describe, expect, it, vi } from "vitest";
import { Address, Keypair, Networks, StrKey, rpc, xdr } from "@stellar/stellar-sdk";
import {
  buildMessageEntry,
  encodeEntry,
  messageToScVal,
  REFERENCE_WASM_HASH,
  verifyMessage,
  verifySignIn,
  type NonceStore,
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
    allowHttp: true,
    networkPassphrase,
    domain: "demo.c-sign.dev",
    now,
    ...extra,
  });

const signIn = (nonces: Partial<NonceStore>) =>
  verifySignIn({
    signature: encodeEntry(entry()),
    rpcUrl,
    allowHttp: true,
    networkPassphrase,
    domain: "demo.c-sign.dev",
    now,
    nonces: { issuedAt: () => now, consume: () => true, ...nonces },
  });

const stepStatus = (r: Awaited<ReturnType<typeof verify>>, id: string) => r.steps.find((s) => s.id === id)?.status;

describe("verifyMessage, offline rules", () => {
  it("rejects malformed XDR", async () => {
    const r = await verify("not-xdr");
    expect(r.status).toBe("invalid");
    expect(stepStatus(r, "decode")).toBe("fail");
  });

  it("applies the size limits before decoding", async () => {
    const tooLong = await verify("A".repeat(21852));
    expect(tooLong.reason).toMatch(/longer than 21848/);
    const tooLarge = await verify(Buffer.alloc(16385).toString("base64"));
    expect(tooLarge.reason).toMatch(/larger than 16384/);
    expect(stepStatus(tooLarge, "decode")).toBe("fail");
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

  it("rejects stale or replayed sign-ins, measuring age from when the nonce was issued", async () => {
    const stale = await signIn({ issuedAt: () => now - 301 });
    expect(stale.reason).toMatch(/issued 301s ago/);
    const replay = await signIn({ issuedAt: () => undefined });
    expect(replay.reason).toMatch(/not issued here/);
    expect(replay.status).toBe("invalid");
  });

  it("makes a failing nonce store inconclusive instead of throwing", async () => {
    const r = await signIn({ issuedAt: () => Promise.reject(new Error("store down")) });
    expect(r.status).toBe("inconclusive");
    expect(stepStatus(r, "freshness")).toBe("error");
  });

  it("fails closed when a JavaScript caller omits domain", async () => {
    const r = await verify(entry(), { domain: undefined });
    expect(r.status).toBe("invalid");
    expect(stepStatus(r, "domain")).toBe("fail");
  });

  it("does not consume the nonce when the RPC is unavailable", async () => {
    const consume = vi.fn(() => true);
    const r = await signIn({ consume });
    expect(r.status).toBe("inconclusive");
    expect(consume).not.toHaveBeenCalled();
  });

  it("caps clock skew at 60 s whatever the caller asks for", async () => {
    const r = await verify(entry(), { now: now - 61, clockSkewSeconds: 3600 });
    expect(r.reason).toMatch(/in the future/);
  });

  it("reports RPC failure as inconclusive, never invalid", async () => {
    const r = await verify(entry());
    expect(r.status).toBe("inconclusive");
    expect(stepStatus(r, "network")).toBe("error");
    expect(r.steps.map((s) => s.id)).toEqual([
      "decode", "shape", "credentials", "rebuild", "message", "domain", "freshness", "network", "expiration", "pin", "check_auth", "consume",
    ]);
  });

  it("refuses a plain http RPC without the opt-in, as inconclusive", async () => {
    const r = await verify(entry(), { allowHttp: undefined });
    expect(r.status).toBe("inconclusive");
    expect(r.reason).toMatch(/allowHttp/);
  });
});

describe("verifySignIn, nonce consumption", () => {
  afterEach(() => vi.restoreAllMocks());

  // A distinct verifier for each test, so the pin cache does not carry over.
  const authorized = (verifierId: string) => {
    const proto = rpc.Server.prototype;
    vi.spyOn(proto, "getNetwork").mockResolvedValue({ passphrase: networkPassphrase, protocolVersion: "25" } as never);
    vi.spyOn(proto, "getLatestLedger").mockResolvedValue({ id: "", sequence: 900, protocolVersion: "25", closeTime: String(now) } as never);
    const executable = xdr.ContractExecutable.contractExecutableWasm(Buffer.from(REFERENCE_WASM_HASH, "hex"));
    const val = xdr.ScVal.scvContractInstance(new xdr.ScContractInstance({ executable, storage: null }));
    const data = xdr.LedgerEntryData.contractData(
      new xdr.ContractDataEntry({
        ext: new xdr.ExtensionPoint(0),
        contract: Address.fromString(verifierId).toScAddress(),
        key: xdr.ScVal.scvLedgerKeyContractInstance(),
        durability: xdr.ContractDataDurability.persistent(),
        val,
      }),
    );
    vi.spyOn(proto, "getLedgerEntries").mockResolvedValue({ latestLedger: 900, entries: [{ key: {}, val: data, liveUntilLedgerSeq: 100_000 }] } as never);
    const event = new xdr.DiagnosticEvent({
      inSuccessfulContractCall: false,
      event: new xdr.ContractEvent({
        ext: new xdr.ExtensionPoint(0),
        contractId: Address.fromString(verifierId).toScAddress().contractId(),
        type: xdr.ContractEventType.diagnostic(),
        body: new xdr.ContractEventBody(0, new xdr.ContractEventV0({
          topics: [xdr.ScVal.scvSymbol("error"), xdr.ScVal.scvError(xdr.ScError.sceContract(1))],
          data: xdr.ScVal.scvVoid(),
        })),
      }),
    });
    vi.spyOn(proto, "simulateTransaction").mockResolvedValue({ id: "1", latestLedger: 900, events: [event], _parsed: true, error: "HostError: Error(Contract, #1)" } as never);
  };
  const run = (verifierId: string, nonces: NonceStore) =>
    verifySignIn({
      signature: encodeEntry(buildMessageEntry({ verifierId, account, message, expirationLedger: 1000 })),
      rpcUrl,
      allowHttp: true,
      networkPassphrase,
      domain: message.domain,
      now,
      nonces,
    });

  it("is invalid when another request consumed the nonce first", async () => {
    const verifierId = StrKey.encodeContract(Buffer.alloc(32, 21));
    authorized(verifierId);
    const r = await run(verifierId, { issuedAt: () => now, consume: () => false });
    expect(r.status).toBe("invalid");
    expect(stepStatus(r, "consume")).toBe("fail");
  });

  it("is inconclusive when consuming the nonce fails", async () => {
    const verifierId = StrKey.encodeContract(Buffer.alloc(32, 22));
    authorized(verifierId);
    const r = await run(verifierId, { issuedAt: () => now, consume: () => Promise.reject(new Error("store down")) });
    expect(r.status).toBe("inconclusive");
    expect(stepStatus(r, "consume")).toBe("error");
  });

  it("consumes the nonce once on valid", async () => {
    const verifierId = StrKey.encodeContract(Buffer.alloc(32, 23));
    authorized(verifierId);
    const consume = vi.fn(() => true);
    const r = await run(verifierId, { issuedAt: () => now, consume });
    expect(r.status).toBe("valid");
    expect(consume).toHaveBeenCalledExactlyOnceWith(message.nonce);
    expect(stepStatus(r, "consume")).toBe("pass");
  });
});
