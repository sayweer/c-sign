import { afterEach, describe, expect, it, vi } from "vitest";
import { Address, Keypair, Networks, StrKey, rpc, xdr } from "@stellar/stellar-sdk";
import {
  CSignError,
  REFERENCE_WASM_HASH,
  buildMessageEntry,
  checkMessageRequest,
  domainFromOrigin,
  isMessageEntry,
  messageToScVal,
  parseMessageEntry,
  signOzEntryWithEd25519,
  signOzMessageWithEd25519,
  type SignedMessage,
} from "../src/index.js";
import { fromHex } from "../src/bytes.js";
import { asV1, withCall, withCredentialAddress, withRoot } from "./helpers.js";

const networkPassphrase = Networks.TESTNET;
const verifierId = StrKey.encodeContract(Buffer.alloc(32, 3));
const account = StrKey.encodeContract(Buffer.alloc(32, 7));
const message: SignedMessage = { version: "1", domain: "demo.c-sign.dev", statement: "Sign in", nonce: "abcDEF123456", issuedAt: 1_790_000_000 };
const entry = () => buildMessageEntry({ verifierId, account, message, expirationLedger: 1000 });
const key = { keypair: Keypair.fromRawEd25519Seed(Buffer.alloc(32, 1)), verifierId };

describe("domainFromOrigin", () => {
  it("refuses anything that is not a bare origin", () => {
    for (const origin of ["not a url", "https://a.b/path", "https://a.b/?q=1", "https://a.b/#h", "https://user@a.b", "ftp://a.b", "file:///etc/hosts"]) {
      expect(domainFromOrigin(origin), origin).toBeUndefined();
    }
  });

  it("allows http only for localhost in developer mode", () => {
    expect(domainFromOrigin("http://evil.example", { developerMode: true })).toBeUndefined();
    expect(domainFromOrigin("http://localhost:3000", { developerMode: true })).toBe("localhost:3000");
  });
});

describe("parseMessageEntry", () => {
  it("returns the decoded message, not a copy from the application", () => {
    const parsed = parseMessageEntry(entry());
    expect(parsed).toEqual({ account, verifierId, message, expirationLedger: 1000 });
  });

  it("refuses other functions, sub-invocations, V1 credentials, other accounts and bad messages", () => {
    const cases: ((e: xdr.SorobanAuthorizationEntry) => xdr.SorobanAuthorizationEntry)[] = [
      (e) => withCall(e, () => ({ functionName: "transfer" })),
      (e) => withRoot(e, { subInvocations: [entry().rootInvocation] }),
      asV1,
      (e) => withCredentialAddress(e, verifierId),
      (e) => withCall(e, (call) => ({ args: [call.args[0]!, messageToScVal({ ...message, statement: "a\nb" }, false)] })),
    ];
    for (const mutate of cases) {
      expect(() => parseMessageEntry(mutate(entry()))).toThrow(CSignError);
    }
  });
});

describe("OpenZeppelin signing", () => {
  it("generic signing refuses a message entry", () => {
    expect(isMessageEntry(entry())).toBe(true);
    expect(() => signOzEntryWithEd25519(entry(), [key], networkPassphrase, "preimage-v1")).toThrow(/message entry/);
  });

  it("message signing checks the entry first", () => {
    expect(() => signOzMessageWithEd25519(entry(), [key], networkPassphrase, "preimage-v1")).not.toThrow();
    const bad = withRoot(entry(), { subInvocations: [entry().rootInvocation] });
    expect(() => signOzMessageWithEd25519(bad, [key], networkPassphrase, "preimage-v1")).toThrow(/sub-invocations/);
  });
});

describe("checkMessageRequest", () => {
  afterEach(() => vi.restoreAllMocks());

  const stub = (over: { passphrase?: string; wasm?: string; executable?: xdr.ContractExecutable; missing?: boolean; liveUntil?: number } = {}) => {
    const proto = rpc.Server.prototype;
    vi.spyOn(proto, "getNetwork").mockResolvedValue({ passphrase: over.passphrase ?? networkPassphrase, protocolVersion: "25" } as never);
    vi.spyOn(proto, "getLatestLedger").mockResolvedValue({ id: "", sequence: 900, protocolVersion: "25", closeTime: "0" } as never);
    const executable = over.executable ?? xdr.ContractExecutable.contractExecutableWasm(fromHex(over.wasm ?? REFERENCE_WASM_HASH));
    const data = xdr.LedgerEntryData.contractData(
      new xdr.ContractDataEntry({
        ext: xdr.ExtensionPoint.v0(),
        contract: Address.fromString(verifierId).toScAddress(),
        key: xdr.ScVal.scvLedgerKeyContractInstance(),
        durability: xdr.ContractDataDurability.persistent,
        val: xdr.ScVal.scvContractInstance(new xdr.ScContractInstance({ executable, storage: null })),
      }),
    );
    const entries = over.missing ? [] : [{ key: {}, val: data, liveUntilLedgerSeq: over.liveUntil ?? 100_000 }];
    vi.spyOn(proto, "getLedgerEntries").mockResolvedValue({ latestLedger: 900, entries } as never);
  };
  const check = (over = {}) =>
    checkMessageRequest({ entry: entry(), origin: "https://demo.c-sign.dev", rpcUrl: "https://rpc.example", networkPassphrase, ...over });

  it("accepts a request from its own origin to the reference verifier", async () => {
    stub();
    await expect(check()).resolves.toMatchObject({ account, verifierId });
  });

  it("refuses another origin and an origin that is not https", async () => {
    stub();
    await expect(check({ origin: "https://evil.example" })).rejects.toThrow(/request came from evil.example/);
    await expect(check({ origin: "http://demo.c-sign.dev" })).rejects.toThrow(/not a verified domain/);
  });

  it("refuses a verifier it cannot confirm", async () => {
    stub({ wasm: "00".repeat(32) });
    await expect(check()).rejects.toThrow(/not an accepted hash/);
    stub({ missing: true });
    await expect(check()).rejects.toThrow(/No contract/);
    stub({ liveUntil: 1 });
    await expect(check()).rejects.toThrow(/archived/);
    stub({ executable: xdr.ContractExecutable.contractExecutableStellarAsset() });
    await expect(check()).rejects.toThrow(/not a Wasm/);
    stub({ passphrase: Networks.PUBLIC });
    await expect(check()).rejects.toThrow(/Could not check/);
  });
});
