import { afterEach, describe, expect, it, vi } from "vitest";
import { Keypair, Networks, StrKey, rpc, xdr } from "@stellar/stellar-sdk";
import {
  CSignError,
  addressCredentials,
  buildMessageEntry,
  signPasskeyKitEntryWithEd25519,
  simulateAuthorizedCall,
  type AuthorizedCallOptions,
} from "../src/index.js";
import { contractCall } from "./helpers.js";

const networkPassphrase = Networks.TESTNET;
const wallet = StrKey.encodeContract(Buffer.alloc(32, 5));
const key = Keypair.random();

describe("simulateAuthorizedCall", () => {
  afterEach(() => vi.restoreAllMocks());

  const stub = (simulation: object) => {
    const proto = rpc.Server.prototype;
    vi.spyOn(proto, "getLatestLedger").mockResolvedValue({ id: "", sequence: 900, protocolVersion: "25" } as never);
    return vi.spyOn(proto, "simulateTransaction").mockResolvedValue({ id: "1", latestLedger: 900, events: [], _parsed: true, ...simulation } as never);
  };
  const options = (over: Partial<AuthorizedCallOptions> = {}): AuthorizedCallOptions => ({
    rpcUrl: "http://127.0.0.1:1",
    allowHttp: true,
    networkPassphrase,
    account: wallet,
    contract: wallet,
    function: "add_signer",
    args: [xdr.ScVal.scvVoid()],
    sign: (entry) => signPasskeyKitEntryWithEd25519(entry, [key], networkPassphrase),
    ...over,
  });

  it("signs the call with a short expiration and simulates it in enforcing mode", async () => {
    const simulate = stub({ transactionData: {}, minResourceFee: "0" });
    let signedFor: xdr.SorobanAuthorizationEntry | undefined;
    const r = await simulateAuthorizedCall(options({ sign: (entry) => ((signedFor = entry), signPasskeyKitEntryWithEd25519(entry, [key], networkPassphrase)) }));
    expect(r.status).toBe("valid");
    expect(addressCredentials(signedFor!).signatureExpirationLedger).toBe(902);
    expect(contractCall(signedFor!).functionName.toString()).toBe("add_signer");
    expect(simulate.mock.calls[0]![2]).toBe("enforce");
  });

  it("is invalid when the account rejects the key", async () => {
    stub({ error: "HostError: Error(Auth, InvalidAction)\n..." });
    expect((await simulateAuthorizedCall(options())).status).toBe("invalid");
  });

  it("is inconclusive when the call fails for another reason or the RPC is down", async () => {
    stub({ error: "HostError: Error(Contract, #3)" });
    expect((await simulateAuthorizedCall(options())).status).toBe("inconclusive");
    vi.restoreAllMocks();
    expect((await simulateAuthorizedCall(options())).status).toBe("inconclusive");
  });
});

describe("signPasskeyKitEntryWithEd25519", () => {
  it("refuses a message entry", () => {
    const entry = buildMessageEntry({
      verifierId: "CCL5EDN2VGJYHY4BAF2ZXBE7LWP6QJ3TNZ64FLYUCQPRHRUOLIWHNFD5",
      account: wallet,
      message: { version: "1", domain: "example.com", statement: "x", nonce: "abcDEF123456", issuedAt: 1 },
      expirationLedger: 10,
    });
    expect(() => signPasskeyKitEntryWithEd25519(entry, [key], networkPassphrase)).toThrow(CSignError);
  });
});
