import { afterEach, describe, expect, it, vi } from "vitest";
import { StrKey, rpc } from "@stellar/stellar-sdk";
import { CSignError, addressCredentials, createMessageEntry, parseMessageEntry, type SignedMessage } from "../src/index.js";

const verifierId = "CCL5EDN2VGJYHY4BAF2ZXBE7LWP6QJ3TNZ64FLYUCQPRHRUOLIWHNFD5";
const account = StrKey.encodeContract(Buffer.alloc(32, 9));
const message: SignedMessage = { version: "1", domain: "example.com", statement: "Sign in", nonce: "abcDEF123456", issuedAt: 1_790_000_000 };
const params = { verifierId, account, message, rpcUrl: "http://127.0.0.1:1", allowHttp: true };

describe("createMessageEntry", () => {
  afterEach(() => vi.restoreAllMocks());

  const latest = (sequence: number) =>
    vi.spyOn(rpc.Server.prototype, "getLatestLedger").mockResolvedValue({ id: "", sequence, protocolVersion: "25" } as never);

  it("expires 720 ledgers after the latest ledger by default", async () => {
    latest(5000);
    const { entry, expirationLedger } = await createMessageEntry(params);
    expect(expirationLedger).toBe(5720);
    expect(addressCredentials(entry).signatureExpirationLedger()).toBe(5720);
    expect(parseMessageEntry(entry)).toMatchObject({ account, verifierId, message });
  });

  it("takes validForLedgers", async () => {
    latest(5000);
    expect((await createMessageEntry({ ...params, validForLedgers: 60 })).expirationLedger).toBe(5060);
  });

  it("rejects a lifetime a relying party would refuse", async () => {
    await expect(createMessageEntry({ ...params, validForLedgers: 17281 })).rejects.toThrow(CSignError);
    await expect(createMessageEntry({ ...params, validForLedgers: 0 })).rejects.toThrow(CSignError);
  });
});
