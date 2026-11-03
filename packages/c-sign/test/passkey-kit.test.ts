import { describe, expect, it } from "vitest";
import { Keypair, Networks, xdr } from "@stellar/stellar-sdk";
import { Ed25519Signer as Signer020, PasskeyClient as Client020, PasskeyKit as Kit020 } from "passkey-kit";
import { Ed25519Signer as Signer014, PasskeyClient as Client014, PasskeyKit as Kit014 } from "passkey-kit-014";
import {
  CSignError,
  addressCredentials,
  buildMessageEntry,
  encodeEntry,
  signMessageWithPasskeyKit,
  signPasskeyKitMessageWithEd25519,
} from "../src/index.js";

const ACCOUNT = "CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE";
const VERIFIER = "CAAVTMCBXEIBPR64EAASKFXERVPYFZA2JYP5A3BG6PESWEFUJX5IHKN4";
const WASM = "97ce047884106b1c6c3bb40b8973cc48db1c4dad95c9e20462bf2c701daa764e";
const config = { rpcUrl: "https://soroban-testnet.stellar.org", networkPassphrase: Networks.TESTNET, walletWasmHash: WASM };

const entry = () =>
  buildMessageEntry({
    verifierId: VERIFIER,
    account: ACCOUNT,
    message: { version: "1", domain: "app.example.com", statement: "Sign in", nonce: "abcdef12345678", issuedAt: 1_800_000_000 },
    expirationLedger: 1000,
  });

// A kit signs only once a wallet is attached.
const wallet = { contractId: ACCOUNT, rpcUrl: config.rpcUrl, networkPassphrase: config.networkPassphrase };
const kit014 = new Kit014(config);
kit014.wallet = new Client014(wallet);
const kit020 = new Kit020(config);
kit020.wallet = new Client020(wallet);

const kits = [
  ["0.14.0", kit014, (k: Keypair) => new Signer014(k)],
  ["0.20.0", kit020, (k: Keypair) => new Signer020(k)],
] as const;

describe.each(kits)("passkey-kit %s", (_version, kit, makeSigner) => {
  const sign = (e: xdr.SorobanAuthorizationEntry, k: Keypair) =>
    signMessageWithPasskeyKit(kit as never, e, makeSigner(k) as never);

  it("our Ed25519 encoding equals what the kit writes", async () => {
    const key = Keypair.random();
    const e = entry();
    const viaKit = await sign(e, key);
    expect(encodeEntry(signPasskeyKitMessageWithEd25519(e, [key], Networks.TESTNET))).toBe(encodeEntry(viaKit));
  });

  it("orders several signers as the kit does", async () => {
    const keys = [Keypair.random(), Keypair.random(), Keypair.random()];
    const e = entry();
    let viaKit = e;
    for (const key of keys) viaKit = await sign(viaKit, key);
    expect(encodeEntry(signPasskeyKitMessageWithEd25519(e, keys, Networks.TESTNET))).toBe(encodeEntry(viaKit));
  });

  it("does not touch the entry it is given, and keeps its expiration", async () => {
    const e = entry();
    const before = encodeEntry(e);
    const signed = await sign(e, Keypair.random());
    expect(encodeEntry(e)).toBe(before);
    expect(addressCredentials(signed).signatureExpirationLedger()).toBe(1000);
  });
});

describe("message guard", () => {
  const notAMessage = () => {
    const e = entry();
    e.rootInvocation().function().contractFn().functionName("transfer");
    return e;
  };
  const withSubInvocation = () => {
    const e = entry();
    e.rootInvocation().subInvocations([e.rootInvocation()]);
    return e;
  };

  it.each([
    ["another function", notAMessage],
    ["a sub-invocation", withSubInvocation],
  ])("refuses an entry with %s before reaching the kit", async (_name, make) => {
    let called = false;
    const kit = { signAuthEntry: async (e: xdr.SorobanAuthorizationEntry) => ((called = true), e) };
    await expect(signMessageWithPasskeyKit(kit, make())).rejects.toThrow(CSignError);
    expect(called).toBe(false);
    expect(() => signPasskeyKitMessageWithEd25519(make(), [Keypair.random()], Networks.TESTNET)).toThrow(CSignError);
  });
});
