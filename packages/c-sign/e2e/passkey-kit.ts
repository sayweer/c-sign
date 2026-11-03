// Testnet experiments for passkey-kit wallets, with the real kit and a software authenticator.
//
//   pnpm e2e:passkey-kit
//
// Every wallet, key and sponsor is fresh. Writes docs/EXPERIMENTS-PASSKEY-KIT.md.
import { writeFileSync } from "node:fs";
import { createHash, generateKeyPairSync, randomBytes, sign as nodeSign } from "node:crypto";
import { Address, Keypair, Operation, TransactionBuilder, xdr, type Transaction } from "@stellar/stellar-sdk";
import { PasskeyClient as Client020, PasskeyKit as Kit020, PasskeySigner as PasskeySigner020, SignerStore } from "passkey-kit";
import { Ed25519Signer as Ed25519Signer014, PasskeyClient as Client014, PasskeyKit as Kit014, PasskeySigner as PasskeySigner014 } from "passkey-kit-014";
import {
  addressCredentials,
  buildMessageEntry,
  encodeEntry,
  entrySignaturePayload,
  signMessageWithPasskeyKit,
  signPasskeyKitMessageWithEd25519,
  verifyMessage,
  type VerifyResult,
} from "../src/index.js";
import { deployments, fundedKeypair, networkPassphrase, rpcUrl, server, submit } from "./testnet.js";

/** Smart-wallet Wasm passkey-kit 0.14 deployed on testnet; Eunomia's WALLET_WASM_HASH. */
const WASM_014 = "fdefad64b96837147e1c333e51f537b696eab925e9f147e63d597c04e3c903f0";
/** Canonical smart-wallet Wasm in passkey-kit 0.20's documentation. */
const WASM_020 = "97ce047884106b1c6c3bb40b8973cc48db1c4dad95c9e20462bf2c701daa764e";
const RP_ID = "demo.c-sign.dev";
const ORIGIN = `https://${RP_ID}`;
const VERIFIER = deployments.instances[0];

const b64url = (b: Buffer | Uint8Array) => Buffer.from(b).toString("base64url");
const sha256 = (b: Buffer) => createHash("sha256").update(b).digest();

/** A P-256 credential behind the `startRegistration` / `startAuthentication` the kit calls. */
class SoftwareAuthenticator {
  readonly id = randomBytes(32);
  private readonly key = generateKeyPairSync("ec", { namedCurve: "P-256" });
  readonly publicKey = this.key.publicKey.export({ format: "der", type: "spki" }).subarray(-65) as Buffer;

  private authData() {
    return Buffer.concat([sha256(Buffer.from(RP_ID)), Buffer.from([0x05]), Buffer.alloc(4)]);
  }

  private clientData(type: string, challenge: string) {
    return Buffer.from(JSON.stringify({ type, challenge, origin: ORIGIN, crossOrigin: false }));
  }

  startRegistration = async ({ optionsJSON }: { optionsJSON: { challenge: string } }) => ({
    id: b64url(this.id),
    rawId: b64url(this.id),
    type: "public-key",
    clientExtensionResults: {},
    response: {
      clientDataJSON: b64url(this.clientData("webauthn.create", optionsJSON.challenge)),
      attestationObject: "",
      transports: [],
      publicKey: b64url(this.publicKey),
      publicKeyAlgorithm: -7,
    },
  });

  startAuthentication = async ({ optionsJSON }: { optionsJSON: { challenge: string } }) => {
    const authenticatorData = this.authData();
    const clientData = this.clientData("webauthn.get", optionsJSON.challenge);
    const signature = nodeSign("sha256", Buffer.concat([authenticatorData, sha256(clientData)]), this.key.privateKey);
    return {
      id: b64url(this.id),
      rawId: b64url(this.id),
      type: "public-key",
      clientExtensionResults: {},
      response: {
        authenticatorData: b64url(authenticatorData),
        clientDataJSON: b64url(clientData),
        signature: b64url(signature),
      },
    };
  };
}

// Soroban encodings of the wallet's contract types, shared by both Wasm versions.
const NO_EXPIRATION = xdr.ScVal.scvVec([xdr.ScVal.scvVoid()]);
const PERSISTENT = xdr.ScVal.scvVec([xdr.ScVal.scvSymbol("Persistent")]);
const UNLIMITED = xdr.ScVal.scvVec([xdr.ScVal.scvVoid()]);
/** `SignerLimits(Some({ contract: None }))`: the signer may act on this contract only. Eunomia's `walletOnlyLimits`. */
const onlyContract = (contract: string) =>
  xdr.ScVal.scvVec([
    xdr.ScVal.scvMap([new xdr.ScMapEntry({ key: Address.fromString(contract).toScVal(), val: xdr.ScVal.scvVoid() })]),
  ]);
const ed25519Signer = (key: Keypair, limits: xdr.ScVal) =>
  xdr.ScVal.scvVec([xdr.ScVal.scvSymbol("Ed25519"), xdr.ScVal.scvBytes(Buffer.from(key.rawPublicKey())), NO_EXPIRATION, limits, PERSISTENT]);
const secp256r1Signer014 = (a: SoftwareAuthenticator) =>
  xdr.ScVal.scvVec([xdr.ScVal.scvSymbol("Secp256r1"), xdr.ScVal.scvBytes(a.id), xdr.ScVal.scvBytes(a.publicKey), NO_EXPIRATION, UNLIMITED, PERSISTENT]);

async function submitOp(sponsor: Keypair, op: xdr.Operation) {
  const account = await server.getAccount(sponsor.publicKey());
  const built = new TransactionBuilder(account, { fee: "1000000", networkPassphrase }).addOperation(op).setTimeout(60).build();
  const tx = await server.prepareTransaction(built);
  tx.sign(sponsor);
  return submit(tx);
}

async function deployWallet(sponsor: Keypair, wasmHash: string, args: xdr.ScVal[]): Promise<string> {
  const res = await submitOp(
    sponsor,
    Operation.createCustomContract({
      address: Address.fromString(sponsor.publicKey()),
      wasmHash: Buffer.from(wasmHash, "hex"),
      salt: randomBytes(32),
      constructorArgs: args,
    }),
  );
  if (res.status !== "SUCCESS" || !res.returnValue) throw new Error(`Wallet deploy failed: ${res.status} ${res.hash}`);
  return Address.fromScVal(res.returnValue).toString();
}

/** Adds a signer, authorized by an unlimited Ed25519 signer already on the wallet. */
async function addSigner(sponsor: Keypair, wallet: string, signer: xdr.ScVal, admin: Keypair) {
  const call = { contract: wallet, function: "add_signer", args: [signer] };
  const account = await server.getAccount(sponsor.publicKey());
  const sim = await server.simulateTransaction(
    new TransactionBuilder(account, { fee: "1000000", networkPassphrase }).addOperation(Operation.invokeContractFunction(call)).setTimeout(60).build(),
  );
  if (!("result" in sim) || !sim.result) throw new Error(`add_signer simulation failed: ${JSON.stringify(sim).slice(0, 300)}`);
  const latest = (await server.getLatestLedger()).sequence;
  const auth = sim.result.auth.map((entry) => {
    const creds = entry.credentials().switch().name === "sorobanCredentialsAddressV2" ? entry.credentials().addressV2() : entry.credentials().address();
    creds.signatureExpirationLedger(latest + 100);
    return signAdminEntry(entry, admin);
  });
  const res = await submitOp(sponsor, Operation.invokeContractFunction({ ...call, auth }));
  if (res.status !== "SUCCESS") throw new Error(`add_signer failed: ${res.status} ${res.hash}`);
}

/** Signs a wallet-admin entry directly: the message signers of this package refuse anything but a message. */
function signAdminEntry(entry: xdr.SorobanAuthorizationEntry, key: Keypair) {
  const copy = xdr.SorobanAuthorizationEntry.fromXDR(entry.toXDR());
  if (copy.credentials().switch().name === "sorobanCredentialsAddress") {
    copy.credentials(xdr.SorobanCredentials.sorobanCredentialsAddressV2(copy.credentials().address()));
  }
  const tag = (bytes: Buffer) => xdr.ScVal.scvVec([xdr.ScVal.scvSymbol("Ed25519"), xdr.ScVal.scvBytes(bytes)]);
  const signature = key.sign(entrySignaturePayload(copy, networkPassphrase));
  addressCredentials(copy).signature(
    xdr.ScVal.scvVec([xdr.ScVal.scvMap([new xdr.ScMapEntry({ key: tag(Buffer.from(key.rawPublicKey())), val: tag(signature) })])]),
  );
  return copy;
}

const rows: { id: string; what: string; expected: string; observed: string; pass: boolean }[] = [];
function record(id: string, what: string, expected: VerifyResult["status"], result: VerifyResult) {
  const failed = result.steps.find((s) => s.status === "fail" || s.status === "error");
  const observed = result.status === "valid" ? "valid" : `${result.status} (${failed?.id}: ${result.reason})`;
  const pass = result.status === expected;
  rows.push({ id, what, expected, observed, pass });
  console.log(`${pass ? "PASS" : "FAIL"}  ${id}  ${what}: ${observed}`);
}

const verify = (entry: xdr.SorobanAuthorizationEntry) =>
  verifyMessage({ signature: encodeEntry(entry), rpcUrl, networkPassphrase, domain: RP_ID });

async function entryFor(account: string, statement: string) {
  const latest = (await server.getLatestLedger()).sequence;
  return buildMessageEntry({
    verifierId: VERIFIER,
    account,
    message: { version: "1", domain: RP_ID, statement, nonce: randomBytes(8).toString("hex"), issuedAt: Math.floor(Date.now() / 1000) },
    expirationLedger: latest + 720,
  });
}

function writeReport(wallets: Record<string, string>) {
  const lines = [
    "# passkey-kit experiments",
    "",
    `Generated by \`pnpm e2e:passkey-kit\` (\`packages/c-sign/e2e/passkey-kit.ts\`) on ${new Date().toISOString().slice(0, 10)}. RPC: \`${rpcUrl}\`. Every wallet and key is fresh. Passkey signatures come from the real kit (0.14.0, 0.20.0) and a software P-256 authenticator, not from a browser or a hardware key.`,
    "",
    `Wasm: \`${WASM_014.slice(0, 8)}…\` (0.14 line, the hash Eunomia deploys), \`${WASM_020.slice(0, 8)}…\` (canonical for 0.20).`,
    "",
    "| ID | Experiment | Expected | Observed | Pass |",
    "| --- | --- | --- | --- | --- |",
    ...rows.map((r) => `| ${r.id} | ${r.what} | ${r.expected} | ${r.observed.replaceAll("|", "\\|")} | ${r.pass ? "yes" : "NO"} |`),
    "",
    "Wallets:",
    "",
    ...Object.entries(wallets).map(([name, id]) => `- ${name}: [\`${id.slice(0, 8)}…\`](https://stellar.expert/explorer/testnet/contract/${id})`),
    "",
    "- **K4, K9:** a recovery key limited to the wallet contract cannot sign a message. It stays a recovery key.",
    "- **K5, K10:** adding the verifier to a key's limits makes that key valid for every domain. Do not do this for a recovery key.",
    "",
  ];
  writeFileSync(new URL("../../../docs/EXPERIMENTS-PASSKEY-KIT.md", import.meta.url), lines.join("\n"));
}

async function main() {
  const sponsor = await fundedKeypair();
  const config = { rpcUrl, networkPassphrase };

  // passkey-kit 0.14 on the Wasm Eunomia deploys.
  const auth014 = new SoftwareAuthenticator();
  const wallet014 = await deployWallet(sponsor, WASM_014, [secp256r1Signer014(auth014)]);
  console.log(`0.14 wallet ${wallet014}`);
  const kit014 = new Kit014({ ...config, walletWasmHash: WASM_014, rpId: RP_ID, WebAuthn: auth014 } as never);
  kit014.wallet = new Client014({ contractId: wallet014, rpcUrl, networkPassphrase });
  record(
    "K1",
    "0.14: passkey signs through the kit",
    "valid",
    await verify(await signMessageWithPasskeyKit(kit014 as never, await entryFor(wallet014, "K1"), new PasskeySigner014(b64url(auth014.id)) as never)),
  );

  const stranger = Keypair.random();
  record(
    "K2",
    "0.14: a key that is not a signer",
    "invalid",
    await verify(signPasskeyKitMessageWithEd25519(await entryFor(wallet014, "K2"), [stranger], networkPassphrase)),
  );

  // Eunomia's recovery setup: an Ed25519 signer limited to the wallet contract.
  const owner = Keypair.random();
  const recovery = Keypair.random();
  const agent = Keypair.random();
  const walletEd = await deployWallet(sponsor, WASM_014, [ed25519Signer(owner, UNLIMITED)]);
  console.log(`0.14 Ed25519 wallet ${walletEd}`);
  await addSigner(sponsor, walletEd, ed25519Signer(recovery, onlyContract(walletEd)), owner);
  await addSigner(sponsor, walletEd, ed25519Signer(agent, onlyContract(VERIFIER)), owner);
  record("K3", "0.14: unlimited Ed25519 owner, without the kit", "valid", await verify(signPasskeyKitMessageWithEd25519(await entryFor(walletEd, "K3"), [owner], networkPassphrase)));
  record("K4", "0.14: recovery key limited to the wallet contract", "invalid", await verify(signPasskeyKitMessageWithEd25519(await entryFor(walletEd, "K4"), [recovery], networkPassphrase)));
  record("K5", "0.14: key whose limits name the verifier", "valid", await verify(signPasskeyKitMessageWithEd25519(await entryFor(walletEd, "K5"), [agent], networkPassphrase)));
  const kitEd = new Kit014({ ...config, walletWasmHash: WASM_014, rpId: RP_ID } as never);
  kitEd.wallet = new Client014({ contractId: walletEd, rpcUrl, networkPassphrase });
  record("K6", "0.14: Ed25519 owner through the kit", "valid", await verify(await signMessageWithPasskeyKit(kitEd as never, await entryFor(walletEd, "K6"), new Ed25519Signer014(owner) as never)));

  // passkey-kit 0.20: the kit's own createWallet (binding proof included) on the current Wasm.
  const auth020 = new SoftwareAuthenticator();
  const kit020 = new Kit020({
    ...config,
    walletWasmHash: WASM_020,
    rpId: RP_ID,
    allowedOrigins: [ORIGIN],
    deploySource: sponsor.secret(),
    WebAuthn: auth020,
  } as never);
  const created = await kit020.createWallet("c-sign", "e2e");
  // The kit's fee can fall below what the network requires at the moment; the sponsor tops it up.
  const bump = TransactionBuilder.buildFeeBumpTransaction(sponsor, "10000000", TransactionBuilder.fromXDR(created.signedTx, networkPassphrase) as Transaction, networkPassphrase);
  bump.sign(sponsor);
  const deployed = await submit(bump as unknown as Transaction);
  if (deployed.status !== "SUCCESS") throw new Error(`0.20 deploy failed: ${JSON.stringify(deployed)}`);
  console.log(`0.20 wallet ${created.contractId}`);
  kit020.wallet = new Client020({ contractId: created.contractId, rpcUrl, networkPassphrase });
  record(
    "K7",
    "0.20: passkey signs through the kit",
    "valid",
    await verify(await signMessageWithPasskeyKit(kit020 as never, await entryFor(created.contractId, "K7"), new PasskeySigner020(b64url(auth020.id)) as never)),
  );
  const other = new SoftwareAuthenticator();
  const otherKit = new Kit020({ ...config, walletWasmHash: WASM_020, rpId: RP_ID, allowedOrigins: [ORIGIN], WebAuthn: other } as never);
  otherKit.wallet = new Client020({ contractId: created.contractId, rpcUrl, networkPassphrase });
  record(
    "K8",
    "0.20: another passkey, not on the wallet",
    "invalid",
    await verify(await signMessageWithPasskeyKit(otherKit as never, await entryFor(created.contractId, "K8"), new PasskeySigner020(b64url(other.id)) as never)),
  );

  // The same limits on the current Wasm, installed with the kit's own admin path and the passkey.
  const addWithKit = async (key: Keypair, limits: Map<string, undefined>) => {
    const signed = await kit020.signAdmin(await kit020.addEd25519(key.publicKey(), limits as never, SignerStore.Persistent), new PasskeySigner020(b64url(auth020.id)) as never);
    const auth = (signed.built?.operations[0] as { auth?: xdr.SorobanAuthorizationEntry[] }).auth;
    const call = signed.built?.operations[0] as unknown as { func: xdr.HostFunction };
    const res = await submitOp(sponsor, Operation.invokeHostFunction({ func: call.func, auth }));
    if (res.status !== "SUCCESS") throw new Error(`add_signer failed: ${res.status} ${res.hash}`);
  };
  const recovery020 = Keypair.random();
  const verifierKey020 = Keypair.random();
  await addWithKit(recovery020, new Map([[created.contractId, undefined]]));
  await addWithKit(verifierKey020, new Map([[VERIFIER, undefined]]));
  record("K9", "0.20: recovery key limited to the wallet contract", "invalid", await verify(signPasskeyKitMessageWithEd25519(await entryFor(created.contractId, "K9"), [recovery020], networkPassphrase)));
  record("K10", "0.20: key whose limits name the verifier", "valid", await verify(signPasskeyKitMessageWithEd25519(await entryFor(created.contractId, "K10"), [verifierKey020], networkPassphrase)));

  writeReport({ "0.14 passkey wallet": wallet014, "0.14 Ed25519 wallet": walletEd, "0.20 passkey wallet": created.contractId });
  const failed = rows.filter((r) => !r.pass);
  console.log(`\n${rows.length - failed.length}/${rows.length} passed. RPC: ${rpcUrl}`);
  process.exitCode = failed.length ? 1 : 0;
}

await main();
