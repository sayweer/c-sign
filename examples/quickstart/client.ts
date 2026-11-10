// A wallet in the terminal: creates a testnet smart account with one Ed25519 signer,
// then signs in to the server from server.ts. In a real app the wallet is a passkey
// or browser extension; only the signing call changes.
import { Address, Keypair, Operation, TransactionBuilder, rpc, xdr } from "@stellar/stellar-sdk";
import {
  TESTNET,
  createMessageEntry,
  encodeEntry,
  ozEd25519Signer,
  signOzMessageWithEd25519,
  type OzEd25519Key,
  type SignedMessage,
} from "c-sign";

const SERVER = process.env.SERVER ?? "http://localhost:8787";
// OpenZeppelin smart account and Ed25519 verifier deployed on testnet by smart-account-kit.
// This account version signs the "legacy-concat" digest; stellar-accounts 0.8.0 and later sign "preimage-v1".
const OZ_ACCOUNT_WASM = "1b5f4534a76322da2ad7c745f6900857a6802b0ca79850c35a03561df997785a";
const OZ_ED25519_VERIFIER = "CAAVTMCBXEIBPR64EAASKFXERVPYFZA2JYP5A3BG6PESWEFUJX5IHKN4";

const server = new rpc.Server(TESTNET.rpcUrl);

/** Funds a fresh G... key with friendbot and deploys a smart account whose only signer is `key`. */
async function createSmartAccount(key: OzEd25519Key): Promise<string> {
  const sponsor = Keypair.random();
  const funded = await fetch(`https://friendbot.stellar.org?addr=${sponsor.publicKey()}`);
  if (!funded.ok) throw new Error(`Friendbot failed (${funded.status}); try again in a minute`);

  const op = Operation.createCustomContract({
    address: Address.fromString(sponsor.publicKey()),
    wasmHash: Buffer.from(OZ_ACCOUNT_WASM, "hex"),
    salt: Buffer.from(Keypair.random().rawPublicKey()),
    constructorArgs: [xdr.ScVal.scvVec([ozEd25519Signer(key)]), xdr.ScVal.scvMap([])],
  });
  const source = await server.getAccount(sponsor.publicKey());
  const tx = await server.prepareTransaction(
    new TransactionBuilder(source, { fee: "1000000", networkPassphrase: TESTNET.networkPassphrase }).addOperation(op).setTimeout(60).build(),
  );
  tx.sign(sponsor);
  const sent = await server.sendTransaction(tx);
  const done = await server.pollTransaction(sent.hash, { attempts: 30 });
  if (done.status !== rpc.Api.GetTransactionStatus.SUCCESS || !done.returnValue) {
    throw new Error(`Account deploy failed: ${done.status} ${sent.hash}`);
  }
  return Address.fromScVal(done.returnValue).toString();
}

async function signIn(account: string, key: OzEd25519Key): Promise<string> {
  // 1. The server's challenge.
  const message = (await (await fetch(`${SERVER}/challenge`)).json()) as SignedMessage;
  // 2. The unsigned entry for verify_message(account, message) on a reference verifier instance.
  const { entry } = await createMessageEntry({ verifierId: TESTNET.verifierInstances[0], account, message, rpcUrl: TESTNET.rpcUrl });
  // 3. The wallet signs it. A real wallet first runs checkMessageRequest and shows `message` to the user.
  const signed = signOzMessageWithEd25519(entry, [key], TESTNET.networkPassphrase, "legacy-concat");
  return encodeEntry(signed);
}

const post = async (signature: string) =>
  (await fetch(`${SERVER}/verify`, { method: "POST", body: JSON.stringify({ signature }) })).json();

const key: OzEd25519Key = { keypair: Keypair.random(), verifierId: OZ_ED25519_VERIFIER };
console.log("Creating a testnet smart account...");
const account = await createSmartAccount(key);
console.log(`Account: ${account}`);

const signature = await signIn(account, key);
console.log("Sign in:     ", await post(signature));
console.log("Replay it:   ", await post(signature));
