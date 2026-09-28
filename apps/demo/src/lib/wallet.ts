// The demo wallet. In production this lives in a wallet app or extension; here
// it runs in the page so the whole flow fits on one screen. It writes `domain`
// itself, from the page origin, as SPEC §5 requires of wallets.
import { Keypair, rpc, xdr } from "@stellar/stellar-sdk";
import { SmartAccountKit } from "smart-account-kit";
import { IndexedDBStorage } from "smart-account-kit/storage";
import {
  REFERENCE_WASM_HASH,
  buildMessageEntry,
  encodeEntry,
  signOzEntryWithEd25519,
  type SignedMessage,
} from "c-sign";
import { ED25519_VERIFIER, NETWORK_PASSPHRASE, OZ_ACCOUNT_WASM, RPC_URL, WEBAUTHN_VERIFIER } from "./config";

export interface WalletState {
  account: string;
  credentialId: string;
  /** Recovery key secret. Kept in this browser only; this is a testnet demo. */
  recoverySecret?: string;
  passkeyRemoved?: boolean;
}

const STORE = "c-sign-demo.wallet";
export const server = new rpc.Server(RPC_URL);

type KitConfig = ConstructorParameters<typeof SmartAccountKit>[0];

let kit: SmartAccountKit | null = null;
function getKit(): SmartAccountKit {
  kit ??= createKit();
  return kit;
}

/** Tests swap in a software authenticator and in-memory storage here. */
export function createKit(overrides: Partial<KitConfig> = {}): SmartAccountKit {
  kit = new SmartAccountKit({
    rpcUrl: RPC_URL,
    networkPassphrase: NETWORK_PASSPHRASE,
    accountWasmHash: OZ_ACCOUNT_WASM,
    webauthnVerifierAddress: WEBAUTHN_VERIFIER,
    ed25519VerifierAddress: ED25519_VERIFIER,
    relayerUrl: `${location.origin}/api/relay`,
    storage: overrides.storage ?? new IndexedDBStorage("c-sign-demo"),
    rpName: "C-Sign demo",
    ...overrides,
  });
  return kit;
}

export function loadWallet(): WalletState | null {
  try {
    const raw = localStorage.getItem(STORE);
    return raw ? (JSON.parse(raw) as WalletState) : null;
  } catch {
    return null;
  }
}

function saveWallet(state: WalletState | null) {
  if (state) localStorage.setItem(STORE, JSON.stringify(state));
  else localStorage.removeItem(STORE);
}

export function forgetWallet() {
  saveWallet(null);
  void getKit().disconnect();
}

export async function createAccount(name: string): Promise<WalletState> {
  const result = await getKit().createWallet("C-Sign demo", name || "demo", { autoSubmit: true });
  if (!result.submitResult?.success) {
    throw result.submitResult?.error ?? new Error("The account could not be deployed");
  }
  const state = { account: result.contractId, credentialId: result.credentialId };
  saveWallet(state);
  return state;
}

async function ensureConnected(state: WalletState) {
  const k = getKit();
  if (k.isConnected && k.contractId === state.account) return;
  await k.connectWallet({ contractId: state.account, credentialId: state.credentialId });
}

function recoveryKey(state: WalletState) {
  if (!state.recoverySecret) return null;
  const keypair = Keypair.fromSecret(state.recoverySecret);
  getKit().externalSigners.addEd25519FromSecret(state.recoverySecret);
  return keypair;
}

/** Wallet-side check before signing: is the verifier instance running the pinned Wasm? */
export async function verifierIsPinned(verifierId: string): Promise<boolean> {
  try {
    const instance = await server.getContractData(verifierId, xdr.ScVal.scvLedgerKeyContractInstance(), rpc.Durability.Persistent);
    const exe = instance.val.contractData().val().instance().executable();
    return exe.switch().name === "contractExecutableWasm" && Buffer.from(exe.wasmHash()).toString("hex") === REFERENCE_WASM_HASH;
  } catch {
    return false;
  }
}

/** Which keys currently have to sign under the account's Default rule. */
export function activeSigners(state: WalletState): ("passkey" | "recovery")[] {
  const out: ("passkey" | "recovery")[] = [];
  if (!state.passkeyRemoved) out.push("passkey");
  if (state.recoverySecret) out.push("recovery");
  return out;
}

/**
 * Signs `verify_message(account, msg)` with every signer the account's rule
 * requires. Returns the base64 entry: that is the C-Sign signature.
 */
export async function signMessage(state: WalletState, message: SignedMessage, verifierId: string): Promise<string> {
  const latest = (await server.getLatestLedger()).sequence;
  const expiration = latest + 720; // about an hour
  let entry = buildMessageEntry({ verifierId, account: state.account, message, expirationLedger: expiration });
  const recovery = recoveryKey(state);
  if (recovery) entry = signOzEntryWithEd25519(entry, [{ keypair: recovery, verifierId: ED25519_VERIFIER }], NETWORK_PASSPHRASE);
  if (!state.passkeyRemoved) {
    await ensureConnected(state);
    entry = await getKit().signAuthEntry(entry, { contextRuleIds: [0], expiration });
  }
  return encodeEntry(entry);
}

/** Adds an Ed25519 recovery key to the Default rule, authorized by the passkey. */
export async function addRecoveryKey(state: WalletState): Promise<{ state: WalletState; hash?: string }> {
  await ensureConnected(state);
  const keypair = Keypair.random();
  const k = getKit();
  k.externalSigners.addEd25519FromSecret(keypair.secret());
  const tx = await k.signers.addBatch(0, [{ tag: "External", values: [ED25519_VERIFIER, Buffer.from(keypair.rawPublicKey())] }]);
  const result = await k.signAndSubmitAdmin(tx);
  if (!result.success) throw result.error ?? new Error("Adding the recovery key failed");
  const next = { ...state, recoverySecret: keypair.secret() };
  saveWallet(next);
  return { state: next, hash: result.hash };
}

/** Removes the passkey signer. The rule needs every signer, so passkey and recovery key both sign. */
export async function removePasskey(state: WalletState): Promise<{ state: WalletState; hash?: string }> {
  await ensureConnected(state);
  const recovery = recoveryKey(state);
  if (!recovery) throw new Error("Add a recovery key first");
  const k = getKit();
  const passkey = (await k.multiSigners.getAvailableSigners()).find(
    (s) => s.tag === "External" && s.values[0] === WEBAUTHN_VERIFIER,
  );
  if (!passkey) throw new Error("Passkey signer not found on the account");
  const tx = await k.signers.remove(0, passkey);
  const result = await k.multiSigners.adminOperation(tx, [
    { type: "passkey", credentialId: state.credentialId },
    {
      type: "ed25519",
      ed25519PublicKey: Buffer.from(recovery.rawPublicKey()).toString("hex"),
      signer: { tag: "External", values: [ED25519_VERIFIER, Buffer.from(recovery.rawPublicKey())] },
    },
  ]);
  if (!result.success) throw result.error ?? new Error("Removing the passkey failed");
  const next = { ...state, passkeyRemoved: true };
  saveWallet(next);
  return { state: next, hash: result.hash };
}
