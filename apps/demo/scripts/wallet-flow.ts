// Runs the demo wallet (src/lib/wallet.ts) end to end against a running dev
// server and testnet, with a software P-256 authenticator standing in for the
// passkey. Covers exactly what the page does: create, sign in, add a recovery
// key, remove the passkey, re-check, sign in with the recovery key.
//
//   pnpm dev   # in another terminal
//   BASE_URL=http://localhost:5173 pnpm --filter c-sign-demo flow
import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { MemoryStorage } from "smart-account-kit/storage";
import type { SignedMessage, VerifyResult } from "c-sign";

const BASE = process.env.BASE_URL ?? "http://localhost:5173";
const origin = new URL(BASE);

// Browser globals the wallet module reads.
Object.assign(globalThis, { location: origin });
const store = new Map<string, string>();
Object.assign(globalThis, {
  localStorage: {
    getItem: (k: string) => store.get(k) ?? null,
    setItem: (k: string, v: string) => void store.set(k, v),
    removeItem: (k: string) => void store.delete(k),
  },
});

const b64url = (b: Buffer | string) => Buffer.from(b).toString("base64url");
const sha256 = (b: Buffer | string) => createHash("sha256").update(b).digest();

/** A minimal WebAuthn authenticator: one P-256 key, user presence and verification always set. */
function softAuthenticator() {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" });
  const raw = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x!, "base64url"), Buffer.from(jwk.y!, "base64url")]);
  const credentialId = b64url(randomBytes(16));
  let counter = 0;
  const clientData = (type: string, challenge: string) =>
    Buffer.from(JSON.stringify({ type, challenge, origin: origin.origin, crossOrigin: false }));
  return {
    startRegistration: async ({ optionsJSON }: { optionsJSON: { challenge: string } }) =>
      ({
        id: credentialId,
        rawId: credentialId,
        type: "public-key",
        response: {
          clientDataJSON: b64url(clientData("webauthn.create", optionsJSON.challenge)),
          attestationObject: "",
          publicKey: b64url(raw),
          publicKeyAlgorithm: -7,
          transports: ["internal"],
        },
        clientExtensionResults: {},
        authenticatorAttachment: "platform",
      }) as never,
    startAuthentication: async ({ optionsJSON }: { optionsJSON: { challenge: string; rpId?: string } }) => {
      counter += 1;
      const flags = Buffer.from([0x05]); // UP | UV
      const count = Buffer.alloc(4);
      count.writeUInt32BE(counter);
      const authData = Buffer.concat([sha256(optionsJSON.rpId ?? origin.hostname), flags, count]);
      const cd = clientData("webauthn.get", optionsJSON.challenge);
      const signature = sign("sha256", Buffer.concat([authData, sha256(cd)]), privateKey);
      return {
        id: credentialId,
        rawId: credentialId,
        type: "public-key",
        response: { authenticatorData: b64url(authData), clientDataJSON: b64url(cd), signature: b64url(signature) },
        clientExtensionResults: {},
        authenticatorAttachment: "platform",
      } as never;
    },
  };
}

let failures = 0;
const check = (name: string, ok: boolean, detail = "") => {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? `: ${detail}` : ""}`);
  if (!ok) failures++;
};

async function api<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, body ? { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) } : undefined);
  return (await res.json()) as T;
}

async function main() {
  const wallet = await import("../src/lib/wallet.ts");
  const { VERIFIER_ID } = await import("../src/lib/config.ts");
  wallet.createKit({ webAuthn: softAuthenticator(), storage: new MemoryStorage(), rpId: origin.hostname });

  let state = await wallet.createAccount("flow-test");
  check("create passkey account through the relay", state.account.startsWith("C"), state.account);

  const signIn = async () => {
    const c = await api<{ statement: string; nonce: string; issuedAt: number; token: string }>("/api/challenge");
    const message: SignedMessage = { version: "1", domain: origin.host, statement: c.statement, nonce: c.nonce, issuedAt: c.issuedAt };
    const signature = await wallet.signMessage(state, message, VERIFIER_ID);
    return { signature, result: await api<VerifyResult>("/api/verify", { signature, mode: "signin", token: c.token }) };
  };
  const recheck = (signature: string) => api<VerifyResult>("/api/verify", { signature, mode: "recheck" });

  const first = await signIn();
  check("sign in with the passkey", first.result.status === "valid", first.result.reason);
  check("wallet sees the verifier as pinned", await wallet.verifierIsPinned(VERIFIER_ID));

  const added = await wallet.addRecoveryKey(state);
  state = added.state;
  check("add recovery key (passkey signs)", !!added.hash, added.hash);
  const afterAdd = await recheck(first.signature);
  check("first signature after adding a signer", afterAdd.status === "invalid", `${afterAdd.status}: ${afterAdd.reason}`);

  const both = await signIn();
  check("sign in with passkey + recovery key", both.result.status === "valid", both.result.reason);

  const removed = await wallet.removePasskey(state);
  state = removed.state;
  check("remove passkey (both keys sign)", !!removed.hash, removed.hash);

  const afterRemove = await recheck(first.signature);
  check("first signature after rotation", afterRemove.status === "invalid", afterRemove.reason);

  const recovered = await signIn();
  check("sign in with the recovery key", recovered.result.status === "valid", recovered.result.reason);

  console.log(failures ? `\n${failures} check(s) failed` : "\nWallet flow passed");
  process.exit(failures ? 1 : 0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
