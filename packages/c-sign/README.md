# c-sign

Sign and verify messages with Stellar contract accounts: the TypeScript library for the [draft SEP](https://github.com/sayweer/c-sign/blob/main/docs/SPEC.md).

A contract account has no single key, so there is nothing to check a signature against. C-Sign asks the account itself: a signature is an authorization entry for a verifier call that never lands on-chain, and an enforcing simulation runs the account's own `__check_auth`. Passkeys, multisig, policies and key rotation all work with no change to the account.

The specification is a draft and the library has not been audited. Reference verifier instances are deployed on testnet only.

```sh
npm install c-sign
```

It works in Node.js 22.12+, browsers and edge runtimes, with no Buffer polyfill. It uses stellar-sdk 17 internally and takes authorization entries as base64 XDR or as entry objects from any stellar-sdk version, so an application still on stellar-sdk 16 (as the wallet kits are today) can use it as it is.

## Sign someone in

```ts
import { MemoryNonceStore, createSignInMessage, verifySignIn, TESTNET } from "c-sign";

const nonces = new MemoryNonceStore();   // one server process; see below for several
const DOMAIN = "example.com";            // from your configuration, not from the request

// GET /challenge: the message the wallet signs
const message = createSignInMessage({ domain: DOMAIN, statement: "Sign in to Example", ...nonces.issue() });

// POST /verify: the signature the wallet returns
const result = await verifySignIn({
  signature,                       // base64 SorobanAuthorizationEntry from the wallet
  rpcUrl: TESTNET.rpcUrl,
  networkPassphrase: TESTNET.networkPassphrase,
  domain: DOMAIN,
  nonces,                          // consumed atomically, only on a valid result
});

if (result.status === "valid") startSession(result.account);
```

`status` is `valid`, `invalid` or `inconclusive`, and `steps` lists every check with its outcome. Grant access only on `valid`; `inconclusive` means the check could not be completed (for example an RPC failure) and may be retried. These functions do not throw.

`valid` means the account's current rules accept this message. It does not say which signer or rule did, so a session key allowed to act as the account can also sign in as it.

`MemoryNonceStore` keeps nonces in one process and forgets them on restart. With several instances or serverless functions, implement `NonceStore` on a shared store; with Redis, for example:

```ts
const LIFETIME = 300; // seconds, the default challengeLifetimeSeconds

async function issue() {
  const nonce = createNonce();
  const issuedAt = Math.floor(Date.now() / 1000);
  await redis.set(`csign:${nonce}`, issuedAt, { EX: LIFETIME });
  return { nonce, issuedAt };
}

const nonces = {
  issuedAt: async (nonce: string) => {
    const v = await redis.get(`csign:${nonce}`);
    return v === null ? undefined : Number(v);
  },
  consume: async (nonce: string) => (await redis.getDel(`csign:${nonce}`)) !== null, // atomic
};
```

## G accounts

A `G…` account signs in with [SEP-53](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0053.md) through the same `verifySignIn`, so one endpoint serves both kinds of address. The wallet signs `signInText(message, address, networkPassphrase)`, a CAIP-122 text with the network's chain id (Freighter: `signMessage`), and the application posts the signature, the address and the message:

```ts
import { signInText, verifySignIn } from "c-sign";

// In the browser
const text = signInText(message, address, TESTNET.networkPassphrase);
const { signedMessage } = await freighter.signMessage(text, { address });

// On the server: the same call as for a C... account, with address and message
const result = await verifySignIn({ signature: signedMessage, address, message, rpcUrl, networkPassphrase, domain: DOMAIN, nonces });
```

The server checks the message fields with the same rules as for a contract account, rebuilds the text from them (it never parses text) and checks the signature against the account's key, with no RPC call. SEP-53 checks one key: it does not see signer weights, thresholds or a removed master key. `signSignInWithKeypair` signs with a `Keypair`, for tests and scripts.

## Check a message without signing anyone in

```ts
import { verifyMessage } from "c-sign";

const result = await verifyMessage({ signature, rpcUrl, networkPassphrase, domain: "example.com" });
```

For auditors and services other than the one that issued the nonce. It shows that the account's rules accept the message, not when it was signed or whether it was used before. `domain: null` skips the domain check, for inspection tools only.

## In the application

The application turns the message from its server into an unsigned entry and hands it to the wallet:

```ts
import { createMessageEntry, encodeEntry, TESTNET } from "c-sign";

const { entry, expirationLedger } = await createMessageEntry({
  verifierId: TESTNET.verifierInstances[0],   // any instance running the reference Wasm
  account,                                     // the user's C... address
  message,                                     // from GET /challenge
  rpcUrl: TESTNET.rpcUrl,
});
// Sign `entry` with the wallet (below), then POST encodeEntry(signedEntry) to /verify.
```

The signature stays valid for 720 ledgers (about an hour) unless you pass `validForLedgers`.

## In a wallet

```ts
import { checkMessageRequest } from "c-sign";

const { account, verifierId, message, expirationLedger } = await checkMessageRequest({
  entry: entryFromApp,             // base64 XDR, or an entry object from any stellar-sdk version
  origin,                          // as the platform reports it, never as the application states it
  rpcUrl: myRpcUrl,                // an RPC you choose, not one the application supplies
  networkPassphrase,
});
// Show `message` as decoded here, then invoke the signer.
```

It throws a `CSignError` when the wallet must refuse, including when it cannot confirm the verifier. `signOzMessageWithEd25519` signs for an OpenZeppelin account with Ed25519 signers; its `scheme` argument is the account's digest format, `"preimage-v1"` for stellar-accounts 0.8.0 and later or `"legacy-concat"` for 0.7.x. `signOzEntryWithEd25519` signs other authorization entries and refuses message entries.

For a passkey-kit wallet (tested with 0.14.0 and 0.20.0), `signMessageWithPasskeyKit` signs through a connected kit instance, and `signPasskeyKitMessageWithEd25519(entry, keys, networkPassphrase)` signs without one. Both refuse anything but a message entry. A key whose limits exclude the verifier gets `invalid`; leave recovery keys that way, because adding the verifier to a key's limits makes it valid for every domain.

passkey-kit uses stellar-sdk 16, so give it entries of that SDK with `decode`:

```ts
import { xdr } from "@stellar/stellar-sdk"; // the 16.x your kit uses
import { signMessageWithPasskeyKit, encodeEntry } from "c-sign";

const signed = await signMessageWithPasskeyKit(kit, entry, {
  signer,                                                        // optional; the connected passkey by default
  decode: (b64) => xdr.SorobanAuthorizationEntry.fromXDR(b64, "base64"),
});
const signature = encodeEntry(signed);
```

Signing functions take a `Keypair` from any stellar-sdk version. Byte results (`entrySignaturePayload`, `ozAuthDigest`) are `Uint8Array`.

## More

- [Specification](https://github.com/sayweer/c-sign/blob/main/docs/SPEC.md) and [threat model](https://github.com/sayweer/c-sign/blob/main/docs/THREAT-MODEL.md)
- [Testnet experiments](https://github.com/sayweer/c-sign/blob/main/docs/EXPERIMENTS.md) and [test vectors](https://github.com/sayweer/c-sign/blob/main/vectors/c-sign-v1.json)
- [Live demo](https://c-sign-demo.vercel.app)
