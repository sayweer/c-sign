# Changelog

## 0.3.0

First release on npm. Follows [SPEC v0.0.2](https://github.com/sayweer/c-sign/blob/main/docs/SPEC.md).

### Added

- `G…` accounts in `verifySignIn` and `verifyMessage`: a SEP-53 signature over `signInText`, a CAIP-122 text bound to the network's chain id, checked with the same message rules and no RPC call. `signSignInWithKeypair` and `chainId` helpers.
- `MemoryNonceStore`, `createSignInMessage` and `createNonce`: a relying party's challenge and nonce store in a few lines.
- `createMessageEntry`: the unsigned entry with its expiration set from the RPC's latest ledger (720 ledgers by default).
- Entries are accepted as base64 XDR or as objects from any stellar-sdk version (`EntryInput`, `toEntry`), and signers take a `Keypair` from any version (`Ed25519Keypair`).
- `signMessageWithPasskeyKit` takes a `decode` option to hand a kit on another stellar-sdk major an entry of its own SDK.
- `withSignature` and `instanceWasmHash` helpers.
- Runs in browsers and edge runtimes without a Buffer polyfill.

### Changed

- **Breaking:** stellar-sdk 17 is a dependency instead of a `^16` peer dependency, so installing next to either major works. Node.js 22.12 or later.
- **Breaking:** byte results (`entrySignaturePayload`, `ozAuthDigest`) are `Uint8Array`; `randomEntryNonce` and `BuildEntryParams.nonce` are `bigint`; returned XDR objects follow the stellar-sdk 17 API.
- **Breaking:** `signMessageWithPasskeyKit(kit, entry, { signer, decode })` replaces `signMessageWithPasskeyKit(kit, entry, signer)`.
- A signature that is not strict base64 is `invalid` at the decode step instead of being decoded leniently.

### Fixed

- Verification works against protocol 30 networks; stellar-sdk 16.3 could not read their ledger headers, so every check was `inconclusive`.

## 0.2.0

Not published. SPEC v0.0.2: `verifySignIn` (domain and `NonceStore` required, nonce consumed atomically) split from `verifyMessage`; the wallet-side checks (`checkMessageRequest`, `parseMessageEntry`, `domainFromOrigin`); OpenZeppelin stellar-accounts 0.8.0 signing; passkey-kit 0.14 and 0.20 signing.
