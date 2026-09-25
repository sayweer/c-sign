# C-Sign: signed messages for Stellar contract accounts

**Working name:** SEP-53C, a "SEP-53 profile for contract accounts"
**Status:** early development. The verifier contract compiles to wasm and passes its 5 unit tests. Nothing is deployed yet.

Read the [project overview](C-Sign-Overview.pdf) first, then [docs/SPEC.md](docs/SPEC.md).

C-Sign lets a Stellar contract account (a `C…` address: passkey wallets, multisig accounts, agent wallets with spending policies) sign an arbitrary, human-readable message, and lets anyone verify that signature against the account's **current** on-chain rules, without submitting a transaction and without paying a fee.

It is Stellar's counterpart to ERC-1271, with one difference: wallets do not implement anything per account, because every Stellar contract account already enforces its rules in `__check_auth`.

## Why

- [SEP-53](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0053.md) (message signing) covers only classic `G…` keypairs.
- [SEP-43](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0043.md) (wallet interface) leaves `signMessage` undefined for contract accounts. In [stellar-protocol#1928](https://github.com/stellar/stellar-protocol/issues/1928) SDF asked for either an explicit "undefined" or a concrete approach. C-Sign is that approach.
- In practice, wallets today either throw on `signMessage` for C addresses or return incompatible ad-hoc WebAuthn envelopes that verify a key, not the account. A key that was removed from the account still produces a "valid" signature.

## How it works

1. **Readable message.** The dapp builds `SignedMessage { domain, statement, challenge, issued_at }`. The wallet shows it as text. Nothing is signed blind.
2. **Signing.** The wallet signs a `SorobanAuthorizationEntry` whose root invocation is `verify_message(account, msg)` on the canonical verifier contract, with no sub-invocations and with V2 address credentials ([CAP-71](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0071.md)). Network id, nonce and expiration are already part of the signed preimage.
3. **No side effects.** `verify_message` calls `account.require_auth()` and then always fails with the reserved error `AUTH_OK`. Submitting a published signature on-chain fails the transaction and does not consume the nonce.
4. **Verification.** The relying party runs `simulateTransaction` with `authMode: "enforce"` and accepts only `AUTH_OK`. The account's own `__check_auth` decides, using its current signers, thresholds and policies. Off-chain replay protection comes from the relying party's one-time `challenge`, as in SIWE.

An **anchored mode** (`anchor_message`) runs the same authorization and then emits the event `("anchored", account) -> sha256(xdr(msg))`, for cases that need a durable on-chain proof.

This is the same pattern [SEP-45](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0045.md) already uses to authenticate contract accounts for web sessions (authorization entry + enforcing simulation), generalized to arbitrary messages and without a server-side signature.

## Repository layout

```
contracts/verifier/          sep53c-verifier Soroban contract (Rust, soroban-sdk 28)
docs/SPEC.md                 draft specification (English)
docs/ROADMAP.md              30-day plan, deliverables, success criteria
docs/OVERVIEW.md             project overview (start here)
```

Planned, not started: a TypeScript `signMessage` / `verifyMessage` library with adapters for OpenZeppelin smart accounts (via smart-account-kit), passkey-kit and OZ multisig; a two-origin demo; a public conformance suite. See [docs/ROADMAP.md](docs/ROADMAP.md).

## Build and test

```sh
cargo test                # unit tests, native
stellar contract build    # wasm: target/wasm32v1-none/release/sep53c_verifier.wasm
```

Requires Rust with the `wasm32v1-none` target and stellar-cli 23 or newer (tested with 27.0.0). Enforcing simulation needs stellar-rpc 23 or newer and `SimulationAuthMode` in js-stellar-sdk.

## Known limitations

- Validity is checked against the account's current rules, as with ERC-1271. A signature can stop verifying after signers change. Use anchored mode when non-repudiation matters.
- Signature lifetime is bounded by `max_entry_ttl` (about 180 days on testnet).
- Off-chain verification trusts the RPC used for simulation, like ERC-1271 with `eth_call`. Run your own RPC or cross-check two providers.
- Accounts that are not yet deployed cannot be verified. There is no EIP-6492 equivalent.
- Accounts whose context rules only allow specific contracts need a rule for the verifier before they can sign messages.

## Links

- Design comment on [stellar-protocol#1928](https://github.com/stellar/stellar-protocol/issues/1928#issuecomment-5823338114) (2026-09-24). SDF asked to continue in a dedicated issue.
- Draft specification: [docs/SPEC.md](docs/SPEC.md)

## License

Apache-2.0
