# C-Sign: signed messages for Stellar contract accounts

**Status:** draft specification and reference verifier. The verifier builds reproducibly and passes its unit tests. Not deployed yet.

Read the [project overview](C-Sign-Overview.pdf) first, then the [draft specification](docs/SPEC.md).

C-Sign lets a Stellar contract account (a `C…` address: passkey wallets, multisig accounts, agent wallets with spending policies) sign a human-readable message, and lets anyone verify that signature against the account's **current** on-chain rules, without submitting a transaction and without paying a fee. It is the counterpart of [SEP-53](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0053.md) for contract accounts, discussed in [stellar-protocol#2027](https://github.com/stellar/stellar-protocol/issues/2027).

## How it works

1. **The relying party asks for a message.** It gives a statement and a one-time nonce. The **wallet** fills in the relying party's domain from the requesting origin, so a site cannot obtain a signature addressed to another site.
2. **The wallet signs an authorization entry.** The account authorizes exactly one call, `verify_message(account, msg)`, on an instance of the reference verifier contract. No sub-calls, V2 address credentials. The wallet shows the domain and statement decoded from that entry.
3. **The verifier never succeeds.** It calls `account.require_auth()` and then always fails with the reserved error `AuthOk`. A signature submitted on-chain has no effect and the host rolls its nonce back, so it stays verifiable.
4. **The relying party verifies by simulation.** It rebuilds the expected call, checks that the verifier instance runs the reference Wasm (by hash), and runs `simulateTransaction` in enforcing mode. The account's own `__check_auth` decides against its current signers, thresholds and policies. The result is `valid`, `invalid` or `inconclusive`.

There is **no canonical verifier address**. Anyone can deploy the reference Wasm; wallets and relying parties trust an instance only if its executable hash matches the published one.

## Reference verifier

```
contracts/verifier/WASM_HASH = 2a5004a7736327a994d449af03ae7c5eea481da2d2d3191222dc7b4934a4c299
```

One function, no admin, no storage, no upgrade path. The message is a symbol-keyed map that the contract never reads, so new optional message fields never change the Wasm or its hash.

## Repository layout

```
contracts/verifier/     reference verifier (Rust, soroban-sdk 28) and its pinned Wasm hash
docs/SPEC.md            draft SEP: "Signed Messages for Contract Accounts"
docs/SEP-43-CHANGE.md   proposed wallet-interface change, separate from the SEP
docs/OVERVIEW.md        project overview (source of C-Sign-Overview.pdf)
docs/ROADMAP.md         plan and checkpoints
```

Next: testnet deployment, a TypeScript `verifyMessage` library and testnet experiments with OpenZeppelin smart accounts. See [docs/ROADMAP.md](docs/ROADMAP.md).

## Build and test

```sh
cargo test                        # unit tests, native
stellar contract build --locked   # wasm: target/wasm32v1-none/release/sep53c_verifier.wasm
stellar contract info hash --wasm target/wasm32v1-none/release/sep53c_verifier.wasm   # must equal contracts/verifier/WASM_HASH
```

The build is reproducible. Pinned inputs: rustc 1.96.1 (`rust-toolchain.toml`), soroban-sdk 28.0.0 (`Cargo.lock`) and stellar-cli 27.0.0, whose version is embedded in the Wasm metadata. CI checks the hash on every push. Enforcing simulation needs stellar-rpc 23 or newer and `SimulationAuthMode` in js-stellar-sdk (17.1.0 or newer recommended).

## Known limitations

- Validity follows the account's current rules, as with ERC-1271: a signature stops verifying after signers or policies change.
- Signature lifetime is bounded by `max_entry_ttl` (about 180 days on current network settings).
- Verification trusts the RPC that runs the simulation, like ERC-1271 with `eth_call`. Use your own RPC or cross-check two providers.
- Accounts that are not deployed yet cannot be verified.
- Accounts whose context rules only allow specific contracts need a rule that covers the verifier.

## License

Apache-2.0
