# Roadmap

Everything in the first phase runs on Stellar **testnet**. No checkpoint depends on mainnet, on an institution, or on an external maintainer's approval.

## Done

- Design comment on [#1928](https://github.com/stellar/stellar-protocol/issues/1928#issuecomment-5823338114) and dedicated issue [#2027](https://github.com/stellar/stellar-protocol/issues/2027), as SDF asked.
- Draft SEP "Signed Messages for Contract Accounts" ([SPEC.md](SPEC.md)) following the SEP template, and the separate SEP-43 proposal ([SEP-43-CHANGE.md](SEP-43-CHANGE.md)).
- Reference verifier: one function, no admin, no storage, message as a map; 5 unit tests; reproducible Wasm with a pinned hash checked in CI.

## Phase 1: first 30 days

### Week 1: testnet evidence (go/no-go)

- Deploy two instances of the reference verifier (to show there is no canonical one), extend their TTL, publish ids in the README. A one-command script redeploys after testnet resets.
- Accounts: OpenZeppelin smart account with one ed25519 signer, OpenZeppelin 2-of-3 with a threshold policy, and a minimal ed25519 account.
- Experiments, each recorded with transaction hashes:
  1. **Valid signature** verifies as `valid` for each account type.
  2. **On-chain submission** of a signature fails, the account's nonce is not consumed, and the signature still verifies. The same experiment with a non-reverting verifier shows the nonce being burned.
  3. **Hash pinning**: a fake verifier that returns the success code without calling `require_auth` is accepted without pinning and rejected with it.
  4. **Negative cases** are `invalid`: removed signer, wrong domain, tampered message, expired signature, reused nonce, extra sub-invocation, V1 credentials.
  5. **Size limit**: the largest statement a policy-enabled OpenZeppelin account accepts.
- **Gate:** if experiment 2 fails (the nonce is consumed), work stops and the design is revisited.

### Week 2: TypeScript library

- `verifyMessage`: structural checks, invocation rebuild, verifier hash pinning, enforcing simulation and the three-state decision (`valid` / `invalid` / `inconclusive`).
- `buildMessageAuthEntry` and signing helpers for OpenZeppelin smart accounts and simple ed25519 accounts; SEP-53 for `G…` accounts.
- A thin adapter with the shape x402's sign-in-with-x expects: `({ address, message, signature }) => Promise<boolean>`.

### Week 3: conformance and demo

- Conformance suite in CI against testnet with the positive and negative vectors above.
- Two-origin demo: a signer page and an independent verifier service on different origins. Core scene: sign, verify, remove the signer, verify again (`valid` then `invalid`).

### Week 4: specification and ecosystem

- Update the draft SEP with measured limits and test vectors; open the SEP pull request once the discussion is settled.
- Design comments on Stellar Wallets Kit #95 and #112; at least one pull request to a kit or SDK repository.

## Phase 1 is done when

1. Two instances of the reference verifier are deployed on testnet, their executable hash equals `contracts/verifier/WASM_HASH`, and their ids and TTL are in the README.
2. A TypeScript library with `verifyMessage` and signing helpers is in this repository, with unit tests and testnet integration tests.
3. The experiments above are recorded with transaction hashes, including the on-chain submission that leaves the nonce unconsumed.
4. Verification of a contract-account signature completes in under 2 seconds against the public testnet RPC (median of 20 runs).
5. The draft SEP includes measured limits and test vectors.
6. The two-origin demo runs on testnet with a short walkthrough video.

Maintainer replies, merged pull requests, SEP acceptance and mainnet are not part of phase 1; each depends on an external actor.

## Biggest risk

Signing differs by account type: OpenZeppelin accounts sign a digest that commits to `context_rule_ids`, other accounts sign the raw payload, and kits expose `signAuthEntry` differently. The SEP standardizes only the entry shape and its verification, and verification by simulation is independent of those formats. Delegated signers are out of phase 1.

## After phase 1

- **Consumer layer:** CAIP-122 `stellar` profile, an x402 sign-in-with-x verifier for Stellar, server middleware, an off-chain approval example.
- **Standard and distribution:** SEP-43 pull request, wallet display guidance, a wallet-side reference implementation, a Stellar Wallets Kit module, counterfactual (not yet deployed) accounts.
- **Mainnet:** instances on mainnet, a small audit and threat model, wallet and kit integrations, usage metrics.

SEP acceptance is an undated external event and is not a condition of any phase.
