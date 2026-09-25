# Roadmap

Everything in the first phase runs on Stellar **testnet**. No checkpoint depends on mainnet, on an institution, or on an external maintainer's approval.

## Phase 1: first 30 days

### Week 1: specification v0 and go/no-go

- Publish the draft profile ([SPEC.md](SPEC.md)) as a dedicated stellar-protocol issue linked from #1928, as SDF requested.
- Go/no-go test against public testnet RPC with three account types: (a) smart-account-kit passkey wallet (OpenZeppelin smart account, Default rule), (b) OZ 2-of-3 ed25519 multisig, (c) passkey-kit wallet. For each:
  1. does a V2 `verify_message` entry pass `simulateTransaction(authMode: "enforce")` and is the `AUTH_OK` code readable from the result?
  2. when the same entry is submitted on-chain, does the transaction fail without consuming the nonce, and does the next simulation still pass?
  3. does `anchor_message` execute and emit the event?
  4. what is the largest `statement` a policy-enabled OZ account can carry under the event size limit?
- Decision rule: if (a) fails, work stops and the design is revisited. If `AUTH_OK` cannot be read reliably, `verify_message` is left non-reverting and the griefing risk is documented. If (b) or (c) fails, that account type is dropped from scope and noted.

### Week 2: verifier contract

- `sep53c-verifier`: `verify_message` and `anchor_message`, no admin, no storage (this repository, `contracts/verifier`).
- Unit tests with soroban-sdk testutils; integration tests against real OZ account and passkey-kit wasm.
- Testnet deploy, TTL extension of code and instance (`stellar contract extend … --ledgers-to-extend 3110000`), contract id in the README. A one-command redeploy script guards against testnet resets. A weekly CI health job simulates a fixed vector and alerts on archival.

### Week 3: TypeScript library

- `signMessage`: SEP-53 for G accounts; adapters for smart-account-kit/OZ (v0.9 and 0.7.x digests), passkey-kit and OZ multisig for C accounts; `buildMessageAuthEntry()` for wallet implementers.
- `verifyMessage`: SEP-53 for G; structural checks + enforcing simulation + `AUTH_OK` check + `restorePreamble` reporting for C.
- Express/Next.js verification middleware. Published on npm, default network testnet.

### Week 4: demo, conformance, ecosystem

- Two-origin demo: signer page and independent verifier API on different origins. Account matrix: G, OZ passkey C, OZ 2-of-3 multisig C, passkey-kit C.
- Conformance suite in CI with at least 12 negative vectors: removed signer, rotated signer, expired signature, wrong network, wrong domain, tampered message, reused challenge, policy rejection, unauthorized context rule, extra sub-invocation, cross-account replay with a V1 credential, displayed message ≠ signed message. Plus the positive griefing test: an ephemeral signature submitted on-chain is not invalidated.
- Design comments on #1928 and Stellar Wallets Kit #95 / #112; at least one pull request to a kit or SDK repository, `stellar/smart-account-kit` first.

## Deliverables

1. Draft specification (Markdown, stellar-protocol issue).
2. `sep53c-verifier` source + testnet contract id.
3. npm package (core, adapters, verify, middleware) + README.
4. Two-origin demo on testnet + short video.
5. Conformance matrix + negative vectors + CI report.
6. Go/no-go report: week-1 findings, supported account types, message size limit, griefing test result.
7. Links to PRs and design comments.

## Phase 1 is done when

1. A canonical, admin-less `sep53c-verifier` contract is deployed on Stellar testnet. Its contract id and the hash of one `anchor_message` transaction are published in the README, together with the ledger its TTL was extended to.
2. An open-source TypeScript library is published on npm with `signMessage` and `verifyMessage` for G accounts (SEP-53) and C accounts (enforcing simulation, no transaction submitted), with adapters for OpenZeppelin smart accounts via smart-account-kit, passkey-kit and OZ multisig.
3. A public conformance suite runs in CI on testnet. All positive cases pass for at least 3 C-account types plus G accounts, and at least 12 negative vectors are rejected. A test shows that submitting an ephemeral signature on-chain does not invalidate it.
4. Off-chain verification of a C-account signature completes in under 2 seconds against the public testnet RPC, measured as the median of 20 runs and recorded in the CI log.
5. The draft specification is published as a stellar-protocol issue linked from #1928. Design comments are posted on Stellar Wallets Kit #95 and #112, and at least one pull request is opened to a wallet-kit or SDK repository.
6. A two-origin demo is live on testnet with a short walkthrough video.

Maintainer replies, merged PRs, SEP acceptance and mainnet are not part of phase 1; each depends on an external actor.

## Biggest risk and gate

The signer side differs by account type: OZ v0.9 moved to an account-bound `AuthDigestPreimage` (breaking for off-chain signing), passkey-kit and smart-account-kit are not drop-in compatible, and `signAuthEntry` means different things in different wallets. The week-1 gate is: the smart-account-kit (OZ, Default rule) account accepts a V2 `verify_message` entry in enforcing simulation and `AUTH_OK` is readable. Delegated signers (CAP-71) are out of phase 1.

## After phase 1

- **Phase 2, consumer layer:** CAIP-122 `stellar` profile PR, an x402 sign-in-with-x verifier for Stellar (G: SEP-53, C: C-Sign), server-side packages and an off-chain approval example.
- **Phase 3, standard and distribution:** SEP draft PR, wallet display guidance, wallet-side reference implementation, Stellar Wallets Kit shim, anchored-mode indexer example, public conformance matrix.
- **Mainnet:** mainnet verifier + small audit + threat model; at least two merged wallet/kit integrations; usage metrics.

SEP acceptance is an undated external event and is not a condition of any phase.
