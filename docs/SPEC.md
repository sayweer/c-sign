# C-Sign: Signed Messages for Contract Accounts

| | |
|---|---|
| **Status** | Draft, v0 (2026-09-25) |
| **Working name** | SEP-53C, "SEP-53 profile for contract accounts" |
| **Author** | Seyit ([@sayweer](https://github.com/sayweer)) |
| **Discussion** | [stellar-protocol#1928](https://github.com/stellar/stellar-protocol/issues/1928) (dedicated issue to follow) |
| **Reference implementation** | this repository |

## Abstract

This profile defines how a contract account (a `C…` address) signs an arbitrary, human-readable message and how any party verifies that signature against the account's current on-chain authorization rules, without submitting a transaction. It reuses the Soroban authorization framework: the signature is a `SorobanAuthorizationEntry` for a side-effect-free call on a canonical verifier contract, and verification is an enforcing simulation of that call. [SEP-53](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0053.md) remains unchanged for `G…` accounts.

## Motivation

- SEP-53 only covers Stellar keypairs. SEP-43 leaves `signMessage` undefined for contract accounts; [#1928](https://github.com/stellar/stellar-protocol/issues/1928) asks for either an explicit "undefined" or an approach.
- A contract account has no single key. Its rules (signers, thresholds, policies, context rules) live in its `__check_auth`. Any scheme that verifies a signature against a public key ignores those rules: a removed or rotated signer still produces a "valid" signature.
- Wallets today either reject `signMessage` for C addresses or return mutually incompatible envelopes. Relying parties have no interoperable way to verify them.
- [SEP-45](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0045.md) already authenticates contract accounts through an authorization entry and an enforcing simulation. This profile generalizes that pattern to arbitrary messages and removes the server-side signature.

## Specification

### 1. Message

The signed payload is a structured, displayable value, not a hash:

```rust
pub struct SignedMessage {
    pub domain: String,     // relying-party domain, e.g. "vote.example.com"
    pub statement: String,  // what the user agrees to, e.g. "Proposal #12 = YES"
    pub challenge: Bytes,   // one-time value chosen by the relying party (≥ 16 random bytes)
    pub issued_at: u64,     // unix time, seconds
}
```

- Wallets MUST display `domain` and `statement` as plain text before signing.
- `statement` length is bounded. Recommended maximum: 1 KiB. The exact limit will be measured against `tx_max_contract_events_size_bytes` in week 1 of the implementation, because policy-enabled accounts embed the full auth context in events.

### 2. Signature

A C-Sign signature is a `SorobanAuthorizationEntry` with the following properties:

1. **Root invocation** is `verify_message(account, msg)` (ephemeral mode) or `anchor_message(account, msg)` (anchored mode) on the canonical verifier contract for the network. Arguments are exactly `(account, msg)`.
2. **No sub-invocations.** Verifiers MUST reject entries whose root has any sub-invocation.
3. **Credentials** MUST be `SOROBAN_CREDENTIALS_ADDRESS_V2` ([CAP-71](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0071.md)), and `credentials.address` MUST equal the `account` argument. This binds the signature to one account and prevents cross-account replay between accounts that share a signer.
4. **Network id, nonce and `signature_expiration_ledger`** are part of the signed preimage (`HashIdPreimageSorobanAuthorization`), so no extra fields are needed for network binding or uniqueness.
5. **Expiration.** `signature_expiration_ledger` MUST be at most `current_ledger + max_entry_ttl − 1`. For challenge-response use, a short lifetime is RECOMMENDED (for example 720 ledgers, about one hour).
6. **The wallet builds the entry.** The reference flow is `signMessage(message)`: the wallet (or embedded kit) constructs the entry from the plain message, displays the message and signs. Passing a pre-built entry through `signAuthEntry` is a legacy/test path.

### 3. Canonical verifier contract

Admin-less, storage-less, immutable. One deployment per network; its contract id is published in this specification once deployed.

```rust
#[contracterror] pub enum Error { AuthOk = 1 }

pub struct Verifier;
impl Verifier {
    /// Ephemeral mode: runs `account.require_auth()` for the invocation
    /// `verify_message(account, msg)`, then ALWAYS fails with Error::AuthOk.
    pub fn verify_message(env: Env, account: Address, msg: SignedMessage) -> Result<(), Error>;

    /// Anchored mode: runs `account.require_auth()`, then publishes the event
    /// topics ["anchored", account], data sha256(xdr(msg)), and returns that hash.
    pub fn anchor_message(env: Env, account: Address, msg: SignedMessage) -> BytesN<32>;
}
```

`verify_message` never succeeds on-chain. If anyone submits a published ephemeral signature, the transaction fails and the account's nonce is not consumed, so the signature remains verifiable off-chain. Since the function name is part of the authorized invocation, an ephemeral signature cannot be used as an anchored one.

### 4. Verification (ephemeral mode)

A relying party verifies `(address, message, verifierContractId, signedAuthEntry)` as follows:

1. **Structural checks**, all local:
   - `verifierContractId` is the canonical verifier for the expected network;
   - root invocation is `verify_message` on that contract, with arguments `(address, message)` and no sub-invocations;
   - credentials are V2 and `credentials.address == address`;
   - `message.domain` matches the relying party; `message.challenge` was issued by the relying party, is unused and not expired; `message.issued_at` is within the accepted clock skew; `statement` is within the size limit;
   - `signature_expiration_ledger` is in the future.
2. **Enforcing simulation.** Build a transaction that invokes `verify_message(address, message)` with the signed entry attached, and call `simulateTransaction` with `authMode: "enforce"` (stellar-rpc ≥ 23). Do not submit it.
3. **Decision.** The signature is valid **if and only if** the simulation fails with the verifier's `Error(Contract, #1)` (`AuthOk`). Any authorization failure (`Error(Auth, …)`), any other error, or a successful simulation is invalid. If the response carries a `restorePreamble`, the verifier reports "restore required" instead of "invalid".
4. **Consume the challenge** on success.

The host converts every `__check_auth` failure into `Error(Auth, InvalidAction)`, so an account cannot forge the `AuthOk` code.

### 5. Anchored mode

Anchored mode is for durable proofs. The signer authorizes `anchor_message(account, msg)`; the entry is submitted on-chain by anyone; the emitted event `("anchored", account) -> sha256(xdr(msg))` is the proof. Front-running is harmless: the result is the same event. RPC event retention is limited (about 7 days), so long-term availability needs an indexer or ledger archive.

### 6. SEP-43 `signMessage` for C addresses (proposal)

```ts
signMessage(message, { address: "C…", mode?: "ephemeral" | "anchored" }) => {
  address: string,               // C…
  message: SignedMessage,        // as displayed and signed
  verifierContractId: string,    // C…
  mode: "ephemeral" | "anchored",
  signedAuthEntry: string        // base64 XDR SorobanAuthorizationEntry
}
```

For `G…` addresses `signMessage` keeps its SEP-53 behavior. A single encoding (base64 XDR) is fixed here to close the hex/base64 ambiguity seen in wallet kits.

## Security considerations

- **Domain separation.** The canonical verifier is the only valid root. Wallets can recognize it and render the call as "sign message", not as a contract invocation.
- **Cross-account replay** is prevented by V2 credentials plus the `account` argument. **Cross-network replay** is prevented by the network id in the preimage. **Cross-domain replay** is prevented by `domain` and the relying party's `challenge`.
- **Nonce burning (griefing)** is prevented by the always-fail design of `verify_message`.
- **Blind signing** is avoided by signing a displayable structure, not a hash.
- **Current-state semantics.** Validity reflects the account's rules at verification time. This is a feature for revocation and a weakness for non-repudiation; use anchored mode for the latter.
- **RPC trust.** Ephemeral verification trusts the simulating RPC, exactly like ERC-1271 with `eth_call`. Mitigation: own RPC or cross-checking two providers.
- **Narrow-context accounts.** Accounts whose context rules only allow specific contracts (for example a spending-limit policy) need an explicit rule for the verifier. This is correct behavior, and it means limited agent keys cannot sign messages unless the account allows it.

## Limitations

- Signature lifetime ≤ `max_entry_ttl` (about 180 days). Not suitable for long-lived vouchers; use anchored mode.
- Undeployed (counterfactual) accounts cannot be verified. There is no EIP-6492 equivalent.
- On-chain consumers do not need this profile: a Soroban contract can `require_auth` any C address directly. C-Sign targets off-chain verification.

## Open questions

1. Should this live inside SEP-43, or as a separate SEP that SEP-43 references for C addresses?
2. Is the always-fail pattern acceptable, and are there objections to wallets building an authorization entry for a third-party verifier contract?
3. Should the canonical verifier be a single contract per network, or an allow-list?

## References

- SEP-53 Sign and Verify Messages; SEP-43 Wallet Interface; SEP-45 Web Authentication for Contract Accounts
- CAP-71 (V2 address credentials), stellar-protocol issue #1928 and security advisory #1899
- ERC-1271, EIP-6492 (Ethereum), Sign-In With Ethereum (challenge model)
