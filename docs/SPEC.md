## Preamble

```
SEP: To Be Assigned
Title: Signed Messages for Contract Accounts
Author: Seyit (@sayweer)
Status: Draft
Created: 2026-09-25
Updated: 2026-09-26
Version: 0.0.1
Discussion: https://github.com/stellar/stellar-protocol/issues/2027
```

## Simple Summary

A way for a Stellar contract account (a `C…` address such as a passkey wallet, a multisig account or an agent wallet with spending policies) to sign a human-readable message, and for anyone to check that signature against the account's current on-chain rules without submitting a transaction.

## Dependencies

- [SEP-53](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0053.md): message signing for `G…` accounts. This SEP is its counterpart for `C…` accounts and does not change it.
- [SEP-43](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0043.md): wallet interface. Integration is proposed separately (see [SEP-43-CHANGE.md](SEP-43-CHANGE.md)).
- [SEP-45](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0045.md): the authorization-entry-plus-enforcing-simulation pattern this SEP generalizes.
- [CAP-46-11](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0046-11.md) (Soroban authorization) and [CAP-71](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0071.md) (`SOROBAN_CREDENTIALS_ADDRESS_V2`, protocol 27).
- stellar-rpc 23 or newer (`simulateTransaction` with `authMode`).

## Motivation

SEP-53 lets a keypair sign a message. SEP-43 leaves `signMessage` undefined for contract accounts ([#1928](https://github.com/stellar/stellar-protocol/issues/1928)). A contract account has no single key: who may act, with which threshold and under which policy is decided by its `__check_auth`. A signature checked against one public key ignores all of that. A signer removed from the account yesterday still produces a "valid" signature today.

In practice wallets either throw on `signMessage` for `C…` addresses or return incompatible WebAuthn envelopes (Stellar-Wallets-Kit [#93](https://github.com/Creit-Tech/Stellar-Wallets-Kit/issues/93), [#95](https://github.com/Creit-Tech/Stellar-Wallets-Kit/issues/95), [#112](https://github.com/Creit-Tech/Stellar-Wallets-Kit/pull/112)). Relying parties cannot verify those consistently.

| | Signs arbitrary text | Checks the account's current rules | Needs a relying-party key | Verifiable by third parties |
|---|---|---|---|---|
| SEP-53 | yes | no (key only) | no | yes |
| SEP-45 | no (web session) | yes | yes | no |
| Ad-hoc WebAuthn envelopes | yes | no (key only) | no | inconsistent |
| **This SEP** | **yes** | **yes** | **no** | **yes** |

## Abstract

The signature is a `SorobanAuthorizationEntry` in which the account authorizes one call, `verify_message(account, msg)`, on an instance of a small reference verifier contract. `msg` is a symbol-keyed map with a human-readable statement, the relying party's domain and a one-time nonce. The verifier calls `account.require_auth()` and then always fails with a reserved error, so the entry can never have an on-chain effect and a failed submission does not consume its nonce. A relying party verifies by rebuilding the expected invocation, confirming that the verifier instance runs the reference Wasm (by hash), and running an enforcing simulation: the account's own `__check_auth` decides, against current ledger state. No transaction is submitted and no fee is paid. There is no canonical verifier address. Anyone may deploy the reference Wasm, and trust is anchored in its hash.

## Specification

### 1. Terms

- **Account**: the contract account (`C…`) that signs.
- **Wallet**: software that builds and signs the entry for the account.
- **Relying party (RP)**: the party that requests and verifies the signature.
- **Reference verifier**: the Wasm published with this SEP. **Verifier instance**: any deployed contract whose executable is the reference verifier.

### 2. Message

`msg` is an `ScVal::Map` with `ScVal::Symbol` keys, sorted as the host requires.

| Key | Type | Required | Meaning |
|---|---|---|---|
| `version` | String | yes | `"1"` for this version of the SEP |
| `domain` | String | yes | Relying-party domain (RFC 4501 authority). **Written by the wallet**, see §5 |
| `statement` | String | yes | Text the user agrees to. MAY be a full CAIP-122 message |
| `nonce` | String | yes | One-time value chosen by the RP, at least 8 alphanumeric characters |
| `issued_at` | U64 | yes | Unix time in seconds |
| `uri` | String | no | Resource the message refers to |
| `expiration_time` | U64 | no | Unix time after which the RP MUST reject |
| `not_before` | U64 | no | Unix time before which the RP MUST reject |
| `request_id` | String | no | RP-defined identifier |
| `resources` | Vec<String> | no | URIs the user is agreeing to |

- Wallets and RPs MUST reject keys not listed for the declared `version`.
- Size: `statement` MUST NOT exceed 1024 bytes and the XDR-encoded `msg` MUST NOT exceed 2048 bytes. These values are provisional; they will be set from measurements with policy-enabled OpenZeppelin accounts, whose policies embed the call context in events (see Open items).
- The verifier never reads `msg`. New optional keys in later versions do not change the reference Wasm or its hash.

### 3. Reference verifier

```rust
#[contracterror]
pub enum Error { AuthOk = 1 }

pub fn verify_message(env: Env, account: Address, msg: Map<Symbol, Val>) -> Result<(), Error> {
    account.require_auth();
    Err(Error::AuthOk)
}
```

- No admin, no storage, no upgrade path. Source: [contracts/verifier](../contracts/verifier).
- Reference Wasm hash (v1): `2a5004a7736327a994d449af03ae7c5eea481da2d2d3191222dc7b4934a4c299`.
- The build is reproducible with rustc 1.96.1, soroban-sdk 28.0.0 and stellar-cli 27.0.0 (the CLI version is embedded in the Wasm metadata): `stellar contract build --locked`.
- **No instance is canonical.** Any party (a wallet team, an RP, a trusted third party) MAY deploy an instance. A list of known testnet and mainnet instances MAY be kept in the reference repository; it is informative only.

### 4. Signature

A signature is a base64-encoded XDR `SorobanAuthorizationEntry` such that:

1. `root_invocation.function` is `SOROBAN_AUTHORIZED_FUNCTION_TYPE_CONTRACT_FN` on a verifier instance, `function_name` is `verify_message`, and `args` are exactly `[ScAddress(account), msg]`.
2. `root_invocation.sub_invocations` is empty.
3. `credentials` is `SOROBAN_CREDENTIALS_ADDRESS_V2` and `credentials.address` equals `account`. V2 binds the signer address into the preimage (`HashIdPreimageSorobanAuthorizationWithAddress`), so a signature cannot be reattributed to another account that shares a signer.
4. `signature_expiration_ledger` is at least the current ledger and at most `current + max_entry_ttl − 1`. For interactive use a short lifetime is RECOMMENDED (for example 720 ledgers, about one hour).
5. How `credentials.signature` is produced is defined by the account implementation (for example OpenZeppelin accounts sign an auth digest that commits to `context_rule_ids`). This SEP standardizes only the entry shape and its verification; verification by simulation keeps it independent of account-specific signing formats.

Accounts whose `__check_auth` itself requires authorization from other addresses (for example delegated signers) MAY need additional entries. Their exact shape is an open item (see below).

### 5. Wallet requirements

1. The wallet MUST set `domain` from the origin of the requesting application (browser extension: the sender origin; WalletConnect: the peer's metadata URL; mobile: the calling app's verified domain). If the application supplies a different `domain`, the wallet MUST refuse. This mirrors how WebAuthn writes `origin` into `clientDataJSON` and prevents one site from obtaining a signature addressed to another.
2. The wallet MUST display `domain` and `statement` decoded from the entry it is about to sign, not from a copy supplied by the application, and MUST present the request as a message signature, not as a generic contract call.
3. The wallet MUST recognise the entry by the verifier instance's executable hash (§6 step 5), the function name and the argument shape, and MUST refuse entries with sub-invocations, unknown keys or oversize content.
4. The wallet SHOULD use a short `signature_expiration_ledger`.

### 6. Verification

The RP receives `address`, `msg` and the signed entry, and knows its own domain, the nonces it issued and the list of accepted verifier Wasm hashes. The result is `valid`, `invalid` or `inconclusive`. Network or RPC failures and archived ledger entries are `inconclusive`, never `invalid`.

1. Decode the entry. Malformed XDR is `invalid`.
2. Check §4 items 1 to 4: contract-function root, `verify_message`, empty sub-invocations, V2 credentials with `credentials.address == address`, expiration within bounds.
3. Rebuild the expected root invocation from `(verifier instance, address, msg)` and compare it byte for byte with the received one. Never trust the received invocation.
4. Check `msg`: `version`, `domain` equals the RP's own domain, `nonce` was issued by this RP and is unused, `issued_at` within the accepted clock skew, `expiration_time` and `not_before` if present, no unknown keys, size limits.
5. **Pin the verifier instance.** Read `LedgerKey::ContractData { contract: instance, key: ScVal::LedgerKeyContractInstance, durability: Persistent }` and require `ContractInstance.executable == Wasm(hash)` with `hash` in the accepted list. A missing or archived instance is `inconclusive`. Because the reference Wasm cannot upgrade itself, a positive result MAY be cached indefinitely per `(network, instance)`.
6. Build a transaction with one `InvokeHostFunction` operation calling `verify_message(address, msg)` on the instance, attach the entry (and any supporting entries), and call `simulateTransaction` with `authMode: "enforce"`. Do not submit it.
7. **Decide.** `valid` if and only if the simulation failed, the error begins with `HostError: Error(Contract, #1)`, and the diagnostic events contain an error event raised by the verifier instance with contract error code 1. The contract-id check matters because an account's own `__check_auth` may use error code 1 for its own purposes. An authorization failure (`Error(Auth, …)`) is `invalid`. Anything else is `inconclusive`.
8. On `valid`, mark the nonce as used.

The host converts recoverable errors raised inside `__check_auth` into `Error(Auth, InvalidAction)` before they reach the caller, so an account cannot make the simulation report the verifier's `Error(Contract, #1)`.

### 7. Wallet interface

Integration with SEP-43 is proposed in a separate change ([SEP-43-CHANGE.md](SEP-43-CHANGE.md)): either `signMessage` accepts `C…` addresses and returns the base64 entry, or a new function is added. `G…` addresses keep SEP-53 behaviour.

### 8. CAIP-122 and x402 (informative)

A CAIP-122 profile for Stellar needs two signature types: SEP-53 for `G…` accounts and this SEP for `C…` accounts. For `C…` accounts `statement` carries the formatted CAIP-122 message, `nonce` carries its nonce and the signature string is the base64 entry, whose root invocation already names the verifier instance. An x402 sign-in-with-x verifier for Stellar reduces to `({ address, message, signature }) => Promise<boolean>` backed by §6.

## Design Rationale

- **The account decides, not a key.** Verification runs the account's own `__check_auth` against current state, so it works for every existing contract account without an upgrade and never re-implements signer, threshold or policy logic.
- **Why not an account-side `is_valid_signature` (ERC-1271 style).** The host refuses direct calls to reserved `__`-prefixed functions, so a new function would have to be added to every account implementation. On Ethereum, per-account implementations of ERC-1271 led to cross-account replay issues across many wallets because the hash did not bind the account; here V2 credentials bind it at the host level.
- **Why the verifier always fails.** A message signature must never be a usable transaction. Because the root call fails, submitting a published signature has no effect, and the host rolls the consumed nonce back on failure (`auth.rs`: "In case if the root call has failed, the nonce will get 'un-consumed' due to storage rollback"). The same idea was suggested for SEP-45 in [#1561](https://github.com/stellar/stellar-protocol/pull/1561) (a `web_auth_verify` that fails "with a specific error when all signatures are valid") and set aside because the server builds SEP-45 entries itself, which makes nonce handling awkward. Here the wallet builds the entry. Comparable precedents elsewhere: BIP-322 verifies a virtual, unbroadcastable transaction with the script interpreter, and EIP-6492's validator returns its result by reverting.
- **Why not a non-reverting verifier.** Anyone holding a published signature could submit it, consume the nonce and make every later verification fail.
- **Why not SEP-45 as is.** It needs an RP signing key and a `WEB_AUTH_CONTRACT_ID`, authenticates a session rather than a statement, and cannot be verified by third parties.
- **Why no canonical address.** Ownership of a shared contract should not be a dependency. Pinning the code hash gives the same guarantee: an unpinned RP could be fooled by a fake "verifier" that returns error code 1 without calling `require_auth`.
- **Why the message is in the arguments, not a hash.** What the wallet displays is exactly what is authorized, with no need for a separate descriptor or registry.
- **Why a map, not a fixed struct.** Later versions can add optional keys without a new Wasm, so the pinned hash stays valid.
- **Anchored, on-chain proofs are out of scope.** Any contract that requires the account's authorization and emits an event provides them. A future SEP may standardize that event.
- **An RP-bound variant** (`verify_message_for(account, rp, msg)`, requiring both authorizations and not reverting, as in SEP-45) was considered. It removes the always-fail pattern but loses third-party verifiability; it can be added if reviewers prefer it.
- **Key-based verification** (SEP-53 by one signer plus reading the account's signer storage) is rejected: storage layouts differ per implementation and thresholds and policies stay invisible.

## Security Concerns

- **Forged verifier.** Mitigated only by hash pinning (§6 step 5); RPs and wallets MUST pin.
- **Cross-site phishing.** Mitigated by the wallet writing `domain` from the requesting origin and the RP checking it.
- **Replay** across accounts (V2 credentials and the `account` argument), networks (network id in the preimage), relying parties (`domain`) and time (`nonce`, `signature_expiration_ledger`).
- **Nonce burning.** Prevented by the always-failing verifier and host rollback.
- **Blind signing.** The message is displayed from the signed entry; entries with sub-invocations or unknown keys are refused.
- **RPC trust.** Verification trusts the RPC that runs the simulation, as ERC-1271 trusts `eth_call`. RPs SHOULD use their own RPC or cross-check two providers.
- **Current-state semantics.** A signature stops verifying after the account's signers or policies change. This supports revocation but not non-repudiation.
- **Resource limits.** Oversized messages can exceed event or resource limits in policy-enabled accounts; wallets enforce the size limits.

## Limitations

- Signature lifetime is bounded by `max_entry_ttl` (about 180 days on current network settings).
- Accounts that are not deployed yet cannot be verified. A deploy-then-verify wrapper, similar in spirit to EIP-6492, looks feasible and is left for a later version.
- Accounts whose context rules only allow specific contracts need a rule that covers the verifier before they can sign messages.

## Open items (to be settled on testnet before FCP)

- Exact size limits for `statement` and `msg` with policy-enabled OpenZeppelin accounts.
- Confirmation that the verifier-scoped diagnostic error event is present in `simulateTransaction` responses on current stellar-rpc versions.
- Shape of supporting entries for accounts with delegated signers.
- Test vectors for OpenZeppelin smart accounts (single signer and 2-of-3 with a threshold policy) and a minimal ed25519 account, including on-chain submission of a signature to show the nonce is not consumed.

## Changelog

- `v0.0.1`: Initial draft.
