## Preamble

```
SEP: To Be Assigned
Title: Signed Messages for Contract Accounts
Author: Seyit (@sayweer)
Status: Draft
Created: 2026-09-25
Updated: 2026-10-23
Version: 0.0.2
Discussion: https://github.com/stellar/stellar-protocol/discussions/2045
```

## Simple Summary

A way for a Stellar contract account (a `C…` address such as a passkey wallet, a multisig account or an agent wallet with spending policies) to sign a human-readable message, and for anyone to check that signature against the account's current on-chain rules without submitting a transaction.

## Dependencies

- [SEP-53](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0053.md): message signing for `G…` accounts. This SEP is its counterpart for `C…` accounts and does not change it.
- [SEP-43](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0043.md): wallet interface. Integration is proposed separately (see [SEP-43-CHANGE.md](https://github.com/sayweer/c-sign/blob/main/docs/SEP-43-CHANGE.md)).
- [SEP-45](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0045.md): the authorization-entry-plus-enforcing-simulation pattern this SEP generalizes.
- [CAP-46-11](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0046-11.md) (Soroban authorization), [CAP-71](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0071.md) (`SOROBAN_CREDENTIALS_ADDRESS_V2`, protocol 27) and [CAP-85](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0085.md) (`CONTRACT_EXECUTABLE_EXTERNAL_REF`, see §6 step 5).
- stellar-rpc 23 or newer (`simulateTransaction` with `authMode`), returning diagnostic events in simulation results (`preflight-enable-debug`, on by default). Without them no result is `valid`.

## Motivation

SEP-53 lets a keypair sign a message. SEP-43 leaves `signMessage` undefined for contract accounts ([#1928](https://github.com/stellar/stellar-protocol/issues/1928)). A contract account has no single key: who may act, with which threshold and under which policy is decided by its `__check_auth`. A signature checked against one public key ignores all of that. A signer removed from the account yesterday still produces a "valid" signature today.

In practice wallets either throw on `signMessage` for `C…` addresses or return incompatible WebAuthn envelopes (Stellar-Wallets-Kit [#93](https://github.com/Creit-Tech/Stellar-Wallets-Kit/issues/93), [#95](https://github.com/Creit-Tech/Stellar-Wallets-Kit/issues/95), [#112](https://github.com/Creit-Tech/Stellar-Wallets-Kit/pull/112)). Relying parties cannot verify those consistently.

| | Signs arbitrary text | Checks the account's current rules | Needs a relying-party key | Verifiable by third parties |
|---|---|---|---|---|
| SEP-53 | yes | no (key only) | no | yes |
| SEP-45 | no (web session) | yes | yes | no |
| Ad-hoc WebAuthn envelopes | yes | no (key only) | no | inconsistent |
| This SEP | yes | yes | no | yes (bearer, see Security Concerns) |

## Abstract

The signature is a `SorobanAuthorizationEntry` in which the account authorizes one call, `verify_message(account, msg)`, on an instance of a small reference verifier contract. `msg` is a symbol-keyed map with a human-readable statement, the relying party's domain and a one-time nonce. The verifier calls `account.require_auth()` and then always fails with a reserved error, so the host rolls the call back, including the entry's nonce, and the entry cannot change the account's state. The entry works like a bearer credential: anyone who holds it can verify it, including another contract (Security Concerns). A relying party verifies by rebuilding the expected invocation, confirming that the verifier instance runs the reference Wasm (by hash), and running an enforcing simulation: the account's own `__check_auth` decides, against current ledger state. No transaction is submitted and no fee is paid. There is no canonical verifier address. Anyone may deploy the reference Wasm, and trust is anchored in its hash.

## Specification

### 1. Terms

- **Account**: the contract account (`C…`) that signs.
- **Wallet**: software that builds and signs the entry for the account.
- **Relying party (RP)**: the party that requests and verifies the signature.
- **Reference verifier**: the Wasm published with this SEP. **Verifier instance**: any deployed contract whose executable is `CONTRACT_EXECUTABLE_WASM` with the reference verifier's hash.

### 2. Message

`msg` is an `ScVal::Map` with `ScVal::Symbol` keys, sorted as the host requires.

| Key | Type | Required | Meaning |
|---|---|---|---|
| `version` | String | yes | `"1"` for this version of the SEP |
| `domain` | String | yes | Host of the requesting origin, in the form below. Written by the wallet, see §5 |
| `statement` | String | yes | Text the user agrees to, on one line |
| `nonce` | String | yes | One-time value chosen by the RP, at least 8 alphanumeric characters |
| `issued_at` | U64 | yes | Unix time in seconds |
| `uri` | String | no | Resource the message refers to |
| `expiration_time` | U64 | no | Unix time after which the message has expired (§6 step 4) |
| `not_before` | U64 | no | Unix time before which the message is not yet valid (§6 step 4) |
| `request_id` | String | no | RP-defined identifier |
| `resources` | Vec<String> | no | URIs the user is agreeing to |

- Wallets and RPs MUST reject keys not listed for the declared `version`.
- `domain` is the host of the requesting `https` origin (RFC 3986): lower case, internationalized labels as A-labels (RFC 5890), no trailing dot, followed by `:port` only when the port is not 443. It has no scheme, userinfo or path.
- String values, including elements of `resources`, MUST be valid UTF-8 and MUST NOT contain control characters (General Category Cc), line or paragraph separators (Zl, Zp) or code points with the Default_Ignorable_Code_Point property, which include bidirectional controls and zero-width characters. Wallets and RPs MUST reject such messages, not strip the characters.
- Size: `statement` MUST NOT exceed 1024 bytes, the XDR-encoded `msg` 2048 bytes and the XDR-encoded entry 16384 bytes. These limits are a display and transport choice, not host limits ([EXPERIMENTS.md](https://github.com/sayweer/c-sign/blob/main/docs/EXPERIMENTS.md), S1 and S2).
- A signed `msg` is readable by anyone who holds the signature and MUST NOT contain secrets.
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

- No admin, no storage, no upgrade path. Source: [contracts/verifier](https://github.com/sayweer/c-sign/tree/main/contracts/verifier).
- Reference Wasm hash (v1): `2a5004a7736327a994d449af03ae7c5eea481da2d2d3191222dc7b4934a4c299`. RPs and wallets MUST accept only hashes listed in this SEP. A version of this SEP that adds a hash states whether earlier hashes remain acceptable.
- The build is reproducible with rustc 1.96.1, soroban-sdk 28.0.0 and stellar-cli 27.0.0 (commit `5a7c5fe76530bf4248477ac812fc757146b98cc4`, which is embedded in the Wasm metadata): `stellar contract build --locked`.
- **No instance is canonical.** Any party (a wallet team, an RP, a trusted third party) MAY deploy an instance. A list of known testnet and mainnet instances MAY be kept in the reference repository; it is informative only.

### 4. Signature

A signature is a base64-encoded XDR `SorobanAuthorizationEntry` such that:

1. `root_invocation.function` is `SOROBAN_AUTHORIZED_FUNCTION_TYPE_CONTRACT_FN` on a verifier instance, `function_name` is `verify_message`, and `args` are exactly `[ScAddress(account), msg]`.
2. `root_invocation.sub_invocations` is empty.
3. `credentials` is `SOROBAN_CREDENTIALS_ADDRESS_V2` and `credentials.address` equals `account`. Other credential types, including `SOROBAN_CREDENTIALS_ADDRESS_WITH_DELEGATES` (CAP-71), are not valid.
4. `signature_expiration_ledger` is not lower than the ledger the verification runs at and not higher than that ledger plus `max_entry_ttl − 1`. The host enforces the upper bound.
5. How `credentials.signature` is produced is defined by the account implementation. For example, OpenZeppelin stellar-accounts 0.8.0 and later sign `sha256(xdr(AuthDigestPreimage { account, signature_payload, context_rule_ids }))` and 0.7.x sign `sha256(signature_payload || xdr(context_rule_ids))`; both are in the [test vectors](https://github.com/sayweer/c-sign/blob/main/vectors/c-sign-v1.json). This SEP standardizes only the entry shape and its verification; verification by simulation keeps it independent of account-specific signing formats.

A signature is exactly one entry. Accounts whose `__check_auth` needs authorization from other addresses (delegated signers) cannot sign messages under this version, and RPs MUST NOT attach other entries supplied with a signature.

### 5. Wallet requirements

1. The wallet MUST set `domain` from the origin of the requesting application as the platform reports it, never from data the application supplies. For a browser, this is the origin of the frame that sent the request. For WalletConnect, it is the origin from the Verify API when its status is `VALID` and the request is not flagged as a scam; the peer's metadata URL is not an origin. For software that signs without a person reviewing each request, such as an agent, it is the host of the HTTPS connection that delivered the request, never model output or tool arguments. The wallet MUST refuse origins that are not `https`, except `localhost` in a developer mode, and MUST refuse a request whose application-supplied `domain` differs. When the platform reports no origin (deep links, co-signing, QR codes, files, or a WalletConnect request without a `VALID` Verify status or flagged as a scam), the wallet MUST either refuse, or use the application-supplied `domain`, show it as unverified and require the user to confirm it.
2. The wallet MUST display `domain`, `statement` and every other field present, decoded from the entry it is about to sign, not from a copy supplied by the application. It MUST show `statement` in full, as plain text, visibly separate from text the wallet adds, and MUST present the request as a message signature, not as a generic contract call. It MUST do this, and the check of item 3, before invoking a passkey or hardware signer, which sees only a digest.
3. The wallet MUST recognise the entry by the function name, the argument shape and the verifier instance's executable (`CONTRACT_EXECUTABLE_WASM` with an accepted hash, §6 step 5), read through an RPC the wallet chooses, not one the application supplies. It MUST refuse entries with sub-invocations, unknown keys or content that breaks §2.
4. The wallet SHOULD use a short `signature_expiration_ledger` (for sign-in, at most 720 ledgers, about one hour, is RECOMMENDED) and SHOULD choose `credentials.nonce` at random.
5. The wallet MUST sign an entry whose root invocation calls a function named `verify_message` only in response to a message-signing request (§7), never through generic authorization-entry or transaction signing, and never under an approval granted for other requests.
6. Before signing, the wallet SHOULD check that the signers it will use satisfy a rule of the account that covers this call (OpenZeppelin wallets choose `context_rule_ids` themselves). If none does, the wallet SHOULD return a distinct error saying that the account cannot sign messages, instead of a signature.
7. A rule added so that an account can sign messages SHOULD be scoped to the verifier instance the wallet uses (for OpenZeppelin accounts, a `CallContract` rule naming it) and SHOULD hold only signers allowed to act as the account. Any signer in it, for example an agent's session key, can sign in as the account. A wallet that adds a key to a rule matching every call SHOULD tell the user that the key can also sign messages as the account.

### 6. Verification

The RP receives `address`, `msg` and the signed entry, and knows its own domains (from its configuration, not from the request), the nonces it issued and the list of accepted verifier Wasm hashes. The result is `valid`, `invalid` or `inconclusive`. `valid` means that, at the ledger the simulation ran on, the account's authorization logic accepted the entry for this call; it does not identify the signer or rule that authorized it. `inconclusive` means the RP could not decide: an RPC failure, missing diagnostic events, an unreadable or archived verifier instance, or any other unexpected simulation result. A failed check in steps 1 to 5 is `invalid` unless the step says otherwise. An RP MUST NOT authenticate, grant access or record consent on a result other than `valid`; it MAY retry an `inconclusive` one. Archived account or policy entries do not make a result `inconclusive`; the simulation restores them.

1. Decode the entry. A base64 string longer than 21848 characters, a decoded entry longer than 16384 bytes or malformed XDR is `invalid`. The lengths are checked before XDR decoding, and no RPC call is made in these cases.
2. Check §4 items 1 to 3, and that `signature_expiration_ledger` is not lower than the RPC's latest ledger. The host enforces the upper bound of §4 item 4 during step 6. For sign-in, an RP SHOULD also reject an entry that expires more than 17280 ledgers (about one day) after the latest ledger.
3. Rebuild the expected root invocation from `(verifier instance, address, msg)` and compare it byte for byte with the received one. Never trust the received invocation.
4. Check `msg`: `version`, no unknown keys and the rules of §2. `domain` equals one of the RP's own domains exactly, with no suffix or wildcard matching. `nonce` was issued by this RP no more than its challenge lifetime ago (RECOMMENDED: 300 seconds, measured on the RP's clock) and is unused; the RP SHOULD also check that it was issued to the same session and for the same `statement`. `issued_at` is not in the future, and the current time is not before `not_before` and not after `expiration_time` if present. These time checks MAY allow at most 60 seconds of clock skew, which is not added to the challenge lifetime. Every value is taken from `msg`; text formatted from it (for example a CAIP-122 message) is for display only and MUST NOT be parsed.
5. Pin the verifier instance. Read `LedgerKey::ContractData { contract: instance, key: ScVal::LedgerKeyContractInstance, durability: Persistent }` and require `ContractInstance.executable` to be `CONTRACT_EXECUTABLE_WASM` with its hash in the accepted list. Any other executable, including `CONTRACT_EXECUTABLE_EXTERNAL_REF` (CAP-85), is `invalid` and MUST NOT be resolved to a hash. An instance that does not exist is `invalid`; one that cannot be read or is archived is `inconclusive`. A Wasm executable changes only through the contract's own code, which the reference Wasm lacks, so a positive result MAY be cached per (network id, instance).
6. Use an RPC that serves the expected network (check `getNetwork`); an RPC on another network is `inconclusive`, and one whose latest ledger closed more than 30 seconds ago SHOULD be treated as `inconclusive`. The RP SHOULD use its own RPC or cross-check two providers, treating disagreement as `inconclusive`, and SHOULD rate-limit verification per client and per account. Build a transaction with one `InvokeHostFunction` operation calling `verify_message(address, msg)` on the instance, attach the received entry and no other, and call `simulateTransaction` with `authMode: "enforce"`. Do not submit it.
7. Decide from the first line of the simulation error only; later lines can contain log output from the account. `valid` if and only if the simulation failed, the first line begins with `HostError: Error(Contract, #1)`, and the diagnostic events contain an error event raised by the verifier instance with contract error code 1. `invalid` if the first line begins with `HostError: Error(Auth,`. Anything else is `inconclusive`.
8. On `valid`, mark `msg.nonce` as used in the same atomic operation that confirms it is unused (for example a conditional write). `invalid` and `inconclusive` MUST NOT consume it. Key replay state on `msg.nonce`, not on the entry bytes, which can differ for the same authorization.

The nonce checks of steps 4 and 8 are for the RP that issued the nonce. Any other verifier, such as an auditor or another service, applies steps 1 to 7, skips the nonce checks of step 4 and, in place of step 4's domain check, MUST check `domain` against the domains it accepts for that statement. A service that verifies for an RP, such as an x402 facilitator, MUST compare `domain` with that RP's domains, not its own. Such a verifier learns only that the account's current rules authorize the message, not when it was signed or whether it was used before, so its result is not a sign-in.

### 7. Wallet interface

Integration with SEP-43 is proposed in a separate change ([SEP-43-CHANGE.md](https://github.com/sayweer/c-sign/blob/main/docs/SEP-43-CHANGE.md)): either `signMessage` accepts `C…` addresses and returns the base64 entry, or a new function is added. `G…` addresses keep SEP-53 behaviour.

### 8. CAIP-122 and x402 (informative)

A CAIP-122 profile for Stellar needs two signature types: SEP-53 for `G…` accounts and this SEP for `C…` accounts. For `C…` accounts the CAIP-122 message is formatted from `msg`: `domain`, `uri`, `nonce`, `issued_at`, `expiration_time`, `not_before`, `request_id` and `resources` fill the matching CAIP-122 fields and `statement` is its statement line. Verifiers apply §6, which takes these values from `msg` (step 4). The signature string is the base64 entry, whose root invocation already names the verifier instance. An x402 sign-in-with-x verifier for Stellar reduces to `({ address, message, signature }) => Promise<boolean>` backed by §6 and returning `true` only for `valid`; a facilitator checks `domain` against the resource server's domains (§6, after step 8).

## Design Rationale

- **The account decides, not a key.** Verification runs the account's own `__check_auth` against current state, so it works for every existing contract account without an upgrade and never re-implements signer, threshold or policy logic.
- **Why not an account-side `is_valid_signature` (ERC-1271 style).** The host refuses direct calls to reserved `__`-prefixed functions, so a new function would have to be added to every account implementation. On Ethereum, per-account implementations of ERC-1271 led to cross-account replay issues across many wallets because the hash did not bind the account; here V2 credentials bind it at the host level.
- **Why the verifier always fails.** A message signature must never be a usable transaction. Because the verifier's call always returns an error, the host discards its storage changes, including the account's nonce, also when another contract makes the call and catches the error with `try_call`. Submitting a published signature therefore cannot change the account's state or consume its nonce, although a contract that catches the error can act on it (Security Concerns, Bearer credential). The same idea was suggested for SEP-45 in [#1561](https://github.com/stellar/stellar-protocol/pull/1561) (a `web_auth_verify` that fails "with a specific error when all signatures are valid") and set aside because the server builds SEP-45 entries itself, which makes nonce handling awkward. Here the wallet builds the entry. Comparable precedents elsewhere: BIP-322 verifies a virtual, unbroadcastable transaction with the script interpreter, and EIP-6492's validator returns its result by reverting.
- **Why two checks for `valid`.** The host converts recoverable errors raised inside `__check_auth` (contract errors, traps, calls to missing contracts) into `Error(Auth, InvalidAction)`, so an account cannot make the simulation report the verifier's `Error(Contract, #1)`. Non-recoverable errors, such as budget exhaustion, pass through unchanged and end up `inconclusive`. Both checks of §6 step 7 are kept because the error text is not a stable RPC interface and the event check ties the result to the verifier instance.
- **Why the wallet writes `domain`.** It mirrors how WebAuthn writes `origin` into `clientDataJSON`, so one site cannot obtain a signature addressed to another.
- **Why not a non-reverting verifier.** Anyone holding a published signature could submit it, consume the nonce and make every later verification fail.
- **Why not SEP-45 as is.** It needs an RP signing key and a `WEB_AUTH_CONTRACT_ID`, authenticates a session rather than a statement, and cannot be verified by third parties.
- **Why no canonical address.** Ownership of a shared contract should not be a dependency. Pinning the code hash gives the same guarantee: an unpinned RP could be fooled by a fake "verifier" that returns error code 1 without calling `require_auth`.
- **Why the message is in the arguments, not a hash.** What the wallet displays is exactly what is authorized, with no need for a separate descriptor or registry.
- **Why a map, not a fixed struct.** Later versions can add optional keys without a new Wasm, so the pinned hash stays valid.
- **Anchored, on-chain proofs are out of scope.** Any contract that requires the account's authorization and emits an event provides them. A future SEP may standardize that event.
- **An RP-bound variant** (`verify_message_for(account, rp, msg)`, requiring both authorizations and not reverting, as in SEP-45) was considered. It removes the always-fail pattern but loses third-party verifiability; it can be added if reviewers prefer it. It is the option for applications that need a signature only one RP can use.
- **Key-based verification** (SEP-53 by one signer plus reading the account's signer storage) is rejected: storage layouts differ per implementation and thresholds and policies stay invisible.

## Security Concerns

A longer threat model, with test coverage and the reference implementation's known gaps, is in [THREAT-MODEL.md](https://github.com/sayweer/c-sign/blob/main/docs/THREAT-MODEL.md).

- **Who can sign.** Any signer set or policy the account accepts for a call to `verify_message` can sign messages for it. On OpenZeppelin accounts that includes every `Default` context rule whose policies do not check the function name (threshold policies, for example), so session keys, agent keys and recovery signers on such rules can sign as the account. A rule whose policies need no signature lets anyone sign if they accept the call. An RP cannot tell which rule was used; §5 items 6 and 7 are the wallet's side. A policy meant to stop a key from signing messages has to match the function name, not a verifier address, because any instance of the reference Wasm is accepted.
- **Bearer credential.** Whoever holds a signature can verify it, any number of times, for as long as the account's rules accept it. This includes a contract on-chain that calls the verifier with `try_call`, catches error 1 and acts on the result. The verifier's call is rolled back each time, so the account's state and nonce are unchanged. `domain` and `nonce` protect only RPs that check them. Every holder learns the account, `domain` and `statement` and can publish them, so RPs should not log or publish the signatures they receive.
- **Forged verifier.** Mitigated by hash pinning (§5 item 3, §6 step 5).
- **Cross-site phishing.** Mitigated by the wallet writing `domain` from the requesting origin and the RP checking it. The binding is only as strong as the signing wallet: it fails if a wallet signs these entries through a generic path, and it does not hold for a wallet embedded in the requesting application, which can sign for any `domain`.
- **Replay** across accounts (V2 credentials and the `account` argument), networks (network id in the preimage), relying parties (`domain`) and time (`msg.nonce`, `expiration_time`, `signature_expiration_ledger`). The entry's own nonce gives no replay protection: the host rolls it back whenever the verifier call runs, so only the account can consume it. The account can revoke a signature by spending the same nonce in a successful call whose `signature_expiration_ledger` is not lower than the signature's; the host keeps a spent nonce only until that ledger.
- **Blind signing.** The message is displayed from the signed entry; entries with sub-invocations or unknown keys are refused. Passkeys and hardware signers see only a digest, so display and verifier recognition rest on wallet software.
- **RPC trust.** Verification trusts the RPC that runs the simulation, as ERC-1271 trusts `eth_call`. A lagging RPC can report `valid` for a signer removed a few ledgers earlier (see §6 step 6).
- **Current-state semantics.** A signature stops verifying after the account's signers or policies change. This supports revocation but not non-repudiation. `issued_at` is chosen by the signer and is not evidence of when a signature was made. An account whose executable is a CAP-85 external reference also changes when the reference's owner publishes new code.
- **Resource limits.** Verification runs the account's `__check_auth`, chosen by whoever presents the signature, on the RP's RPC, up to the network's per-transaction budget (see §6 step 6 on rate limits).

## Limitations

- Signature lifetime is bounded by `max_entry_ttl` (about 180 days on current network settings).
- Accounts that are not deployed yet cannot be verified. A deploy-then-verify wrapper, similar in spirit to EIP-6492, looks feasible and is left for a later version. Such a wrapper must not let the account be the verifier's direct caller: the host authorizes a contract's direct calls without a signature.
- An account whose only rule covering the verifier carries a policy that allows only transfers (for example OpenZeppelin `spending_limit`) cannot sign messages through that rule.

## Open items

- Delegated signers: the shape of supporting entries, how a co-signer's wallet shows the message instead of an opaque `__check_auth` payload, and keyless delegation (GHSA-jpg9-m7w4-c7wc). Excluded from this version; to be designed with the SEP-45 maintainers, who face the same problem ([#1648](https://github.com/stellar/stellar-protocol/issues/1648)).
- Whether stellar-rpc can return the simulation's host error as structured data, so that §6 step 7 need not match error text.

## Implementations

- Reference verifier: [contracts/verifier](https://github.com/sayweer/c-sign/tree/main/contracts/verifier).
- TypeScript library for building, signing and verifying entries: [packages/c-sign](https://github.com/sayweer/c-sign/tree/main/packages/c-sign) (implements v0.0.1; v0.0.2 changes pending).
- Test vectors: [vectors/c-sign-v1.json](https://github.com/sayweer/c-sign/blob/main/vectors/c-sign-v1.json) (message encoding, entries, signature payloads, OpenZeppelin signing for 0.7.x and 0.8.0, structural rejections).
- Testnet experiments: [EXPERIMENTS.md](https://github.com/sayweer/c-sign/blob/main/docs/EXPERIMENTS.md).

## Changelog

- `v0.0.2`: §4 item 5 describes the OpenZeppelin auth digest of stellar-accounts 0.7.x and 0.8.0. After a threat model: `valid` means the account's rules accept the call, signatures are bearer credentials and delegated signers are out of scope; wallet requirements cover origin sources, generic signing paths and message-signing rules; `domain`, characters, entry size, `inconclusive`, error matching, clock skew, Wasm-only verifier executables (CAP-85) and third-party verification are specified.
- `v0.0.1`: Initial draft.
