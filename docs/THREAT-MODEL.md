# C-Sign threat model

This document covers [SPEC.md](SPEC.md) version 0.0.2, the reference verifier with Wasm hash `2a5004a7…c299`, the TypeScript library `packages/c-sign` 0.1.0 and the passkey demo in `apps/demo`, as of 23 October 2026. It is a design review backed by testnet experiments and offline tests, not an audit. Section numbers (§) refer to the specification.

## Scope and assets

C-Sign lets a contract account sign a message as an authorization entry for `verify_message(account, msg)` on an instance of a verifier that always fails, and lets a relying party (RP) check it with an enforcing simulation. The threat model protects:

- The account's identity at RPs: nobody should sign in as the account, or make it appear to agree to a statement, without the account's authorization logic accepting it.
- The integrity of what was agreed: the `statement`, `domain` and other fields the user approved are the ones that verify.
- The account's on-chain state: a message signature must never change the account's state or consume its authorization nonce.
- RP availability: verifying an untrusted signature should not cost the RP more than a bounded simulation.

Adversaries considered: a phishing site; anyone who holds a signature (an RP, a log reader, another contract); a holder of a narrow-purpose key on the account (session key, agent key, recovery signer, co-signer); the author of a malicious account contract presenting signatures to an RP; text that reaches an agent that signs (prompt injection); a stale, misconfigured or dishonest RPC; a party that deploys a look-alike verifier.

## Trust assumptions

- Soroban host. The host binds V2 credentials to network, account, nonce, expiry and invocation; rolls back the storage of a failed call frame, including the authorization nonce written there; converts recoverable errors raised inside `__check_auth` to `Error(Auth, InvalidAction)`; and sets the contract id of events itself.
- RPC. The RPC used for verification serves the expected network, is close to the network tip, runs the protocol's current host, returns diagnostic events in simulation results (`preflight-enable-debug`), and reports the simulation honestly. Verification trusts it the way ERC-1271 trusts `eth_call`.
- Verifier Wasm hash. Trust in a verifier instance rests only on its executable being `CONTRACT_EXECUTABLE_WASM` with a hash listed in the SEP. The build is reproducible with the toolchain named in §3, including the exact stellar-cli commit embedded in the Wasm metadata. The hash constant shipped in the library is a convenience; the SEP text is the source.
- Wallet. The wallet writes `domain` from the platform-reported origin, displays fields decoded from the entry it signs, recognises the verifier through its own RPC, and signs these entries only through a message-signing request (§5). Passkeys and hardware signers see only a digest, so this is a software trust assumption.
- Account. The account's `__check_auth` checks signatures over the payload the host gives it, and the owner understands which rules and signers it has configured.
- RP. The RP knows its own domains from configuration, issues and consumes nonces, and fails closed.

## What a `valid` result means

`valid` means: at the ledger the simulation ran on, through that RPC, the account's authorization logic accepted the presented credentials for this exact call to this pinned verifier instance. When the RP also ran the checks of §6 step 4 and step 8, the message was addressed to this RP and has not been used before.

It does not mean:

- That a particular person or key signed. Any signer set or policy that the account accepts for this call can produce it, including session keys, agent keys and recovery signers on broad rules, and rules whose policies need no signature. The RP cannot see which rule matched.
- That the message was signed at `issued_at`. The signer chooses that value.
- That the signature is private or single-use. It is a bearer credential: anyone who holds it can verify it again, off-chain or from a contract on-chain, for as long as the account's rules accept it.
- That it verified in the past or will verify later. Validity follows current state: signer rotation, policy changes, time- or usage-based policies and account upgrades change the answer.

Only `valid` authenticates. `inconclusive` means the RP could not decide and is never a pass.

## Threats and mitigations

"Where" names the layer that carries the mitigation: the specification (§), the reference library, the wallet, the RP or the host.

| Threat | Mitigation | Where | Residual risk |
|---|---|---|---|
| Look-alike verifier returns error 1 without calling `require_auth`, so anyone "signs" for any account | Pin the instance's executable to an accepted Wasm hash before simulating | §3, §5 item 3, §6 step 5 | An RP that skips pinning, or accepts hashes without reading the SEP list; governance of future hashes and downgrade to older ones is defined only as "a later version says whether earlier hashes remain acceptable" |
| Instance whose executable can be repointed (CAP-85 `EXTERNAL_REF`) shows the reference hash today and a fake tomorrow | Only `CONTRACT_EXECUTABLE_WASM` is accepted and never resolved through a reference; only Wasm pins are cached | §6 step 5, §5 item 3 | None known; CAP-57 would need a re-check of "an instance cannot be replaced" |
| Account contract makes the RP see the verifier's success code | Host converts the account's recoverable errors; `valid` needs the first line to start with `Error(Contract, #1)` and a verifier-scoped error event | §6 step 7, host | Rests on error text that is not a stable RPC interface |
| Replay across accounts, networks or verifier instances | V2 preimage binds network id, address, nonce, expiry and invocation; `account` is also an argument | §4, host | None |
| Phishing site obtains a signature addressed to another site | Wallet writes `domain` from the reported origin; RP compares it exactly with its configured domains | §2, §5 item 1, §6 step 4 | Wallets embedded in the requesting application; origin-less channels (shown as unverified, §5 item 1); any origin that can use a passkey's rpId; wallets that do not implement §5 |
| Phishing site routes a `verify_message` entry through generic auth-entry or transaction signing | Wallets sign these entries only for message-signing requests | §5 item 5 | Wallets that predate this SEP |
| Replay of a sign-in to the same RP | Single-use `msg.nonce`, consumed atomically on `valid` only; challenge lifetime and time checks with at most 60 s skew | §6 steps 4 and 8 | RP implementation |
| Holder of a signature reuses it elsewhere, including a contract that calls the verifier, catches error 1 and records the result | Documented as a bearer credential; `msg` must not carry secrets; RPs should not log or publish signatures; third-party verifiers must check `domain` | §2, §6 (after step 8), Security Concerns | Inherent to third-party verifiability. A signature can reveal the account, `domain` and `statement` to anyone it reaches, and its validity can be probed later. An RP-bound variant is discussed in Design Rationale |
| A published signature is submitted on-chain to burn the account's nonce | The verifier always fails, so the host rolls back the nonce, also under `try_call` | §3, host | None; the account itself can revoke a signature by spending the nonce (intended) |
| A session, agent or recovery key signs in as the account | Wallet checks rule coverage before signing and returns a distinct error if none applies; message rules scoped to the verifier instance and holding only signers allowed to act as the account; deny policies match the function name | §5 items 6 and 7, Security Concerns | The RP cannot tell which rule matched; accounts with broad rules sign through them |
| Policy-only rules let anyone sign | Documented; policy authors must treat `verify_message` like any other function | Security Concerns | Custom policies |
| Display spoofing: bidi, zero-width or control characters, line breaks that fake header lines, a CAIP-122 text inside `statement` that names another domain or nonce | Forbidden code points rejected, not stripped; wallet displays the decoded entry; RPs take values from `msg` and never parse formatted text | §2, §5 item 2, §6 step 4 | Homoglyph domains in A-label form; users who do not read |
| Blind signing on passkeys and hardware signers | Wallet shows the message and checks the verifier before invoking the signer | §5 items 2 and 3 | The authenticator shows nothing about the message |
| Agent is talked into signing for a site of the attacker's choice | `domain` comes from the HTTPS connection, never from model output or tool arguments | §5 item 1 | The agent can still be talked into signing a statement for the real requester; keep agent keys off rules that can sign messages (§5 item 7) |
| Client forces `inconclusive` or loads the RP's RPC with oversized entries | Length limits checked before decoding and before any RPC call; `inconclusive` never authenticates | §2, §6 step 1, §6 | An expensive `__check_auth` still costs up to the per-transaction budget; rate limits per client and per account (§6 step 6) |
| Stale, wrong-network or dishonest RPC | `getNetwork` check, latest ledger at most 30 s old, own RPC or two providers with disagreement as `inconclusive` | §6 step 6 | A lagging RPC can accept a signer removed a few ledgers ago; CAP-77 frozen keys are not applied in simulation; three reads may hit different ledgers on a load-balanced provider |
| RPC omits diagnostic events, so the event check cannot pass | Missing events are `inconclusive` (fail closed); the dependency is stated | Dependencies, §6 step 7 | Availability depends on the operator setting |
| Repudiation, or backdated statements after account takeover | Current-state semantics and the meaning of `issued_at` are stated | Security Concerns | Inherent. Parties that need durable evidence record the verification result with their own timestamp or anchor it on-chain |
| Long-lived signatures widen every window above | Short `signature_expiration_ledger` recommended; RPs reject sign-in entries expiring more than 17280 ledgers ahead | §5 item 4, §6 step 2 | Up to `max_entry_ttl` (about 180 days) for third-party use |
| Entry bytes are malleable (credential type is outside the preimage; account signatures may be re-encodable) | V2 only; replay state keyed on `msg.nonce`, not entry bytes | §4 item 3, §6 step 8 | None known |
| Delegated co-signers sign an opaque `__check_auth` payload that can commit to anything | Delegated signers are out of scope; RPs attach no other entries | §4, Open items | Open item, linked to GHSA-jpg9-m7w4-c7wc and SEP-45 #1648 |
| A future wrapper lets the account call the verifier directly, which the host authorizes without a signature | The verifier is the root of the verification transaction; Limitations require that a wrapper never makes the account the verifier's direct caller | §6 step 6, Limitations | CAP-89 |

## What was tested

Testnet, recorded in [EXPERIMENTS.md](EXPERIMENTS.md) with transaction links and regenerated by `pnpm e2e`:

- P1, P2: an unmodified OpenZeppelin account signs, and two independent verifier instances both work.
- E1a, E1b: a look-alike verifier is accepted without pinning and rejected with it.
- E2a to E2c: a signature submitted on-chain fails and leaves the nonce unused; a verifier that succeeds burns it.
- N1 to N5: tampered statement, other domain, other account, expired entry and reused nonce are `invalid`.
- R1, R2, T1 to T3: results follow signer changes and threshold changes.
- M1, M2, O1 to O3: a minimal non-OpenZeppelin account and an OpenZeppelin stellar-accounts 0.8.0 account verify through the same path; the wrong digest is rejected.
- S1, S2: the host accepts statements near 190 KB; the RPC request cap is what stops verification, so the §2 limits are a display and transport choice.
- L1: latency against a public testnet RPC.

Offline, in a lab kept outside this repository:

- An offline Soroban host test (soroban-sdk 28) with the reference verifier, a minimal account and a contract that calls the verifier and catches its error. The contract recorded the authorization repeatedly, in separate transactions and twice in one, and the account's nonce stayed unused. This is the basis of the bearer-credential text.
- Library decision tests against a scriptable mock RPC, covering type confusion, unsorted, duplicate and unknown keys, invalid UTF-8, error-code prefixes such as `#10`, an account raising its own code 1, and the gaps listed below.
- Read-only testnet probes: a forged signature for a real OpenZeppelin account and a signature for a nonexistent account are `invalid`; oversized credentials make the RPC fail.
- Diagnostic events were present in enforce-mode simulations on four public RPC providers (testnet and mainnet) on 22 October 2026.
- The Wasm hash was reproduced locally, and the library and verifier unit tests pass.
- An inventory traced 85 rules and claims from the specification, README and demo to code and tests. The contradictions it found between the 0.0.1 text and the code are resolved in the 0.0.2 text; where the code still differs, the item is listed below.

Planned: the failing direction of the verifier-event check on testnet, wrapper consumption on testnet, replay with a signer shared between accounts, and the event check across more RPC providers.

## Known gaps in the reference implementation

The specification is the target. The library implements 0.0.1 and the following are planned for library v0.2:

| Area | Current behaviour | v0.0.2 rule |
|---|---|---|
| Sign-in checks | `domain` and the nonce check are optional, and a result without them can still be `valid` | Split the API so a sign-in requires both and an inspection call never reports a sign-in (§6 step 4, §6 after step 8) |
| Input size | No limit on the encoded or decoded entry before decoding | Length limits before decoding, no RPC call (§6 step 1) |
| Characters and `domain` form | Not checked | §2 |
| Time | Default skew of 300 s, also added to the challenge lifetime; vectors encode that window | At most 60 s, not added (§6 step 4) |
| Expiration | No sign-in upper bound | 17280 ledgers for sign-in (§6 step 2) |
| Network and RPC | Network passphrase not checked against the RPC; pin cache keyed by the declared passphrase; latest-ledger age not checked; plain `http` RPC accepted without an explicit opt-in | §6 step 6; cache per network id |
| Missing verifier instance | `inconclusive` | `invalid` (§6 step 5) |
| Decision | `invalid` found by searching the whole error text | First line only (§6 step 7) |
| Nonce | Checked before pinning and simulation, consumption left to the caller, no atomic consume; a throwing callback makes `verifyMessage` throw | Consume on `valid` only, atomically (§6 step 8) |
| Wallet side | No validator for entries received from an application; the OpenZeppelin signing helper signs any entry | §5 items 3 and 5 |

Interoperability: smart-account-kit 0.8.0 still signs the pre-0.8 digest, so passkey signatures through it do not verify for stellar-accounts 0.8.0 accounts until the kit is updated. The library signs both digests.

The demo is a testnet showcase, not a template for production RPs. Its known gaps, to be fixed before it is presented as an integration example: the RP does not take its domain from fixed configuration; nonce and rate-limit state live in memory per serverless instance; the verify endpoint has no CSRF protection and does not check the statement; the sponsoring relay does not limit what it pays for; and the wallet sheet displays the application's copy of the message instead of the decoded entry and allows signing while the verifier check is pending. Its passkeys use the demo's own rpId, so the demo is an embedded wallet in the sense of Security Concerns.

## Protocol changes to watch

- CAP-89 (Draft): invoker-less authorization. It does not change `require_auth`, but a v2 verifier could use `require_auth_no_invoker` so that direct-caller authorization can never produce a result. A new verifier means a new hash.
- CAP-85 (Final, protocol 28): handled by the Wasm-only rule.
- CAP-57 (Draft): full eviction and recreation of entries would require re-checking instance immutability and pin caching.
- CAP-84 (Accepted): muxed contract addresses; RPs should reject muxed strkeys for `address`.
- CAP-72 (Draft): contract signers for `G…` accounts would make a `G…` variant of this SEP meaningful.
- CAP-71 delegation: needs `SOROBAN_CREDENTIALS_ADDRESS_WITH_DELEGATES`, excluded today.
- The simulation error string and the `events` field are not a stable API, and the `preflight-enable-debug` default could change. Changes fail closed (`inconclusive`). The testnet experiments should be re-run after each protocol and stellar-rpc major upgrade.

## Out of scope

- Bugs in account implementations, including `__check_auth` that does not check what it signs.
- Compromise of the user's device, browser, wallet software or keys.
- What an RP does after sign-in (sessions, authorization, account linking).
- Delegated signers and accounts that are not yet deployed (Open items, Limitations).
- `G…` accounts, covered by SEP-53.
- Anchored on-chain proofs and legal non-repudiation.
- Confidentiality of `msg`, which is public by design.
