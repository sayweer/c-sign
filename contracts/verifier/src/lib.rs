#![no_std]
//! `sep53c-verifier`: the reference verifier contract for C-Sign, "Signed
//! Messages for Contract Accounts".
//!
//! A C-Sign signature is a `SorobanAuthorizationEntry` whose root invocation is
//! `verify_message(account, msg)` on an instance of this contract, with no
//! sub-invocations and V2 address credentials. The account's own `__check_auth`
//! decides validity, so existing contract accounts need no upgrade.
//!
//! There is no canonical instance. Anyone may deploy this Wasm; wallets and
//! relying parties trust an instance only after checking that its executable
//! Wasm hash equals the hash published with the specification. The contract has
//! no admin, no storage and no upgrade path, so that check is done once per
//! instance.

use soroban_sdk::{contract, contracterror, contractimpl, Address, Env, Map, Symbol, Val};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    /// Returned by `verify_message` once authorization succeeded. Off-chain
    /// verifiers treat only this error, raised by a pinned verifier instance,
    /// as "signature valid".
    AuthOk = 1,
}

#[contract]
pub struct Verifier;

#[contractimpl]
impl Verifier {
    /// Runs the account's `__check_auth` for the invocation
    /// `verify_message(account, msg)` and then always fails with
    /// [`Error::AuthOk`].
    ///
    /// `msg` is the human-readable message as a symbol-keyed map. Its keys are
    /// defined by the specification, not by this contract: the contract never
    /// reads it, so new optional keys never change this Wasm or its hash. `msg`
    /// is still part of the authorized arguments, so the signature covers it.
    ///
    /// Because the call never succeeds, a published signature submitted
    /// on-chain fails the transaction, the host rolls the nonce back, and the
    /// signature stays verifiable off-chain through enforcing simulation.
    pub fn verify_message(_env: Env, account: Address, msg: Map<Symbol, Val>) -> Result<(), Error> {
        let _ = msg;
        account.require_auth();
        Err(Error::AuthOk)
    }
}

#[cfg(test)]
mod test;
