#![no_std]
//! `sep53c-verifier`: the canonical, admin-less, storage-less verifier contract
//! for C-Sign, a SEP-53 profile for contract (C-address) accounts.
//!
//! A C-Sign signature is a `SorobanAuthorizationEntry` whose root invocation is
//! `verify_message(account, msg)` (ephemeral mode) or `anchor_message(account, msg)`
//! (anchored mode) on this contract, with no sub-invocations. The account's own
//! `__check_auth` decides validity, so existing smart accounts need no upgrade.

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, xdr::ToXdr, Address,
    Bytes, BytesN, Env, String,
};

/// A human-readable message. Wallets display it as-is; nothing is signed blind.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedMessage {
    /// Relying-party domain, e.g. `vote.example.com`.
    pub domain: String,
    /// What the user agrees to, e.g. `Proposal #12 = YES`.
    pub statement: String,
    /// One-time challenge chosen by the relying party (off-chain replay protection).
    pub challenge: Bytes,
    /// Unix time (seconds) at which the message was issued.
    pub issued_at: u64,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    /// Reserved code that `verify_message` returns once authorization succeeded.
    /// Off-chain verifiers treat *only* this code as "signature valid".
    AuthOk = 1,
}

/// Emitted by `anchor_message`. Topics: `["anchored", account]`. Data: `sha256(xdr(msg))`.
#[contractevent(topics = ["anchored"], data_format = "single-value")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Anchored {
    #[topic]
    pub account: Address,
    pub message_hash: BytesN<32>,
}

#[contract]
pub struct Verifier;

#[contractimpl]
impl Verifier {
    /// Ephemeral mode.
    ///
    /// Runs the account's `__check_auth` for the invocation
    /// `verify_message(account, msg)` and then always fails with [`Error::AuthOk`].
    /// Because the call never succeeds, submitting a published signature on-chain
    /// fails the transaction and does not consume the nonce. The signature stays
    /// valid for off-chain verification through enforcing simulation.
    pub fn verify_message(_env: Env, account: Address, msg: SignedMessage) -> Result<(), Error> {
        // `msg` is part of the authorized arguments; it needs no further handling here.
        let _ = msg;
        account.require_auth();
        Err(Error::AuthOk)
    }

    /// Anchored mode.
    ///
    /// Runs the account's `__check_auth`, then publishes the event
    /// `("anchored", account) -> sha256(xdr(msg))` as a durable on-chain proof
    /// and returns that hash.
    pub fn anchor_message(env: Env, account: Address, msg: SignedMessage) -> BytesN<32> {
        account.require_auth();
        let hash: BytesN<32> = env.crypto().sha256(&msg.to_xdr(&env)).to_bytes();
        Anchored {
            account,
            message_hash: hash.clone(),
        }
        .publish(&env);
        hash
    }
}

#[cfg(test)]
mod test;
