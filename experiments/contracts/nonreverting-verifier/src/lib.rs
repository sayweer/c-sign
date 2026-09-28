#![no_std]
//! Comparison fixture for the nonce experiment (E2).
//!
//! Same interface as the reference verifier, but it returns `Ok(())` after
//! `require_auth`. A signature submitted on-chain therefore succeeds and burns
//! its nonce, which is exactly what the reference verifier's always-fail design
//! avoids.

use soroban_sdk::{contract, contractimpl, Address, Env, Map, Symbol, Val};

#[contract]
pub struct NonRevertingVerifier;

#[contractimpl]
impl NonRevertingVerifier {
    pub fn verify_message(_env: Env, account: Address, msg: Map<Symbol, Val>) {
        let _ = msg;
        account.require_auth();
    }
}
