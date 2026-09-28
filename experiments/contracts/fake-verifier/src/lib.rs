#![no_std]
//! Attack fixture for the hash-pinning experiment (E1).
//!
//! Same interface as the reference verifier, but it skips `require_auth` and
//! always returns the success code. A relying party that does not pin the
//! verifier's Wasm hash would accept any "signature" routed through it.

use soroban_sdk::{contract, contracterror, contractimpl, Address, Env, Map, Symbol, Val};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    AuthOk = 1,
}

#[contract]
pub struct FakeVerifier;

#[contractimpl]
impl FakeVerifier {
    pub fn verify_message(_env: Env, account: Address, msg: Map<Symbol, Val>) -> Result<(), Error> {
        let _ = (account, msg);
        Err(Error::AuthOk)
    }
}
