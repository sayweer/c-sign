#![no_std]
//! Minimal contract account for the experiments (M1, M2).
//!
//! One Ed25519 key, set at deployment. `__check_auth` verifies a 64-byte
//! signature over the raw signature payload, with no context rules or
//! policies. C-Sign verification does not depend on this format: the account
//! decides, by simulation.

use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contracterror, contractimpl, contracttype,
    crypto::Hash,
    BytesN, Env, Vec,
};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
}

#[contracttype]
enum DataKey {
    PublicKey,
}

#[contract]
pub struct Ed25519Account;

#[contractimpl]
impl Ed25519Account {
    pub fn __constructor(env: Env, public_key: BytesN<32>) {
        env.storage().instance().set(&DataKey::PublicKey, &public_key);
    }
}

#[contractimpl]
impl CustomAccountInterface for Ed25519Account {
    type Error = Error;
    type Signature = BytesN<64>;

    fn __check_auth(env: Env, signature_payload: Hash<32>, signature: BytesN<64>, _contexts: Vec<Context>) -> Result<(), Error> {
        let public_key: BytesN<32> = env.storage().instance().get(&DataKey::PublicKey).ok_or(Error::NotInitialized)?;
        // Traps on a bad signature; the host reports it as an authorization failure.
        env.crypto().ed25519_verify(&public_key, &signature_payload.into(), &signature);
        Ok(())
    }
}
