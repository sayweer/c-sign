#![cfg(test)]
extern crate std;

use super::*;
use soroban_sdk::{
    testutils::{Address as _, MockAuth, MockAuthInvoke},
    Env, IntoVal, Map, String, Symbol, Val,
};

fn sample(env: &Env) -> Map<Symbol, Val> {
    let mut msg = Map::new(env);
    msg.set(Symbol::new(env, "domain"), String::from_str(env, "vote.example.com").into_val(env));
    msg.set(Symbol::new(env, "issued_at"), 1_759_000_000u64.into_val(env));
    msg.set(Symbol::new(env, "nonce"), String::from_str(env, "8f3a1c2b9d7e4a60").into_val(env));
    msg.set(Symbol::new(env, "statement"), String::from_str(env, "Proposal #12 = YES").into_val(env));
    msg.set(Symbol::new(env, "version"), String::from_str(env, "1").into_val(env));
    msg
}

/// The account authorizes exactly `verify_message(account, msg)` on this
/// contract, with no sub-invocations. This is the shape of a C-Sign signature.
fn authorize(env: &Env, verifier: &Address, account: &Address, msg: &Map<Symbol, Val>) {
    env.mock_auths(&[MockAuth {
        address: account,
        invoke: &MockAuthInvoke {
            contract: verifier,
            fn_name: "verify_message",
            args: (account.clone(), msg.clone()).into_val(env),
            sub_invokes: &[],
        },
    }]);
}

#[test]
fn fails_with_auth_ok_when_account_authorizes_exact_call() {
    let env = Env::default();
    let id = env.register(Verifier, ());
    let client = VerifierClient::new(&env, &id);
    let account = Address::generate(&env);
    let msg = sample(&env);

    authorize(&env, &id, &account, &msg);

    assert_eq!(client.try_verify_message(&account, &msg), Err(Ok(Error::AuthOk)));
}

#[test]
fn rejects_tampered_message() {
    let env = Env::default();
    let id = env.register(Verifier, ());
    let client = VerifierClient::new(&env, &id);
    let account = Address::generate(&env);
    let signed = sample(&env);

    authorize(&env, &id, &account, &signed);

    let mut tampered = signed.clone();
    tampered.set(
        Symbol::new(&env, "statement"),
        String::from_str(&env, "Proposal #12 = NO").into_val(&env),
    );

    // The authorization covers the exact arguments: a different message is an
    // auth failure (host error), never the reserved `AuthOk` contract error.
    assert!(matches!(client.try_verify_message(&account, &tampered), Err(Err(_))));
}

#[test]
fn rejects_signature_for_another_account() {
    let env = Env::default();
    let id = env.register(Verifier, ());
    let client = VerifierClient::new(&env, &id);
    let signer = Address::generate(&env);
    let other = Address::generate(&env);
    let msg = sample(&env);

    authorize(&env, &id, &signer, &msg);

    assert!(matches!(client.try_verify_message(&other, &msg), Err(Err(_))));
}

#[test]
fn rejects_when_account_does_not_authorize() {
    let env = Env::default();
    let id = env.register(Verifier, ());
    let client = VerifierClient::new(&env, &id);
    let account = Address::generate(&env);

    assert!(matches!(client.try_verify_message(&account, &sample(&env)), Err(Err(_))));
}

#[test]
fn is_agnostic_to_message_keys() {
    // New optional keys defined by later versions of the specification do not
    // need a new Wasm: the contract never reads the message.
    let env = Env::default();
    let id = env.register(Verifier, ());
    let client = VerifierClient::new(&env, &id);
    let account = Address::generate(&env);
    let mut msg = sample(&env);
    msg.set(Symbol::new(&env, "uri"), String::from_str(&env, "https://vote.example.com/12").into_val(&env));
    msg.set(Symbol::new(&env, "expiration_time"), 1_759_003_600u64.into_val(&env));

    authorize(&env, &id, &account, &msg);

    assert_eq!(client.try_verify_message(&account, &msg), Err(Ok(Error::AuthOk)));
}
