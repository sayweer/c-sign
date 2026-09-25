#![cfg(test)]
extern crate std;

use super::*;
use soroban_sdk::{
    testutils::{Address as _, Events as _, MockAuth, MockAuthInvoke},
    Bytes, Env, Event as _, IntoVal, String,
};

fn sample(env: &Env) -> SignedMessage {
    SignedMessage {
        domain: String::from_str(env, "vote.example.com"),
        statement: String::from_str(env, "Proposal #12 = YES"),
        challenge: Bytes::from_array(env, &[7u8; 32]),
        issued_at: 1_759_000_000,
    }
}

/// The account authorizes exactly `verify_message(account, msg)` on this contract,
/// with no sub-invocations. This is the shape of a C-Sign signature.
fn authorize_verify(env: &Env, verifier: &Address, account: &Address, msg: &SignedMessage) {
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
fn verify_message_fails_with_auth_ok_when_account_authorizes_exact_call() {
    let env = Env::default();
    let id = env.register(Verifier, ());
    let client = VerifierClient::new(&env, &id);
    let account = Address::generate(&env);
    let msg = sample(&env);

    authorize_verify(&env, &id, &account, &msg);

    // Authorization passed, then the call failed with the reserved code.
    let res = client.try_verify_message(&account, &msg);
    assert_eq!(res, Err(Ok(Error::AuthOk)));
}

#[test]
fn verify_message_rejects_tampered_message() {
    let env = Env::default();
    let id = env.register(Verifier, ());
    let client = VerifierClient::new(&env, &id);
    let account = Address::generate(&env);
    let signed = sample(&env);

    authorize_verify(&env, &id, &account, &signed);

    let mut tampered = signed.clone();
    tampered.statement = String::from_str(&env, "Proposal #12 = NO");

    // The authorization is bound to the signed arguments: a different message
    // is an auth failure (host error), never the reserved `AuthOk` code.
    let res = client.try_verify_message(&account, &tampered);
    assert!(matches!(res, Err(Err(_))));
}

#[test]
fn verify_message_rejects_when_account_does_not_authorize() {
    let env = Env::default();
    // No mocked auths: the account never authorizes the call.
    let id = env.register(Verifier, ());
    let client = VerifierClient::new(&env, &id);
    let account = Address::generate(&env);

    let res = client.try_verify_message(&account, &sample(&env));
    assert!(matches!(res, Err(Err(_))));
}

#[test]
fn anchor_message_emits_event_with_message_hash() {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register(Verifier, ());
    let client = VerifierClient::new(&env, &id);
    let account = Address::generate(&env);
    let msg = sample(&env);

    let hash = client.anchor_message(&account, &msg);
    let expected: BytesN<32> = env.crypto().sha256(&msg.clone().to_xdr(&env)).to_bytes();
    assert_eq!(hash, expected);

    // Exactly one event: topics ["anchored", account], data = sha256(xdr(msg)).
    assert_eq!(
        env.events().all(),
        [Anchored {
            account: account.clone(),
            message_hash: expected,
        }
        .to_xdr(&env, &id)]
    );
}

#[test]
fn anchor_message_rejects_when_account_does_not_authorize() {
    let env = Env::default();
    let id = env.register(Verifier, ());
    let client = VerifierClient::new(&env, &id);
    let account = Address::generate(&env);

    assert!(client.try_anchor_message(&account, &sample(&env)).is_err());
}
