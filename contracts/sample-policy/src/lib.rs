#![no_std]

//! # sample-policy
//!
//! A **sample** policy contract: the smallest possible implementation of
//! the `safeguard-policy` wire contract that `safeguard-hooks` calls.
//!
//! ```text
//!                      Safeguard Hooks
//!                             │
//!        try_invoke_contract  │  is_authorized(account, token) → bool
//!                             ▼
//!                   sample-policy (this contract)
//! ```
//!
//! The wire contract is deliberately tiny — one function:
//!
//! ```ignore
//! pub fn is_authorized(e: Env, account: Address, token: Address) -> bool
//! ```
//!
//! * `account` — the party the hooks layer is screening;
//! * `token` — the bound token the operation concerns, so a single policy
//!   deployment can apply per-token rules;
//! * returns `true` when the account may transact on that token.
//!
//! A revert counts as a denial: `safeguard-policy-client` treats an
//! unevaluable call as `PolicyUnavailable` and the operation fails closed.
//!
//! ## What this contract is *not*
//!
//! This is a demo/deny-list stand-in for the `safeguard-policy` polyrepo
//! (DEFINE). It holds no registries, no jurisdictions, no sanctions data,
//! and no identity verification. Its only job is to let the local-network
//! integration suite (and a human demoing the stack) run the full
//! ENFORCE path — deploy hooks, bind a token, freeze an account, and watch
//! a policy denial revert a real transaction — without deploying the real
//! policy system. The real registry lives in `safeguard-policy`.

use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

/// Storage key for the blocked account (deny-list target).
const BLOCKED: soroban_sdk::Symbol = symbol_short!("blkd");

/// Sample deny-list policy. Constructor pins the single blocked account;
/// `None` allows everyone (the allow-all configuration).
#[contract]
pub struct SamplePolicy;

#[contractimpl]
impl SamplePolicy {
    /// Records the blocked account. `blocked: None` is an allow-all policy;
    /// `blocked: Some(account)` denies that account on every token this
    /// policy is consulted about.
    pub fn __constructor(e: Env, blocked: Option<Address>) {
        e.storage().instance().set(&BLOCKED, &blocked);
    }

    /// The `safeguard-policy` wire contract: whether `account` may transact
    /// on `token`. This sample ignores `token` (the deny-list applies
    /// everywhere); a real policy keys its rules off both arguments.
    pub fn is_authorized(e: Env, account: Address, _token: Address) -> bool {
        let blocked: Option<Address> = e.storage().instance().get(&BLOCKED).unwrap();
        Some(account) != blocked
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{Address as _, EnvTestConfig};

    fn host(blocked: Option<&Address>) -> (Env, Address) {
        let e = Env::new_with_config(EnvTestConfig {
            capture_snapshot_at_drop: false,
        });
        let contract = e.register(SamplePolicy, (blocked.cloned(),));
        (e, contract)
    }

    #[test]
    fn allow_all_configuration_authorizes_everyone() {
        let (e, contract) = host(None);
        let client = SamplePolicyClient::new(&e, &contract);
        let token = Address::generate(&e);

        for _ in 0..3 {
            assert!(client.is_authorized(&Address::generate(&e), &token));
        }
    }

    #[test]
    fn deny_list_configuration_blocks_only_the_pinned_account() {
        let (e, contract) = host(None);
        let blocked = Address::generate(&e);
        let token = Address::generate(&e);
        let other = Address::generate(&e);
        let client = SamplePolicyClient::new(&e, &contract);

        // Re-deploy the policy pinned to `blocked` on the same env.
        let deny = e.register(SamplePolicy, (Some(blocked.clone()),));
        let deny_client = SamplePolicyClient::new(&e, &deny);

        assert!(!deny_client.is_authorized(&blocked, &token));
        assert!(deny_client.is_authorized(&other, &token));
        // The allow-all instance still authorizes everyone.
        assert!(client.is_authorized(&blocked, &token));
    }
}
