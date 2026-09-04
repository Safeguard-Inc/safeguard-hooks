//! Cross-contract invocation of the external policy contract.
//!
//! The policy contract is deployed and maintained by the `safeguard-policy`
//! polyrepo; this module knows only its interface (see the crate docs).
//! Because the policy is not compiled into this workspace, the call is made
//! by raw `Symbol` invocation rather than a generated client.

use soroban_sdk::{Address, Env, Error, IntoVal, Symbol};

use safeguard_hook_core::RejectionReason;

/// The policy function this crate calls. Public contract between
/// `safeguard-hooks` and `safeguard-policy` — do not rename.
pub const POLICY_FN: &str = "is_authorized";

/// A handle for screening parties against a configured policy contract.
///
/// Cheap to construct per evaluation; it exists so callers name the policy
/// once and do not thread the address through every screen.
#[derive(Clone, Debug)]
pub struct PolicyClient {
    address: Address,
}

impl PolicyClient {
    /// Names the policy contract a hook evaluation should consult.
    pub fn new(address: &Address) -> Self {
        PolicyClient {
            address: address.clone(),
        }
    }

    /// The policy contract address this client calls.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Screens `account` on `token` against the policy.
    ///
    /// See the crate docs for the exact semantics; a failed or malformed
    /// policy answer is reported as [`RejectionReason::PolicyUnavailable`]
    /// so the caller can fail closed.
    pub fn is_authorized(
        &self,
        e: &Env,
        account: &Address,
        token: &Address,
    ) -> Result<bool, RejectionReason> {
        is_authorized(e, &self.address, account, token)
    }
}

/// Screens `account` on `token` against the policy at `policy_address`.
///
/// `Ok(true)` means authorized, `Ok(false)` means denied, and
/// `Err(RejectionReason::PolicyUnavailable)` means the policy could not be
/// evaluated (reverted, missing, or returned a non-boolean).
pub fn is_authorized(
    e: &Env,
    policy_address: &Address,
    account: &Address,
    token: &Address,
) -> Result<bool, RejectionReason> {
    let func = Symbol::new(e, POLICY_FN);
    let args = (account.clone(), token.clone()).into_val(e);

    match e.try_invoke_contract::<bool, Error>(policy_address, &func, args) {
        Ok(Ok(authorized)) => Ok(authorized),
        // The policy answered but the value was not a boolean: treat it as
        // an unusable policy rather than guessing at intent.
        Ok(Err(_)) => Err(RejectionReason::PolicyUnavailable),
        // The policy reverted or could not be reached at all.
        Err(_) => Err(RejectionReason::PolicyUnavailable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{Address as _, EnvTestConfig};
    use soroban_sdk::{contract, contractimpl, symbol_short};

    /// A minimal policy implementing the cross-repo wire contract: an account
    /// is authorized only when it matches the configured `allowed` account on
    /// the configured `token`. Proves both arguments reach the policy.
    #[contract]
    struct WhitelistPolicy;

    #[contractimpl]
    impl WhitelistPolicy {
        pub fn __constructor(e: Env, allowed: Address, token: Address) {
            e.storage().instance().set(&symbol_short!("acct"), &allowed);
            e.storage().instance().set(&symbol_short!("tokn"), &token);
        }

        pub fn is_authorized(e: Env, account: Address, token: Address) -> bool {
            let allowed: Address = e.storage().instance().get(&symbol_short!("acct")).unwrap();
            let bound: Address = e.storage().instance().get(&symbol_short!("tokn")).unwrap();
            account == allowed && token == bound
        }
    }

    /// A policy that always reverts: models an unavailable or broken policy
    /// contract, which enforcement must treat as a rejection.
    #[contract]
    struct RevertingPolicy;

    #[contractimpl]
    impl RevertingPolicy {
        pub fn is_authorized(_e: Env, _account: Address, _token: Address) -> bool {
            panic!("policy unavailable")
        }
    }

    fn policy_env() -> Env {
        Env::new_with_config(EnvTestConfig {
            capture_snapshot_at_drop: false,
        })
    }

    #[test]
    fn authorized_account_returns_true() {
        let e = policy_env();
        let alice = Address::generate(&e);
        let token = Address::generate(&e);

        let policy = e.register(WhitelistPolicy, (&alice, &token));
        let client = PolicyClient::new(&policy);

        assert_eq!(client.is_authorized(&e, &alice, &token), Ok(true));
    }

    #[test]
    fn non_whitelisted_account_returns_false() {
        let e = policy_env();
        let alice = Address::generate(&e);
        let bob = Address::generate(&e);
        let token = Address::generate(&e);

        let policy = e.register(WhitelistPolicy, (&alice, &token));
        let client = PolicyClient::new(&policy);

        // Bob is not whitelisted: the policy answers "no".
        assert_eq!(client.is_authorized(&e, &bob, &token), Ok(false));
    }

    #[test]
    fn token_is_passed_through_to_the_policy() {
        let e = policy_env();
        let alice = Address::generate(&e);
        let token_a = Address::generate(&e);
        let token_b = Address::generate(&e);

        // Alice is whitelisted on Token A only.
        let policy = e.register(WhitelistPolicy, (&alice, &token_a));
        let client = PolicyClient::new(&policy);

        assert_eq!(client.is_authorized(&e, &alice, &token_a), Ok(true));
        // The same account on a different token must not inherit the
        // decision — the token argument really reaches the policy.
        assert_eq!(client.is_authorized(&e, &alice, &token_b), Ok(false));
    }

    #[test]
    fn reverting_policy_is_reported_unavailable() {
        let e = policy_env();
        let alice = Address::generate(&e);
        let token = Address::generate(&e);

        let policy = e.register(RevertingPolicy, ());
        let client = PolicyClient::new(&policy);

        // A policy that reverts must never look like a denial or an
        // approval — it is reported unavailable and the hook fails closed.
        assert_eq!(
            client.is_authorized(&e, &alice, &token),
            Err(RejectionReason::PolicyUnavailable)
        );
    }

    #[test]
    fn missing_policy_contract_is_reported_unavailable() {
        let e = policy_env();
        let alice = Address::generate(&e);
        let token = Address::generate(&e);
        let ghost = Address::generate(&e);

        // No contract is registered at `ghost`: the call cannot succeed.
        assert_eq!(
            is_authorized(&e, &ghost, &alice, &token),
            Err(RejectionReason::PolicyUnavailable)
        );
    }

    #[test]
    fn client_and_free_function_agree() {
        let e = policy_env();
        let alice = Address::generate(&e);
        let token = Address::generate(&e);

        let policy = e.register(WhitelistPolicy, (&alice, &token));
        assert_eq!(
            is_authorized(&e, &policy, &alice, &token),
            PolicyClient::new(&policy).is_authorized(&e, &alice, &token)
        );
    }
}
