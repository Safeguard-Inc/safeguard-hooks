//! The underlying Stellar Asset Contract `authorized()` view.
//!
//! When a bound token wraps a SAC and the deployment enables
//! `sac_passthrough`, every gated operation additionally consults the SAC's
//! standardized `authorized(account)` view for fund-holding parties. This
//! composes the enforcement layer's freeze with the *issuer's* own
//! freeze/deauthorize (driven through the SAC's `set_authorized`) without
//! mirroring any state — the transitive-compliance pattern from the
//! OpenZeppelin confidential-token compliance design.
//!
//! Like the policy gate, the SAC check fails closed: a SAC that reverts or
//! cannot be reached denies the party, because the operation could not be
//! verified.

use soroban_sdk::{Address, Env, Error, IntoVal, Symbol};

use safeguard_hook_core::RejectionReason;

/// The SEP-41 `authorized` view on a Stellar Asset Contract.
pub const SAC_AUTHORIZED_FN: &str = "authorized";

/// Returns whether `account` is authorized to hold the asset on `sac`.
///
/// * `Ok(true)` — the SAC says the account is authorized.
/// * `Ok(false)` — the SAC says the account is not authorized.
/// * `Err(SacAuthorizationFailed)` — the SAC could not be reached or its
///   answer was not a boolean.
pub fn is_authorized(e: &Env, sac: &Address, account: &Address) -> Result<bool, RejectionReason> {
    let func = Symbol::new(e, SAC_AUTHORIZED_FN);
    let args = (account.clone(),).into_val(e);

    match e.try_invoke_contract::<bool, Error>(sac, &func, args) {
        Ok(Ok(authorized)) => Ok(authorized),
        Ok(Err(_)) | Err(_) => Err(RejectionReason::SacAuthorizationFailed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{Address as _, EnvTestConfig};
    use soroban_sdk::{contract, contractimpl, symbol_short};

    /// A minimal SAC implementing the SEP-41 `authorized` view for the
    /// accounts listed at construction.
    #[contract]
    struct MockSac;

    #[contractimpl]
    impl MockSac {
        pub fn __constructor(e: Env, authorized_account: Address) {
            e.storage()
                .instance()
                .set(&symbol_short!("auth"), &authorized_account);
        }

        pub fn authorized(e: Env, id: Address) -> bool {
            let authorized: Address = e.storage().instance().get(&symbol_short!("auth")).unwrap();
            id == authorized
        }
    }

    /// A SAC whose `authorized` view always reverts.
    #[contract]
    struct RevertingSac;

    #[contractimpl]
    impl RevertingSac {
        pub fn authorized(_e: Env, _id: Address) -> bool {
            panic!("sac unavailable")
        }
    }

    fn sac_env() -> Env {
        Env::new_with_config(EnvTestConfig {
            capture_snapshot_at_drop: false,
        })
    }

    #[test]
    fn authorized_account_passes() {
        let e = sac_env();
        let alice = Address::generate(&e);
        let sac = e.register(MockSac, (&alice,));

        assert_eq!(is_authorized(&e, &sac, &alice), Ok(true));
        assert_eq!(is_authorized(&e, &sac, &Address::generate(&e)), Ok(false));
    }

    #[test]
    fn reverting_sac_fails_closed() {
        let e = sac_env();
        let alice = Address::generate(&e);
        let sac = e.register(RevertingSac, ());

        assert_eq!(
            is_authorized(&e, &sac, &alice),
            Err(RejectionReason::SacAuthorizationFailed)
        );
    }

    #[test]
    fn missing_sac_fails_closed() {
        let e = sac_env();
        let alice = Address::generate(&e);
        let ghost = Address::generate(&e);

        assert_eq!(
            is_authorized(&e, &ghost, &alice),
            Err(RejectionReason::SacAuthorizationFailed)
        );
    }
}
