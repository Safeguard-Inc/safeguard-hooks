//! The administrative authority gate.
//!
//! Every state-changing entry point of the enforcement contract — token
//! bind/unbind, freeze/unfreeze, compliance configuration rotation — must
//! first pass [`require_admin`]. The authority is a single address stored at
//! initialization; the gate is the SDK's `require_auth`, which reverts the
//! whole transaction when that address did not sign the invocation.
//!
//! Deployments that need separation of duties (a distinct freeze signer vs.
//! a policy-rotation signer, e.g. through an RBAC contract) swap this check
//! at the entry point, mirroring the access-control note in the OpenZeppelin
//! confidential-token compliance spec. This module defines the *shape* of the
//! authority seam; it does not hard-code a governance model.
//!
//! ## Fail-closed behavior
//!
//! * No admin stored (contract never initialized): [`require_admin`]
//!   returns [`RejectionReason::InvalidConfiguration`]. State cannot be
//!   changed on an uninitialized contract.
//! * Admin stored but the caller is not authorized: `require_auth` panics
//!   and the transaction reverts with the host authorization error (mapped
//!   to `unauthorized_caller` in `docs/errors.md`). The panic cannot be
//!   caught on-chain, which is the desired semantics: an unauthorized
//!   attempt aborts the operation.

use soroban_sdk::Env;

use safeguard_hook_core::RejectionReason;
use safeguard_storage::admin as stored_admin;

/// Returns whether the contract is initialized (an admin authority is set).
pub fn is_initialized(e: &Env) -> bool {
    stored_admin(e).is_some()
}

/// Authorization gate for every administrative entry point.
///
/// Returns `Ok(())` when the stored admin authorized the invocation, or
/// [`RejectionReason::InvalidConfiguration`] when the contract was never
/// initialized. When the contract *is* initialized but the caller is not the
/// admin, `require_auth` reverts the transaction before this function can
/// return.
pub fn require_admin(e: &Env) -> Result<(), RejectionReason> {
    let Some(admin) = stored_admin(e) else {
        return Err(RejectionReason::InvalidConfiguration);
    };
    // Reverts the transaction when `admin` did not authorize this call.
    admin.require_auth();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{Address as _, EnvTestConfig};
    use soroban_sdk::{contract, contractimpl, Address, Env};

    use safeguard_hook_core::RejectionReason;
    use safeguard_storage::set_admin;

    /// Test host that exposes the admin gate through a real contract
    /// invocation. `require_auth` only evaluates against a real invocation
    /// context, so the gate cannot be exercised from inside `as_contract`.
    #[contract]
    struct AdminHost;

    #[contractimpl]
    impl AdminHost {
        /// Runs the admin gate and returns the outcome as a reason code
        /// (`0` = authorized). A missing signature reverts instead.
        pub fn admin_gate(e: Env) -> u32 {
            match require_admin(&e) {
                Ok(()) => 0,
                Err(reason) => reason.code(),
            }
        }
    }

    fn host_env() -> (Env, Address) {
        let e = Env::new_with_config(EnvTestConfig {
            capture_snapshot_at_drop: false,
        });
        let host = e.register(AdminHost, ());
        (e, host)
    }

    #[test]
    fn uninitialized_contract_rejects_configuration_changes() {
        let (e, host) = host_env();

        // No admin is stored, so the gate reports InvalidConfiguration rather
        // than reverting with a signature error.
        let code = AdminHostClient::new(&e, &host).admin_gate();
        assert_eq!(code, RejectionReason::InvalidConfiguration.code());
        e.as_contract(&host, || assert!(!is_initialized(&e)));
    }

    #[test]
    fn authorized_admin_passes_the_gate() {
        let (e, host) = host_env();
        let alice = Address::generate(&e);

        e.as_contract(&host, || {
            set_admin(&e, &alice);
            assert!(is_initialized(&e));
        });

        let client = AdminHostClient::new(&e, &host);
        let code = client.mock_all_auths().admin_gate();
        assert_eq!(code, 0);
    }

    #[test]
    fn initialized_state_is_persisted() {
        let (e, host) = host_env();
        let alice = Address::generate(&e);
        e.as_contract(&host, || assert!(!is_initialized(&e)));

        e.as_contract(&host, || {
            set_admin(&e, &alice);
            assert!(is_initialized(&e));
        });
    }

    #[test]
    #[should_panic]
    fn unauthorized_caller_reverts_the_transaction() {
        let (e, host) = host_env();
        let alice = Address::generate(&e);

        e.as_contract(&host, || set_admin(&e, &alice));

        // No auths are mocked: `alice` did not sign, so `require_auth` inside
        // the gate panics and the invocation reverts.
        AdminHostClient::new(&e, &host).admin_gate();
    }
}
