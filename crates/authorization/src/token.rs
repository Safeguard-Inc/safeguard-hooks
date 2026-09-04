//! The per-token enforcement-scope gate.
//!
//! A token is **bound** to the enforcement contract before any of its
//! operations are gated (see `crates/storage/src/bindings.rs`). The binding
//! is the contract's own record of which tokens it serves, and the gate
//! below is what makes that record enforceable.
//!
//! Because Soroban contracts cannot introspect their caller, the enforcement
//! contract learns which token an operation concerns from the operation's
//! arguments — and an impersonator can always claim to *be* a bound token.
//! The binding gate cannot distinguish the bound token from an impersonator,
//! so it is defense in depth rather than caller authentication:
//!
//! * operations for a token with **no binding** are rejected before any
//!   enforcement or state access for that token (`UnboundToken`), which
//!   blocks spoofed or unconfigured tokens outright;
//! * operations for a **bound** token are gated by this contract's state,
//!   and the gates never write token-visible state — a spoofed call can burn
//!   gas or observe public reads, nothing more.
//!
//! The authoritative defense against impersonation is architectural: the
//! confidential token is constructed with its compliance contract address
//! and consults only that contract. The binding gate closes the remaining
//! hole — a token that was never admitted to the scope cannot drag this
//! contract into its operations at all.

use soroban_sdk::{Address, Env};

use safeguard_hook_core::RejectionReason;
use safeguard_storage::is_token_bound as binding_exists;

/// Returns whether `token` is bound to this enforcement contract.
pub fn is_token_bound(e: &Env, token: &Address) -> bool {
    binding_exists(e, token)
}

/// Gate: `token` must be bound before the enforcement contract runs any
/// hook for it.
///
/// Returns [`RejectionReason::UnboundToken`] when the token has no binding
/// entry. This is the check behind the token-spoofing security tests: an
/// unbound token's invocation is rejected before any gate or state access.
pub fn require_token_bound(e: &Env, token: &Address) -> Result<(), RejectionReason> {
    if is_token_bound(e, token) {
        Ok(())
    } else {
        Err(RejectionReason::UnboundToken)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{Address as _, EnvTestConfig};
    use soroban_sdk::{contract, contractimpl, Address, Env};

    use safeguard_storage::bind_token;

    /// Test host exposing the scope gate through a real contract invocation.
    #[contract]
    struct ScopeHost;

    #[contractimpl]
    impl ScopeHost {
        /// Runs the scope gate and returns the outcome as a reason code
        /// (`0` = in scope).
        pub fn scope_gate(e: Env, token: Address) -> u32 {
            match require_token_bound(&e, &token) {
                Ok(()) => 0,
                Err(reason) => reason.code(),
            }
        }
    }

    fn host_env() -> (Env, Address) {
        let e = Env::new_with_config(EnvTestConfig {
            capture_snapshot_at_drop: false,
        });
        let host = e.register(ScopeHost, ());
        (e, host)
    }

    #[test]
    fn unbound_token_is_rejected() {
        let (e, host) = host_env();
        let token = Address::generate(&e);

        e.as_contract(&host, || assert!(!is_token_bound(&e, &token)));
        let code = ScopeHostClient::new(&e, &host).scope_gate(&token);
        assert_eq!(code, RejectionReason::UnboundToken.code());
    }

    #[test]
    fn bound_token_is_in_scope() {
        let (e, host) = host_env();
        let token = Address::generate(&e);

        e.as_contract(&host, || {
            bind_token(&e, &token, None);
            assert!(is_token_bound(&e, &token));
        });

        let code = ScopeHostClient::new(&e, &host).scope_gate(&token);
        assert_eq!(code, 0);
    }

    #[test]
    fn scope_is_isolated_per_token() {
        let (e, host) = host_env();
        let token_a = Address::generate(&e);
        let token_b = Address::generate(&e);

        e.as_contract(&host, || bind_token(&e, &token_a, None));

        // Token A is in scope; Token B is not — one binding never admits
        // another token (multi-token isolation).
        let client = ScopeHostClient::new(&e, &host);
        assert_eq!(client.scope_gate(&token_a), 0);
        assert_eq!(
            client.scope_gate(&token_b),
            RejectionReason::UnboundToken.code()
        );
    }

    #[test]
    fn unbinding_revokes_scope() {
        let (e, host) = host_env();
        let token = Address::generate(&e);

        e.as_contract(&host, || {
            bind_token(&e, &token, None);
            assert!(is_token_bound(&e, &token));
        });

        let client = ScopeHostClient::new(&e, &host);
        assert_eq!(client.scope_gate(&token), 0);

        e.as_contract(&host, || safeguard_storage::unbind_token(&e, &token));
        assert_eq!(
            client.scope_gate(&token),
            RejectionReason::UnboundToken.code()
        );
    }
}
