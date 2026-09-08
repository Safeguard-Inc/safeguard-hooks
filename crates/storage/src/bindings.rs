//! Token binding storage.
//!
//! A token must be **bound** to the enforcement contract before any of its
//! operations are gated. Binding is the admission control that makes
//! unbound-token invocation impossible: hooks invoked for a token that has no
//! binding entry revert with `TokenNotBound` (see the token-spoofing tests).
//!
//! The binding carries the token's underlying Stellar Asset Contract (SAC)
//! address so the enforcement contract can perform the optional SAC
//! `authorized()` passthrough without mirroring token state. `sac: None`
//! simply disables the SAC gate for that token.
//!
//! One binding is one (token → enforcement) relationship. A single policy
//! contract may still serve many tokens through the shared config, and the
//! policy receives the token address on every call so a shared registry can
//! apply per-token rules.

use soroban_sdk::{contracttype, Address, Env};

use crate::keys::DataKey;
use crate::touch;

/// What the enforcement contract knows about a bound token.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenBinding {
    /// Address of the underlying Stellar Asset Contract, when the token wraps
    /// a SAC and SAC passthrough applies to it.
    pub sac: Option<Address>,
}

/// Returns the binding for `token`, if the token is bound.
///
/// A live binding is renewed on read, exactly like a live freeze flag: a
/// bound token must not silently fall out of enforcement scope because its
/// ledger entry expired while idle. Reads keep long-lived bindings alive
/// (see [`crate::touch`]).
pub fn token_binding(e: &Env, token: &Address) -> Option<TokenBinding> {
    let key = DataKey::TokenBinding(token.clone());
    if e.storage().persistent().has(&key) {
        touch(e, &key);
        e.storage().persistent().get(&key)
    } else {
        None
    }
}

/// Returns whether `token` is bound to this enforcement contract.
pub fn is_token_bound(e: &Env, token: &Address) -> bool {
    token_binding(e, token).is_some()
}

/// Binds `token` to this enforcement contract, optionally recording its
/// underlying SAC.
///
/// # Security warning
///
/// This function does **not** authorize the caller. It must only be invoked
/// from an admin-gated entry point.
pub fn bind_token(e: &Env, token: &Address, sac: Option<&Address>) {
    e.storage().persistent().set(
        &DataKey::TokenBinding(token.clone()),
        &TokenBinding { sac: sac.cloned() },
    );
}

/// Removes the binding for `token`.
///
/// # Security warning
///
/// This function does **not** authorize the caller. It must only be invoked
/// from an admin-gated entry point.
pub fn unbind_token(e: &Env, token: &Address) {
    let key = DataKey::TokenBinding(token.clone());
    if e.storage().persistent().has(&key) {
        e.storage().persistent().remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{account, host_env};

    #[test]
    fn binding_round_trip() {
        let (e, contract) = host_env();
        let token = account(&e);
        let sac = account(&e);

        e.as_contract(&contract, || {
            assert!(!is_token_bound(&e, &token));
            assert_eq!(token_binding(&e, &token), None);

            bind_token(&e, &token, Some(&sac));
            assert!(is_token_bound(&e, &token));
            assert_eq!(
                token_binding(&e, &token),
                Some(TokenBinding { sac: Some(sac) })
            );
        });
    }

    #[test]
    fn reads_renew_the_binding_ttl() {
        use crate::{TTL_EXTEND_TO, TTL_THRESHOLD};
        use soroban_sdk::testutils::{storage::Persistent as _, Ledger as _};

        let (e, contract) = host_env();
        let token = account(&e);
        let key = DataKey::TokenBinding(token.clone());

        e.as_contract(&contract, || {
            bind_token(&e, &token, None);
            assert!(is_token_bound(&e, &token));

            // Age the entry: jump most of the way to its expiry so its
            // remaining TTL drops below the renewal threshold. Without the
            // read-time renewal, the binding would silently expire here and
            // the token would fall out of enforcement scope.
            e.ledger()
                .set_sequence_number(e.ledger().sequence() + 6_000_000);
            assert!(e.storage().persistent().get_ttl(&key) < TTL_THRESHOLD);

            // A read must keep the entry alive, not let it expire silently.
            let binding = token_binding(&e, &token);
            assert!(binding.is_some());
            assert!(
                e.storage().persistent().get_ttl(&key) >= TTL_EXTEND_TO,
                "reading a binding must renew its TTL"
            );

            // …and the token is still in scope afterwards.
            assert!(is_token_bound(&e, &token));
        });
    }

    #[test]
    fn bindings_are_isolated_per_token() {
        let (e, contract) = host_env();
        let token_a = account(&e);
        let token_b = account(&e);

        e.as_contract(&contract, || {
            bind_token(&e, &token_a, None);
            assert!(is_token_bound(&e, &token_a));
            assert!(!is_token_bound(&e, &token_b));
        });
    }

    #[test]
    fn unbind_removes_entry() {
        let (e, contract) = host_env();
        let token = account(&e);

        e.as_contract(&contract, || {
            bind_token(&e, &token, None);
            unbind_token(&e, &token);
            assert!(!is_token_bound(&e, &token));
            // Unbinding an unbound token is a no-op, not an error.
            unbind_token(&e, &token);
        });
    }
}
