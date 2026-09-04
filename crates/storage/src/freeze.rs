//! Per-(token, account) freeze state.
//!
//! A frozen account can neither send, receive, deposit, nor withdraw on the
//! frozen token — the freeze check runs before any state change. Freeze
//! state is keyed by token **and** account so one token's freeze never
//! contaminates another token's compliance state (multi-token isolation).
//!
//! Like the OpenZeppelin confidential-token extension, reads renew the TTL of
//! a live entry so an actively-frozen account does not silently thaw because
//! its flag expired.

use soroban_sdk::{Address, Env};

use crate::keys::DataKey;
use crate::touch;

/// Returns whether `account` is frozen on `token`.
///
/// Entries are renewed on read when present. Returns `false` when the entry
/// is absent.
pub fn is_frozen(e: &Env, token: &Address, account: &Address) -> bool {
    let key = DataKey::Freeze(token.clone(), account.clone());
    if e.storage().persistent().has(&key) {
        touch(e, &key);
        true
    } else {
        false
    }
}

/// Marks `account` as frozen on `token`.
///
/// # Security warning
///
/// This function does **not** authorize the caller and does not check the
/// compliance configuration. It must only be invoked from an admin-gated
/// entry point that has already verified configuration is active.
pub fn freeze_account(e: &Env, token: &Address, account: &Address) {
    e.storage()
        .persistent()
        .set(&DataKey::Freeze(token.clone(), account.clone()), &true);
}

/// Clears the frozen flag for `account` on `token`. Idempotent.
///
/// # Security warning
///
/// This function does **not** authorize the caller. It must only be invoked
/// from an admin-gated entry point.
pub fn unfreeze_account(e: &Env, token: &Address, account: &Address) {
    let key = DataKey::Freeze(token.clone(), account.clone());
    if e.storage().persistent().has(&key) {
        e.storage().persistent().remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{account, host_env};

    #[test]
    fn freeze_round_trip() {
        let (e, contract) = host_env();
        let token = account(&e);
        let alice = account(&e);

        e.as_contract(&contract, || {
            assert!(!is_frozen(&e, &token, &alice));
            freeze_account(&e, &token, &alice);
            assert!(is_frozen(&e, &token, &alice));
            unfreeze_account(&e, &token, &alice);
            assert!(!is_frozen(&e, &token, &alice));
        });
    }

    #[test]
    fn freeze_is_isolated_per_token() {
        let (e, contract) = host_env();
        let token_a = account(&e);
        let token_b = account(&e);
        let alice = account(&e);

        e.as_contract(&contract, || {
            freeze_account(&e, &token_a, &alice);
            assert!(is_frozen(&e, &token_a, &alice));
            assert!(!is_frozen(&e, &token_b, &alice));
        });
    }

    #[test]
    fn freeze_is_isolated_per_account() {
        let (e, contract) = host_env();
        let token = account(&e);
        let alice = account(&e);
        let bob = account(&e);

        e.as_contract(&contract, || {
            freeze_account(&e, &token, &alice);
            assert!(is_frozen(&e, &token, &alice));
            assert!(!is_frozen(&e, &token, &bob));
        });
    }

    #[test]
    fn unfreeze_is_idempotent() {
        let (e, contract) = host_env();
        let token = account(&e);
        let alice = account(&e);

        e.as_contract(&contract, || {
            unfreeze_account(&e, &token, &alice);
            assert!(!is_frozen(&e, &token, &alice));
        });
    }
}
