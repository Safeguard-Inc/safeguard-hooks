//! Admin authority storage.
//!
//! A single admin gates administrative entry points (configuration, token
//! binding, freeze). Role-based separation of duties (distinct freeze /
//! policy / clawback signers) can be layered on top by swapping the admin
//! check, mirroring the access-control note in the OpenZeppelin confidential
//! token compliance spec; the storage shape does not change.

use soroban_sdk::{Address, Env};

use crate::keys::DataKey;

/// Returns the configured admin authority, or `None` before initialization.
///
/// Guarded with `has` because reading a missing key from a contract with no
/// instance entry panics (`Storage, MissingValue`) rather than returning
/// `None`.
pub fn admin(e: &Env) -> Option<Address> {
    if e.storage().instance().has(&DataKey::Admin) {
        e.storage().instance().get(&DataKey::Admin)
    } else {
        None
    }
}

/// Writes the admin authority.
///
/// # Security warning
///
/// This function does **not** authorize the caller. It must only be invoked
/// from `initialize` or an admin-gated rotation entry point.
pub fn set_admin(e: &Env, admin: &Address) {
    e.storage().instance().set(&DataKey::Admin, admin);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{account, host_env};

    #[test]
    fn admin_round_trip() {
        let (e, contract) = host_env();
        let admin_addr = account(&e);

        e.as_contract(&contract, || {
            assert_eq!(admin(&e), None);
            set_admin(&e, &admin_addr);
            assert_eq!(admin(&e), Some(admin_addr.clone()));
        });
    }

    #[test]
    fn admin_is_overwritable() {
        let (e, contract) = host_env();
        let first = account(&e);
        let second = account(&e);

        e.as_contract(&contract, || {
            set_admin(&e, &first);
            set_admin(&e, &second);
            assert_eq!(admin(&e), Some(second));
        });
    }
}
