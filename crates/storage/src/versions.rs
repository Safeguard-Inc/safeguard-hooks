//! State-layout versioning.
//!
//! The contract stores one instance entry — `VERSION` — so a future upgrade
//! can detect whether the on-chain state predates a layout migration and
//! either migrate lazily or refuse to run. Bump [`VERSION`] whenever a
//! `DataKey` shape changes in a way that is not backward-compatible.

use soroban_sdk::Env;

use crate::keys::DataKey;

/// Current on-chain state layout version.
///
/// Bump only on incompatible layout changes; document the migration in
/// `docs/storage.md` alongside.
pub const VERSION: u32 = 1;

/// Returns the recorded layout version, or `None` when the contract has no
/// state yet (never initialized).
///
/// Guarded with `has` because reading a missing key from a contract with no
/// instance entry panics (`Storage, MissingValue`) rather than returning
/// `None`.
pub fn version(e: &Env) -> Option<u32> {
    if e.storage().instance().has(&DataKey::Version) {
        e.storage().instance().get(&DataKey::Version)
    } else {
        None
    }
}

/// Records the layout version.
///
/// # Security warning
///
/// This function does **not** authorize the caller. It must only be invoked
/// during initialization or a versioned migration path.
pub fn set_version(e: &Env, version: u32) {
    e.storage().instance().set(&DataKey::Version, &version);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::host_env;

    #[test]
    fn version_is_absent_until_written() {
        let (e, contract) = host_env();
        e.as_contract(&contract, || {
            assert_eq!(version(&e), None);
            set_version(&e, VERSION);
            assert_eq!(version(&e), Some(VERSION));
        });
    }
}
