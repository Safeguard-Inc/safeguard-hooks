//! Shared test harness.
//!
//! Instance storage operations require the *current contract* to be a real,
//! deployed instance — in the Soroban host, `Env::storage().instance()` on an
//! address that was never registered has no instance entry and panics with
//! `Error(Storage, MissingValue)` even for `has`/`get` on absent keys.
//!
//! Every test therefore registers a tiny [`Host`] contract (mirroring the
//! OpenZeppelin test pattern) and runs storage helpers under
//! `env.as_contract(&host, ...)`, which is exactly how the production
//! contract executes them.

use soroban_sdk::testutils::{Address as _, EnvTestConfig};
use soroban_sdk::{contract, contractimpl, Address, Env};

/// A minimal contract that owns the storage under test.
#[contract]
pub struct Host;

#[contractimpl]
impl Host {
    /// The only purpose of the host is to own an instance.
    pub fn ping(_e: Env) {}
}

/// Returns a fresh environment with a registered host contract address.
pub fn host_env() -> (Env, Address) {
    // Snapshot capture at drop is disabled: the auto-generated
    // `test_snapshots/` files are environment dumps, not assertions, and they
    // churn on every SDK bump. Behaviour is asserted explicitly instead.
    let e = Env::new_with_config(EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    let host = e.register(Host, ());
    (e, host)
}

/// Generates an account-style address on `e`.
pub fn account(e: &Env) -> Address {
    Address::generate(e)
}
