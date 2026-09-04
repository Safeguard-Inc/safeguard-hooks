//! # safeguard-storage
//!
//! Contract state keys and persistence helpers for the Safeguard enforcement
//! contract (`contracts/compliance-hooks`).
//!
//! State is deliberately small (see `docs/storage.md`). The enforcement layer
//! stores only what it needs to *make the transaction obey the decision*:
//!
//! * the admin authority ([`admin`]),
//! * the compliance configuration ([`compliance_config`]) — policy address
//!   and SAC passthrough flag,
//! * which tokens are bound to this enforcement contract and to which
//!   underlying SAC ([`bindings`]),
//! * per-(token, account) freeze state ([`freeze`]),
//! * a state-layout version ([`version`]) for forward migrations.
//!
//! The policy *rules* (allowlists, denylists, sanctions, jurisdictions) live
//! in `safeguard-policy`, never here. Policy evaluation happens through
//! `safeguard-policy-client` at enforcement time.
//!
//! ## Security model
//!
//! The helpers in this crate **do not authorize callers** — mirroring the
//! OpenZeppelin confidential-token storage layer, authorization lives in the
//! entry points (`safeguard-authorization` and the contract). Storage is the
//! last line of defense and must stay simple enough to audit: every key is a
//! variant of the single [`DataKey`] enum, every write function documents
//! exactly what it changes and what it deliberately does not check.

#![no_std]
#[cfg(test)]
extern crate std;

mod admin;
mod bindings;
mod config;
mod freeze;
mod keys;
mod versions;

#[cfg(test)]
mod test_support;

pub use admin::{admin, set_admin};
pub use bindings::{bind_token, is_token_bound, token_binding, unbind_token, TokenBinding};
pub use config::{compliance_config, set_compliance_config, ComplianceConfig};
pub use freeze::{freeze_account, is_frozen, unfreeze_account};
pub use keys::DataKey;
pub use versions::{set_version, version, VERSION};

use soroban_sdk::Env;

/// Ledgers in a day (Stellar network default).
pub const DAY_IN_LEDGERS: u32 = 17_280;
/// Live window granted on every touch/read of a persistent entry.
pub const TTL_EXTEND_TO: u32 = 30 * DAY_IN_LEDGERS;
/// Renew a persistent entry when its remaining lifetime drops below this.
pub const TTL_THRESHOLD: u32 = TTL_EXTEND_TO - DAY_IN_LEDGERS;

/// Extends the TTL of a persistent entry when it is read, so long-lived
/// entries (e.g. freeze flags) are kept alive by the traffic that touches
/// them.
pub fn touch(e: &Env, key: &DataKey) {
    if e.storage().persistent().has(key) {
        e.storage()
            .persistent()
            .extend_ttl(key, TTL_THRESHOLD, TTL_EXTEND_TO);
    }
}
