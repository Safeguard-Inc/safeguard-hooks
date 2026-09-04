//! The single storage-key enum for the enforcement contract.
//!
//! One enum, one place to audit every state entry. Keys are namespaced by
//! [`soroban_sdk::Env`] storage class:
//!
//! * instance storage — singleton configuration that lives for the contract's
//!   lifetime: admin authority, compliance config, state version;
//! * persistent storage — entries that can appear and disappear per account /
//!   token: token bindings and per-(token, account) freeze flags.
//!
//! Per-token and per-account state is keyed by **both** the token and the
//! account so that a decision made for Token A can never bleed into Token B
//! (multi-token isolation). Cross-token contamination is exercised by the
//! security test suite.

use soroban_sdk::{contracttype, Address};

/// Storage keys of the Safeguard enforcement contract.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum DataKey {
    /// The admin authority (instance storage).
    Admin,
    /// The active [`crate::ComplianceConfig`] (instance storage).
    Config,
    /// The state-layout version of the contract (instance storage).
    Version,
    /// Marks `Address` (a token contract) as bound to this enforcement
    /// contract, carrying the token's [`crate::TokenBinding`]
    /// (persistent storage).
    TokenBinding(Address),
    /// Freeze flag for `(token, account)` (persistent storage).
    ///
    /// Freeze state is keyed per token so freezing an account on Token A does
    /// not freeze it on Token B — each token has an independent compliance
    /// lifecycle, which is what makes multi-token isolation enforceable.
    Freeze(Address, Address),
}

impl DataKey {
    /// Namespace prefix used in documentation and schema tooling.
    pub fn class(&self) -> &'static str {
        match self {
            DataKey::Admin | DataKey::Config | DataKey::Version => "instance",
            DataKey::TokenBinding(_) | DataKey::Freeze(..) => "persistent",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_classification_is_stable() {
        use soroban_sdk::testutils::Address as _;
        let e = soroban_sdk::Env::default();
        let a = Address::generate(&e);
        let b = Address::generate(&e);
        assert_eq!(DataKey::Admin.class(), "instance");
        assert_eq!(DataKey::Config.class(), "instance");
        assert_eq!(DataKey::Version.class(), "instance");
        assert_eq!(DataKey::TokenBinding(a.clone()).class(), "persistent");
        assert_eq!(DataKey::Freeze(a, b).class(), "persistent");
    }
}
