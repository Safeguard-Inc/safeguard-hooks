//! Compliance configuration storage.
//!
//! [`ComplianceConfig`] is the single knob an operator turns to change how
//! enforcement behaves for **all** bound tokens: which external policy
//! decides account eligibility, and whether the underlying SAC's
//! authorization state is consulted.
//!
//! `None` (no config) means the enforcement contract is inert: every hook is
//! a silent no-op and no account can be frozen. That is the deployment-time
//! default and matches the short-circuit behaviour of the OpenZeppelin
//! `ComplianceHooks` — vanilla deployments pay zero enforcement overhead.
//! Turning the enforcement layer on is the *first* configuration write.

use soroban_sdk::{contracttype, Address, Env};

use crate::keys::DataKey;

/// Active enforcement configuration shared by all bound tokens.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComplianceConfig {
    /// Optional external policy contract (`safeguard-policy`). When `None`,
    /// the policy gate is disabled.
    pub policy: Option<Address>,
    /// When `true`, every gated operation additionally consults the bound
    /// token's underlying SAC `authorized()` view for fund-holding parties.
    pub sac_passthrough: bool,
}

impl ComplianceConfig {
    /// A fully-disabled configuration (no policy, no SAC passthrough).
    pub const fn disabled() -> Self {
        ComplianceConfig {
            policy: None,
            sac_passthrough: false,
        }
    }
}

/// Returns the active compliance configuration, or `None` when enforcement
/// has not been configured.
///
/// Guarded with `has` because reading a missing key from a contract with no
/// instance entry panics (`Storage, MissingValue`) rather than returning
/// `None`.
pub fn compliance_config(e: &Env) -> Option<ComplianceConfig> {
    if e.storage().instance().has(&DataKey::Config) {
        e.storage().instance().get(&DataKey::Config)
    } else {
        None
    }
}

/// Writes `config` into instance storage, replacing any prior value.
///
/// This is the single setter used both by the deployment-time initialization
/// and by admin-gated rotation.
///
/// # Security warning
///
/// This function does **not** authorize the caller. It must only be invoked
/// from initialization or an admin-gated entry point; a public path that
/// calls it unguarded is a configuration attack.
pub fn set_compliance_config(e: &Env, config: &ComplianceConfig) {
    e.storage().instance().set(&DataKey::Config, config);
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{account, host_env};

    #[test]
    fn config_defaults_to_none() {
        let (e, contract) = host_env();
        e.as_contract(&contract, || {
            assert_eq!(compliance_config(&e), None);
        });
    }

    #[test]
    fn config_round_trip() {
        let (e, contract) = host_env();
        let policy = account(&e);

        e.as_contract(&contract, || {
            let config = ComplianceConfig {
                policy: Some(policy),
                sac_passthrough: true,
            };
            set_compliance_config(&e, &config);
            assert_eq!(compliance_config(&e), Some(config));
        });
    }

    #[test]
    fn disabled_config_short_circuits() {
        let (e, contract) = host_env();
        e.as_contract(&contract, || {
            set_compliance_config(&e, &ComplianceConfig::disabled());
            assert_eq!(
                compliance_config(&e),
                Some(ComplianceConfig {
                    policy: None,
                    sac_passthrough: false
                })
            );
        });
    }
}
