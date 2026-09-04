//! Party roles and gate classification.
//!
//! Authorization and compliance are different questions (see
//! `docs/authorization.md`):
//!
//! * *Authorization* asks "is this caller allowed to perform this
//!   operation?" — a property of the caller and the operation.
//! * *Compliance* asks "is this account permitted under the configured
//!   rules?" — a property of the account and the token.
//!
//! The roles below describe *compliance* subjects. The one asymmetry that
//! matters is the delegated-flow `spender`: a spender holds no funds (the
//! value stays with `from`), so freezing and SAC gates — which protect fund
//! ownership — do not apply to it. The spender is still screened by the
//! external policy, which can block an address regardless of whether it ever
//! touches a balance. This mirrors the allowance model of fungible and RWA
//! tokens and the OpenZeppelin confidential-token compliance extension.

use core::fmt;

/// The compliance-relevant role an account plays in an operation.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum PartyRole {
    /// The account that owns the operation (`register`, `merge`).
    Account,
    /// The source of value (`deposit`, `transfer`, `transfer_from`,
    /// `withdraw`).
    From,
    /// The destination of value (`deposit`, `transfer`, `transfer_from`,
    /// `withdraw`).
    To,
    /// The address authorized to spend on behalf of `from`
    /// (`transfer_from`).
    Spender,
}

impl PartyRole {
    /// Stable lowercase name used in fixtures, events, and logs.
    pub const fn name(self) -> &'static str {
        match self {
            PartyRole::Account => "account",
            PartyRole::From => "from",
            PartyRole::To => "to",
            PartyRole::Spender => "spender",
        }
    }

    /// How this role is screened by the enforcement evaluator.
    ///
    /// * [`GateClass::Full`] — freeze, policy, and (when enabled) SAC
    ///   authorization. Fund-holding roles.
    /// * [`GateClass::PolicyOnly`] — external policy only. The spender.
    pub const fn gate_class(self) -> GateClass {
        match self {
            PartyRole::Account | PartyRole::From | PartyRole::To => GateClass::Full,
            PartyRole::Spender => GateClass::PolicyOnly,
        }
    }

    /// True when this role holds (or is) the funds being moved.
    pub const fn holds_funds(self) -> bool {
        matches!(self.gate_class(), GateClass::Full)
    }
}

/// The set of gates that apply to a party.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum GateClass {
    /// Freeze, policy, and (optionally) SAC authorization checks apply.
    Full,
    /// Only the external policy check applies.
    PolicyOnly,
}

impl fmt::Display for GateClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GateClass::Full => f.write_str("full"),
            GateClass::PolicyOnly => f.write_str("policy_only"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fund_holders_are_fully_gated() {
        for role in [PartyRole::Account, PartyRole::From, PartyRole::To] {
            assert_eq!(role.gate_class(), GateClass::Full);
            assert!(role.holds_funds());
        }
    }

    #[test]
    fn spender_is_policy_only() {
        assert_eq!(PartyRole::Spender.gate_class(), GateClass::PolicyOnly);
        assert!(!PartyRole::Spender.holds_funds());
    }

    #[test]
    fn role_names_are_stable() {
        assert_eq!(PartyRole::Account.name(), "account");
        assert_eq!(PartyRole::From.name(), "from");
        assert_eq!(PartyRole::To.name(), "to");
        assert_eq!(PartyRole::Spender.name(), "spender");
    }
}
