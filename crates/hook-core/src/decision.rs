//! The outcome of an enforcement evaluation.
//!
//! An evaluation is either an `Allow` (every gate passed) or a `Deny` with a
//! machine-readable [`RejectionReason`]. There is deliberately no third
//! "unknown" state: the enforcement layer is **fail-closed**, so an
//! evaluation that cannot complete (policy unreachable, invalid
//! configuration) must surface as a denial or an error, never as an allow.

use crate::reason::RejectionReason;

/// Outcome of a compliance evaluation for one (operation, party).
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum ComplianceDecision {
    /// Every applicable gate passed; the operation may proceed.
    Allow,
    /// At least one gate failed; the operation must not proceed.
    Deny(RejectionReason),
}

impl ComplianceDecision {
    /// Returns `true` when the evaluation allowed the operation.
    pub const fn is_allowed(self) -> bool {
        matches!(self, ComplianceDecision::Allow)
    }

    /// The rejection reason, when the decision is a denial.
    pub const fn reason(self) -> Option<RejectionReason> {
        match self {
            ComplianceDecision::Allow => None,
            ComplianceDecision::Deny(reason) => Some(reason),
        }
    }

    /// Combine two decisions, denying with the first (earlier) reason.
    ///
    /// Gate ordering is significant — cheap, local, and structural gates
    /// (binding, freeze) run before expensive cross-contract gates (policy,
    /// SAC). When both parties of a bilateral operation fail, the *first*
    /// failing party's reason is reported so the top of the rejection chain
    /// is deterministic.
    pub const fn and_then(self, next: ComplianceDecision) -> ComplianceDecision {
        match self {
            ComplianceDecision::Deny(_) => self,
            ComplianceDecision::Allow => next,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_has_no_reason() {
        assert!(ComplianceDecision::Allow.is_allowed());
        assert_eq!(ComplianceDecision::Allow.reason(), None);
    }

    #[test]
    fn deny_carries_its_reason() {
        let d = ComplianceDecision::Deny(RejectionReason::AccountFrozen);
        assert!(!d.is_allowed());
        assert_eq!(d.reason(), Some(RejectionReason::AccountFrozen));
    }

    #[test]
    fn combination_keeps_first_rejection() {
        let frozen = ComplianceDecision::Deny(RejectionReason::AccountFrozen);
        let policy = ComplianceDecision::Deny(RejectionReason::PolicyDenied);
        assert_eq!(
            frozen.and_then(policy),
            ComplianceDecision::Deny(RejectionReason::AccountFrozen)
        );
        assert_eq!(
            ComplianceDecision::Allow.and_then(policy),
            ComplianceDecision::Deny(RejectionReason::PolicyDenied)
        );
        assert_eq!(
            ComplianceDecision::Allow.and_then(ComplianceDecision::Allow),
            ComplianceDecision::Allow
        );
    }
}
