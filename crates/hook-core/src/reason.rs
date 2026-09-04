//! Machine-readable rejection reasons.
//!
//! "Compliance failed" is not a rejection reason. Every denial the
//! enforcement layer can produce is identified by a stable name and code so
//! that tests, the audit polyrepo, the CLI, and incident tooling can key off
//! a reason without parsing prose.
//!
//! The on-chain failure is surfaced as a Soroban contract error (a panic with
//! a numeric code); `RejectionReason` is the *semantic* counterpart used in
//! fixtures, documentation, schemas, and by `safeguard-audit`. The mapping
//! from contract errors to these reasons is documented in `docs/errors.md`
//! and enforced by the security test suite.

/// A stable, machine-readable reason an operation was rejected.
///
/// The string names are part of the public contract (mirrored in
/// `schemas/rejection.schema.json` and consumed by `safeguard-audit`);
/// never rename a variant.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum RejectionReason {
    /// The caller was not authorized to perform the operation.
    UnauthorizedCaller,
    /// The token the operation claims to concern is not bound to this
    /// enforcement layer.
    UnboundToken,
    /// The configured policy returned a denial for an account.
    PolicyDenied,
    /// An account holding funds is frozen.
    AccountFrozen,
    /// The spender of a delegated flow is not authorized by policy.
    SpenderNotAuthorized,
    /// A policy-level sanctions screen blocked the account.
    SanctionsBlocked,
    /// A policy-level jurisdiction rule blocked the account.
    JurisdictionRestricted,
    /// The underlying SAC authorization check failed for an account.
    SacAuthorizationFailed,
    /// The enforcement layer configuration is invalid or absent.
    InvalidConfiguration,
    /// The policy contract could not be reached or evaluated (fail-closed).
    PolicyUnavailable,
    /// The operation requires a registered account.
    RegistrationRequired,
}

/// Every rejection reason in code order. Tooling (the operator CLI, the
/// audit polyrepo, incident tooling) iterates this to decode contract error
/// codes without duplicating the mapping.
pub const ALL: [RejectionReason; 11] = [
    RejectionReason::UnauthorizedCaller,
    RejectionReason::UnboundToken,
    RejectionReason::PolicyDenied,
    RejectionReason::AccountFrozen,
    RejectionReason::SpenderNotAuthorized,
    RejectionReason::SanctionsBlocked,
    RejectionReason::JurisdictionRestricted,
    RejectionReason::SacAuthorizationFailed,
    RejectionReason::InvalidConfiguration,
    RejectionReason::PolicyUnavailable,
    RejectionReason::RegistrationRequired,
];

impl RejectionReason {
    /// Stable snake_case identifier. Public contract — do not rename.
    pub const fn name(self) -> &'static str {
        match self {
            RejectionReason::UnauthorizedCaller => "unauthorized_caller",
            RejectionReason::UnboundToken => "unbound_token",
            RejectionReason::PolicyDenied => "policy_denied",
            RejectionReason::AccountFrozen => "account_frozen",
            RejectionReason::SpenderNotAuthorized => "spender_not_authorized",
            RejectionReason::SanctionsBlocked => "sanctions_blocked",
            RejectionReason::JurisdictionRestricted => "jurisdiction_restricted",
            RejectionReason::SacAuthorizationFailed => "sac_authorization_failed",
            RejectionReason::InvalidConfiguration => "invalid_configuration",
            RejectionReason::PolicyUnavailable => "policy_unavailable",
            RejectionReason::RegistrationRequired => "registration_required",
        }
    }

    /// Stable numeric code. Mirrors `schemas/rejection.schema.json`.
    pub const fn code(self) -> u32 {
        match self {
            RejectionReason::UnauthorizedCaller => 1,
            RejectionReason::UnboundToken => 2,
            RejectionReason::PolicyDenied => 3,
            RejectionReason::AccountFrozen => 4,
            RejectionReason::SpenderNotAuthorized => 5,
            RejectionReason::SanctionsBlocked => 6,
            RejectionReason::JurisdictionRestricted => 7,
            RejectionReason::SacAuthorizationFailed => 8,
            RejectionReason::InvalidConfiguration => 9,
            RejectionReason::PolicyUnavailable => 10,
            RejectionReason::RegistrationRequired => 11,
        }
    }

    /// Parse back from the stable name (used by fixtures and tooling).
    pub fn from_name(name: &str) -> Option<Self> {
        ALL.iter().copied().find(|reason| reason.name() == name)
    }

    /// Parse back from the stable numeric code (contract error codes mirror
    /// these 1–11; used by the operator CLI to decode `Error(Contract, #N)`).
    pub fn from_code(code: u32) -> Option<Self> {
        ALL.iter().copied().find(|reason| reason.code() == code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    #[test]
    fn names_are_stable_and_unique() {
        let all = [
            RejectionReason::UnauthorizedCaller,
            RejectionReason::UnboundToken,
            RejectionReason::PolicyDenied,
            RejectionReason::AccountFrozen,
            RejectionReason::SpenderNotAuthorized,
            RejectionReason::SanctionsBlocked,
            RejectionReason::JurisdictionRestricted,
            RejectionReason::SacAuthorizationFailed,
            RejectionReason::InvalidConfiguration,
            RejectionReason::PolicyUnavailable,
            RejectionReason::RegistrationRequired,
        ];
        let mut names: Vec<&str> = all.iter().map(|r| r.name()).collect();
        let mut codes: Vec<u32> = all.iter().map(|r| r.code()).collect();
        names.sort_unstable();
        codes.sort_unstable();
        names.dedup();
        codes.dedup();
        assert_eq!(names.len(), all.len(), "names must be unique");
        assert_eq!(codes.len(), all.len(), "codes must be unique");
    }

    #[test]
    fn names_round_trip() {
        for r in [
            RejectionReason::AccountFrozen,
            RejectionReason::PolicyDenied,
            RejectionReason::SanctionsBlocked,
        ] {
            assert_eq!(RejectionReason::from_name(r.name()), Some(r));
        }
        assert_eq!(RejectionReason::from_name("nonsense"), None);
    }

    #[test]
    fn codes_round_trip_and_all_are_covered() {
        assert_eq!(ALL.len(), 11);
        for reason in ALL {
            assert_eq!(RejectionReason::from_code(reason.code()), Some(reason));
        }
        // 1..=11 are exactly the reason codes; anything else is not a
        // rejection reason (the contract adds its own codes above 11).
        for code in 1..=11 {
            assert!(RejectionReason::from_code(code).is_some());
        }
        assert_eq!(RejectionReason::from_code(0), None);
        assert_eq!(RejectionReason::from_code(12), None);
    }
}
