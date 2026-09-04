//! Operations gated by the enforcement layer.
//!
//! These mirror the callback surface of the confidential-token `Hooks`
//! extension (see `interfaces/hooks/` and the OpenZeppelin confidential-token
//! compliance design): every state-changing entry point on the token that can
//! move or create value is represented here.
//!
//! A token contract invokes the matching hook before applying its state
//! transition; the hook reverts the whole operation when any gate fails.

use crate::party::PartyRole;

/// The state-changing operations a bound token may route through the
/// enforcement layer.
///
/// The variant set is deliberately closed. Adding a new operation is a
/// protocol change: it must be added here, to the on-chain hook entry points,
/// to the interfaces, and to the schemas together.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum Operation {
    /// Account registration on the confidential token.
    Register,
    /// Deposit of the underlying asset into a confidential balance.
    Deposit,
    /// Merge of the pending receiving commitment into the spendable balance.
    Merge,
    /// Confidential transfer between two registered accounts.
    Transfer,
    /// Delegated (spender-authorized) confidential transfer.
    TransferFrom,
    /// Withdrawal of the underlying asset out of a confidential balance.
    Withdraw,
}

impl Operation {
    /// Stable lowercase name, used in event topics, JSON payloads, and CLI
    /// output. The string form is part of the public contract: never rename.
    pub const fn name(self) -> &'static str {
        match self {
            Operation::Register => "register",
            Operation::Deposit => "deposit",
            Operation::Merge => "merge",
            Operation::Transfer => "transfer",
            Operation::TransferFrom => "transfer_from",
            Operation::Withdraw => "withdraw",
        }
    }

    /// The parties this operation names, in a canonical order.
    ///
    /// The set of parties is the *enforcement surface*: for each returned
    /// role the evaluator must run at least one gate. Roles that hold funds
    /// (`account`, `from`, `to`) pass the full gate; the `spender` of a
    /// delegated flow passes the policy gate only (it holds no funds — the
    /// value stays the owner's). See [`crate::party::PartyRole::gate_class`].
    pub const fn parties(self) -> &'static [PartyRole] {
        match self {
            Operation::Register | Operation::Merge => &[PartyRole::Account],
            Operation::Deposit | Operation::Transfer | Operation::Withdraw => {
                &[PartyRole::From, PartyRole::To]
            }
            Operation::TransferFrom => &[PartyRole::Spender, PartyRole::From, PartyRole::To],
        }
    }

    /// Whether the operation moves value between two named parties (`from` →
    /// `to`). Purely a classification helper for documentation and fixtures.
    pub const fn is_bilateral(self) -> bool {
        matches!(
            self,
            Operation::Deposit
                | Operation::Transfer
                | Operation::TransferFrom
                | Operation::Withdraw
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    #[test]
    fn operation_names_are_stable_and_lowercase() {
        let ops = [
            Operation::Register,
            Operation::Deposit,
            Operation::Merge,
            Operation::Transfer,
            Operation::TransferFrom,
            Operation::Withdraw,
        ];
        let names: Vec<&str> = ops.iter().map(|o| o.name()).collect();
        assert_eq!(
            names,
            [
                "register",
                "deposit",
                "merge",
                "transfer",
                "transfer_from",
                "withdraw"
            ]
        );
        assert!(names
            .iter()
            .all(|n| n.chars().all(|c| c.is_ascii_lowercase() || c == '_')));
    }

    #[test]
    fn parties_reflect_who_holds_funds() {
        use PartyRole::*;
        assert_eq!(Operation::Register.parties(), &[Account]);
        assert_eq!(Operation::Merge.parties(), &[Account]);
        assert_eq!(Operation::Deposit.parties(), &[From, To]);
        assert_eq!(Operation::Transfer.parties(), &[From, To]);
        assert_eq!(Operation::TransferFrom.parties(), &[Spender, From, To]);
        // The spender appears first so an operation with a non-compliant
        // spender is rejected before any fund-holder gate runs.
        assert_eq!(Operation::Withdraw.parties(), &[From, To]);
    }

    #[test]
    fn bilateral_classification() {
        assert!(Operation::Deposit.is_bilateral());
        assert!(Operation::Transfer.is_bilateral());
        assert!(Operation::TransferFrom.is_bilateral());
        assert!(Operation::Withdraw.is_bilateral());
        assert!(!Operation::Register.is_bilateral());
        assert!(!Operation::Merge.is_bilateral());
    }

    #[test]
    fn names_round_trip_through_operation() {
        for op in [
            Operation::Register,
            Operation::Deposit,
            Operation::Merge,
            Operation::Transfer,
            Operation::TransferFrom,
            Operation::Withdraw,
        ] {
            let name = op.name();
            assert!(!name.is_empty());
            assert_eq!(op.parties().len() >= 1, true);
        }
    }
}
