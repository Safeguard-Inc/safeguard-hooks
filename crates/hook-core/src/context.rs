//! Context describing *what* is being enforced.
//!
//! [`HookContext`] identifies the calling token and the operation; an
//! [`OperationContext`] narrows that to a single (operation, role) pair so
//! the evaluator can run the right gates for the right party.
//!
//! Contexts never carry amounts or ciphertexts. The enforcement layer does
//! not need — and must not observe — private financial data. Keeping amounts
//! out of the context type is the type-level statement of the privacy
//! boundary documented in `docs/privacy.md`.

use crate::operation::Operation;
use crate::party::PartyRole;

/// The token and operation an enforcement evaluation concerns.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct HookContext<T> {
    /// The token contract that invoked the hook (its own address, passed as
    /// an explicit argument — Soroban contracts cannot introspect callers).
    pub token: T,
    /// The state-changing operation being gated.
    pub operation: Operation,
}

impl<T> HookContext<T> {
    /// Creates a hook context for `token` and `operation`.
    pub const fn new(token: T, operation: Operation) -> Self {
        HookContext { token, operation }
    }

    /// Returns one [`OperationContext`] per party the operation names, in
    /// canonical order.
    ///
    /// The evaluator runs the gates for each returned context and combines
    /// the decisions in order.
    pub fn operation_contexts(&self) -> impl Iterator<Item = OperationContext> + '_ {
        self.operation
            .parties()
            .iter()
            .copied()
            .map(move |role| OperationContext::new(self.operation, role))
    }
}

/// A single (operation, role) gate request.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct OperationContext {
    /// The operation being gated.
    pub operation: Operation,
    /// The role of the account being gated.
    pub role: PartyRole,
}

impl OperationContext {
    /// Creates an operation context for one party of `operation`.
    pub const fn new(operation: Operation, role: PartyRole) -> Self {
        OperationContext { operation, role }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    #[test]
    fn hook_context_expands_to_one_context_per_party() {
        let ctx = HookContext::new(42u64, Operation::TransferFrom);
        let expanded: Vec<OperationContext> = ctx.operation_contexts().collect();
        assert_eq!(expanded.len(), 3);
        assert_eq!(
            expanded,
            Vec::from([
                OperationContext::new(Operation::TransferFrom, PartyRole::Spender),
                OperationContext::new(Operation::TransferFrom, PartyRole::From),
                OperationContext::new(Operation::TransferFrom, PartyRole::To),
            ])
        );
    }

    #[test]
    fn single_party_operations_expand_to_one() {
        for op in [Operation::Register, Operation::Merge] {
            let ctx = HookContext::new("token", op);
            assert_eq!(ctx.operation_contexts().count(), 1);
        }
    }

    #[test]
    fn hook_context_carries_token_identity() {
        let ctx = HookContext::new("token-a", Operation::Transfer);
        assert_eq!(ctx.token, "token-a");
    }
}
