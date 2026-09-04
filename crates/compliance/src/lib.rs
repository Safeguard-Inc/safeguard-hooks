//! # safeguard-compliance
//!
//! The enforcement evaluation pipeline of the Safeguard hooks contract.
//!
//! This crate answers, for a single operation, the question the whole
//! enforcement layer exists for: **may this operation proceed on this
//! token?** It orders the gates, runs them, and combines the results into a
//! single fail-closed [`ComplianceDecision`].
//!
//! ```text
//!            hook entry point (token invokes)
//!                        │
//!                        ▼
//!      ┌─── configuration present? ─── no ──► Deny(InvalidConfiguration)
//!      │        │ yes
//!      │        ▼
//!      │   token bound to this contract?  no ──► Deny(UnboundToken)
//!      │        │ yes
//!      │        ▼
//!      │   for each party the operation names, in order:
//!      │        ├─ Full party (holds funds): frozen? ──► Deny(AccountFrozen)
//!      │        ├─ any party:          policy ok? ──► Deny(PolicyDenied)
//!      │        │                        │ no policy / unevaluable ──► Deny(PolicyUnavailable)
//!      │        └─ Full party + SAC on: SAC authorized? ──► Deny(SacAuthorizationFailed)
//!      │                    │
//!      │                    ▼
//!      └──────────────► Allow
//! ```
//!
//! ## Design rules
//!
//! * **Fail-closed.** There is no "unknown" outcome. An unconfigured
//!   contract, an unbound token, a reverting policy, or a SAC that cannot be
//!   reached all produce a denial, never an allow. The hook layer turns a
//!   denial into a revert, so *rejected operation = no state change*.
//! * **Cheap gates run before expensive ones.** Binding and freeze checks
//!   are local storage reads; policy and SAC checks are cross-contract
//!   calls. A frozen party is rejected before any policy round-trip.
//! * **Gate semantics follow party role.** Parties that hold (or are) the
//!   funds — `account`, `from`, `to` — pass the full gate (freeze, policy,
//!   SAC). The `spender` of a delegated flow holds no funds, so it is
//!   screened by policy only; see `safeguard-hook-core`'s `PartyRole`.
//! * **No private data.** The pipeline never sees amounts or ciphertexts;
//!   it gates *addresses* on *tokens*. (The compliance-hooks contract passes
//!   the operation's parties and nothing else.)
//! * **The policy is an external oracle.** This crate never decides
//!   eligibility — it consults `safeguard-policy` through
//!   `safeguard-policy-client` and enforces the answer.
//!
//! ## Modules
//!
//! * [`evaluator`] — the gate-ordering pipeline, exposed per operation.
//! * [`sac`] — the underlying Stellar Asset Contract `authorized()` view.
//!
//! The hook *entry surface* (which token function maps to which operation)
//! lives in `contracts/compliance-hooks`; this crate is deliberately free of
//! contract ceremony so the ordering logic is testable on its own.

#![no_std]
#[cfg(test)]
extern crate std;

pub mod evaluator;
pub mod sac;

pub use evaluator::{
    evaluate, evaluate_deposit, evaluate_register, evaluate_transfer, evaluate_withdraw,
};
