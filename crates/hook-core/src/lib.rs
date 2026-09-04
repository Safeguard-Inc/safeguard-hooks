//! # safeguard-hook-core
//!
//! Pure domain model for the Safeguard enforcement layer.
//!
//! This crate deliberately has **no dependency on `soroban-sdk`** (or any
//! blockchain environment). It pins down the vocabulary every other layer
//! speaks — which operations exist, which parties each operation names, what
//! "denied" means, and how rejections are identified — so that policy,
//! enforcement, and audit code all agree on the same machine-readable
//! language without sharing an environment.
//!
//! Keeping the model environment-free matters for three reasons:
//!
//! 1. **Testability.** Decision semantics can be unit-tested without spinning
//!    up a Soroban host.
//! 2. **Schema stability.** `RejectionReason`, `Operation`, and
//!    `ComplianceDecision` mirror the JSON schemas in `schemas/`, the event
//!    payloads emitted by `safeguard-events`, and the reason codes consumed by
//!    `safeguard-audit`. One source of truth.
//! 3. **Architecture.** The enforcement layer must never re-implement policy
//!    rules. It can only *classify* an outcome (`allow`/`deny`); the model
//!    types make that boundary visible in the type system.
//!
//! The module map:
//!
//! * [`operation`] — the state-changing operations a confidential token can
//!   name: `register`, `deposit`, `merge`, `transfer`, `transfer_from`,
//!   `withdraw`.
//! * [`party`] — the roles an operation names (`account`, `from`, `to`,
//!   `spender`) and how each role is gated.
//! * [`decision`] — the outcome of an evaluation: `Allow` or `Deny`.
//! * [`reason`] — machine-readable rejection reasons with stable string names.
//! * [`context`] — a single (operation, role) gate request.
//!
//! Soroban-specific *mechanism* (storage keys, cross-contract policy calls,
//! event publishing, admin authorization) lives in the sibling crates
//! `safeguard-storage`, `safeguard-policy-client`, `safeguard-events`, and
//! `safeguard-authorization`; the *ordering* of gates lives in
//! `safeguard-compliance`. This crate stays the shared, dependency-free core.

#![no_std]
#[cfg(test)]
extern crate std;

pub mod context;
pub mod decision;
pub mod operation;
pub mod party;
pub mod reason;

pub use context::{HookContext, OperationContext};
pub use decision::ComplianceDecision;
pub use operation::Operation;
pub use party::{GateClass, PartyRole};
pub use reason::RejectionReason;
