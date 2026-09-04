//! # safeguard-policy-client
//!
//! The typed, fail-closed bridge from Safeguard Hooks (ENFORCE) to the
//! external policy contract in `safeguard-policy` (DEFINE).
//!
//! ```text
//!              safeguard-policy               safeguard-hooks
//!   ┌──────────────────────────┐    call     ┌──────────────────────┐
//!   │ Rules · registries ·     │ ──────────► │ enforcement gates    │
//!   │ jurisdictions · versions │◄──────────  │ freeze · SAC · scope │
//!   └──────────────────────────┘  decision   └──────────────────────┘
//! ```
//!
//! The policy decides *what should happen*; the enforcement contract makes
//! the transaction obey that decision. This crate is the only place in the
//! Hooks codebase that knows how to talk to a policy contract — everything
//! else consumes [`is_authorized`] results.
//!
//! ## The wire contract
//!
//! The interface this crate calls is the **stable contract between the two
//! polyrepos** and mirrors the `Policy` trait of the OpenZeppelin
//! confidential-token compliance design:
//!
//! ```text
//! is_authorized(account: Address, token: Address) -> bool
//! ```
//!
//! * `account` — the party being screened. The enforcement contract screens
//!   each party an operation names (sender, recipient, and — for delegated
//!   flows — the spender) with its own call.
//! * `token` — the token whose operation triggered the screen, so one policy
//!   contract can serve many tokens with per-token rules.
//! * `true` — authorized; `false` — denied.
//!
//! ## What the request deliberately does not carry
//!
//! No amounts, balances, commitments, or ciphertexts are ever sent to the
//! policy. The whole point of a confidential token is that balances and
//! transfer sizes stay private; the policy screens *addresses*, not values.
//! A deployment whose policy genuinely needs amount context must bring its
//! own oracle — this crate protects the privacy boundary by construction.
//!
//! ## Fail-closed evaluation
//!
//! The policy is part of the deployment's trust surface, and enforcement
//! treats an unevaluable policy as a rejection:
//!
//! * `Ok(true)` — authorized.
//! * `Ok(false)` — the policy answered "no" (the caller reports
//!   [`RejectionReason::PolicyDenied`]).
//! * `Err(RejectionReason::PolicyUnavailable)` — the policy call failed or
//!   the policy reverted, or its answer was not a boolean. Enforcement must
//!   never silently proceed when the policy cannot be evaluated; the hook
//!   layer converts this into a revert of the whole operation.
//!
//! Using `try_invoke_contract` (rather than a raw call) lets the enforcement
//! contract map *any* policy failure — a revert, a missing contract, a
//! malformed answer — onto its own stable `policy_unavailable` reason
//! instead of leaking an arbitrary cross-contract error code into the audit
//! trail.

#![no_std]
#[cfg(test)]
extern crate std;

pub mod client;

pub use client::{is_authorized, PolicyClient};
