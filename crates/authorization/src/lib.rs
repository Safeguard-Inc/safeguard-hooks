//! # safeguard-authorization
//!
//! Authority and enforcement-scope rules for the Safeguard enforcement
//! contract (`contracts/compliance-hooks`).
//!
//! Authorization is the question *"who may do this?"* — distinct from
//! compliance, which is *"is this account permitted under the configured
//! rules?"*. The enforcement layer separates the two so that the answer to
//! each question is testable in isolation:
//!
//! ```text
//! Alice is KYC-approved      (compliance: policy says yes)
//! + Alice is not frozen      (compliance: freeze gate)
//! + Alice is authorized…     (authorization: who is acting)
//! ```
//!
//! In a *separate* hooks contract there are only two real authority
//! questions, and this crate answers both:
//!
//! 1. **Who may change enforcement state?** ([`admin`]) A single admin
//!    authority — configured at initialization — gates every state-changing
//!    entry point: token bind/unbind, freeze/unfreeze, and compliance
//!    configuration rotation. There is no anonymous configuration.
//! 2. **Which tokens fall within this contract's scope?** ([`token`]) A
//!    token must be *bound* before any enforcement runs for it. The binding
//!    gate is admission control: hooks invoked for an unbound token are
//!    rejected (`UnboundToken`), which is what makes token spoofing and
//!    cross-token contamination impossible.
//!
//! ## The caller model (why there is no `account` or `spender` module)
//!
//! Soroban contracts cannot introspect their caller — a contract invoked by
//! another contract sees only the arguments it was given. The enforcement
//! contract is invoked *by the confidential token contract* on every gated
//! operation, and there is no on-chain way for it to distinguish "the bound
//! token" from an impersonator.
//!
//! The OpenZeppelin confidential-token compliance design resolves this by
//! making the *token* the gatekeeper of its own hooks: the token is
//! constructed with the compliance contract address, calls it only for
//! operations it is about to apply, and applies nothing when the call
//! reverts. The signer checks that matter — the account authorizing its own
//! `register`, `from` authorizing a delegated spend, the admin behind a
//! freeze — therefore happen **at the token**, where the account, balance,
//! and allowance state actually lives, before the token ever consults this
//! contract. This is why account- and spender-scoped modules deliberately
//! have no home here: re-checking signatures against state we do not hold
//! would be both impossible (no caller) and redundant (the token already
//! checked).
//!
//! What this contract *can* and *must* verify is what it does hold: the
//! authority behind its own state transitions (admin) and the identity of
//! the token it is asked to enforce for, as recorded in its own binding
//! table (token scope). Both gates are fail-closed: an uninitialized
//! contract rejects configuration changes, and an unbound token never
//! triggers enforcement.
//!
//! ## Module map
//!
//! * [`admin`] — the administrative authority gate.
//! * [`token`] — the per-token enforcement-scope gate.
//!
//! Failures are reported with [`safeguard_hook_core::RejectionReason`] so
//! the whole layer speaks one machine-readable vocabulary. Signature
//! failures cannot be returned: `Address::require_auth` panics and reverts
//! the transaction with the host authorization error, which `docs/errors.md`
//! maps to `unauthorized_caller`.

#![no_std]
#[cfg(test)]
extern crate std;

pub mod admin;
pub mod token;

pub use admin::{is_initialized, require_admin};
pub use token::{is_token_bound, require_token_bound};
