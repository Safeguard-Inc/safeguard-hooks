//! # safeguard-events
//!
//! Structured events emitted by the Safeguard enforcement contract.
//!
//! Events are the evidence bridge to `safeguard-audit` (VERIFY): the audit
//! polyrepo indexes these topics to reconstruct *what happened* to the
//! enforcement layer's state.
//!
//! ## What is (and is not) emitted
//!
//! The enforcement layer emits events only for **state changes it applies
//! itself**: freezes, unfreezes, token binds/unbinds, and compliance
//! configuration changes. Per-operation *approvals* are deliberately **not**
//! emitted:
//!
//! * An approval event would be indistinguishable from a spoofed call — any
//!   contract can invoke the hook entry points, and Soroban contracts cannot
//!   introspect their caller. Emitting "approved" records would let an
//!   attacker poison the audit trail at no cost.
//! * A *denial* cannot be emitted at all: enforcement is fail-closed, and a
//!   rejected operation reverts the whole transaction — reverts discard
//!   events. Denials surface as failed transactions (`Error(Contract, #N)`)
//!   carrying the reason code in `docs/errors.md`.
//!
//! The result is an honest audit surface: on-chain events describe
//! enforcement state transitions, never claims about operations the token
//! itself executes.
//!
//! ## Privacy rule
//!
//! No event carries amounts, balances, commitments, ciphertexts, or any
//! private financial data. Topics and payloads name addresses, tokens,
//! policies, and booleans only.

#![no_std]
#[cfg(test)]
extern crate std;

use soroban_sdk::{contractevent, Address, Env};

// ################## FREEZE STATE ##################

/// Emitted when an account is frozen on a token.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountFrozen {
    /// The token on which the account was frozen.
    #[topic]
    pub token: Address,
    /// The frozen account.
    #[topic]
    pub account: Address,
}

/// Publishes an [`AccountFrozen`] event.
pub fn emit_account_frozen(e: &Env, token: &Address, account: &Address) {
    AccountFrozen {
        token: token.clone(),
        account: account.clone(),
    }
    .publish(e);
}

/// Emitted when an account is unfrozen on a token.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountUnfrozen {
    /// The token on which the account was unfrozen.
    #[topic]
    pub token: Address,
    /// The unfrozen account.
    #[topic]
    pub account: Address,
}

/// Publishes an [`AccountUnfrozen`] event.
pub fn emit_account_unfrozen(e: &Env, token: &Address, account: &Address) {
    AccountUnfrozen {
        token: token.clone(),
        account: account.clone(),
    }
    .publish(e);
}

// ################## TOKEN BINDINGS ##################

/// Emitted when a token is bound to the enforcement contract.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenBound {
    /// The token now subject to enforcement.
    #[topic]
    pub token: Address,
}

/// Publishes a [`TokenBound`] event.
pub fn emit_token_bound(e: &Env, token: &Address) {
    TokenBound {
        token: token.clone(),
    }
    .publish(e);
}

/// Emitted when a token is unbound from the enforcement contract.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenUnbound {
    /// The token no longer subject to enforcement.
    #[topic]
    pub token: Address,
}

/// Publishes a [`TokenUnbound`] event.
pub fn emit_token_unbound(e: &Env, token: &Address) {
    TokenUnbound {
        token: token.clone(),
    }
    .publish(e);
}

// ################## CONFIGURATION ##################

/// Emitted whenever the compliance configuration is written or rotated.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComplianceConfigChanged {
    /// The policy address after the change (`None` = gate disabled).
    pub policy: Option<Address>,
    /// The SAC passthrough flag after the change.
    pub sac_passthrough: bool,
}

/// Publishes a [`ComplianceConfigChanged`] event.
pub fn emit_compliance_config_changed(e: &Env, policy: &Option<Address>, sac_passthrough: bool) {
    ComplianceConfigChanged {
        policy: policy.clone(),
        sac_passthrough,
    }
    .publish(e);
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{Address as _, EnvTestConfig, Events};
    use soroban_sdk::{contract, contractimpl, Event as _};

    /// Host exposing one publish path per event type so tests exercise real
    /// contract invocations (events are only observable after one).
    #[contract]
    struct EventHost;

    #[contractimpl]
    impl EventHost {
        pub fn frozen(e: Env, token: Address, account: Address) {
            emit_account_frozen(&e, &token, &account);
        }

        pub fn unfrozen(e: Env, token: Address, account: Address) {
            emit_account_unfrozen(&e, &token, &account);
        }

        pub fn bound(e: Env, token: Address) {
            emit_token_bound(&e, &token);
        }

        pub fn unbound(e: Env, token: Address) {
            emit_token_unbound(&e, &token);
        }

        pub fn config_changed(e: Env, policy: Option<Address>, sac_passthrough: bool) {
            emit_compliance_config_changed(&e, &policy, sac_passthrough);
        }
    }

    fn event_env() -> (Env, Address) {
        let e = Env::new_with_config(EnvTestConfig {
            capture_snapshot_at_drop: false,
        });
        let host = e.register(EventHost, ());
        (e, host)
    }

    #[test]
    fn freeze_event_carries_name_token_and_account_topics() {
        let (e, host) = event_env();
        let token = Address::generate(&e);
        let alice = Address::generate(&e);

        EventHostClient::new(&e, &host).frozen(&token, &alice);

        assert_eq!(
            e.events().all(),
            [AccountFrozen {
                token: token.clone(),
                account: alice.clone()
            }
            .to_xdr(&e, &host)]
        );
    }

    #[test]
    fn each_invocation_reports_only_its_own_events() {
        let (e, host) = event_env();
        let token = Address::generate(&e);
        let alice = Address::generate(&e);

        let client = EventHostClient::new(&e, &host);
        client.frozen(&token, &alice);
        client.unfrozen(&token, &alice);

        // Only the events of the *last* invocation are observable.
        assert_eq!(
            e.events().all(),
            [AccountUnfrozen {
                token,
                account: alice
            }
            .to_xdr(&e, &host)]
        );
    }

    #[test]
    fn binding_events_carry_token_topic() {
        let (e, host) = event_env();
        let token = Address::generate(&e);

        let client = EventHostClient::new(&e, &host);
        client.bound(&token);
        assert_eq!(
            e.events().all(),
            [TokenBound {
                token: token.clone()
            }
            .to_xdr(&e, &host)]
        );

        client.unbound(&token);
        assert_eq!(e.events().all(), [TokenUnbound { token }.to_xdr(&e, &host)]);
    }

    #[test]
    fn config_event_carries_policy_and_flag_as_data() {
        let (e, host) = event_env();
        let policy = Address::generate(&e);

        EventHostClient::new(&e, &host).config_changed(&Some(policy.clone()), &true);

        assert_eq!(
            e.events().all(),
            [ComplianceConfigChanged {
                policy: Some(policy),
                sac_passthrough: true,
            }
            .to_xdr(&e, &host)]
        );
    }

    #[test]
    fn events_are_attributed_to_the_publishing_contract() {
        let (e, host) = event_env();
        let token = Address::generate(&e);

        EventHostClient::new(&e, &host).bound(&token);

        let all = e.events().all();
        assert_eq!(all.events().len(), 1);
        // The emitted event is attributed to the host contract and carries
        // exactly two topics: the event name and the token address.
        assert_eq!(all.filter_by_contract(&host).events().len(), 1);
    }
}
