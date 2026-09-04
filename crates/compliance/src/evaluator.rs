//! The enforcement evaluation pipeline.
//!
//! [`evaluate`] runs the gates for one operation and combines the results
//! into a single decision. The gate order is deliberate and documented in
//! the crate docs: configuration and token-scope checks first (cheap,
//! structural), then per party — freeze (local storage) before policy
//! (cross-contract) before SAC (cross-contract).
//!
//! The pipeline never decides *eligibility* itself. Policy answers come from
//! the external `safeguard-policy` contract through
//! `safeguard-policy-client`; this module only enforces them and translates
//! an unevaluable policy into a denial.

use soroban_sdk::{Address, Env};

use safeguard_authorization::require_token_bound;
use safeguard_hook_core::{ComplianceDecision, Operation, PartyRole, RejectionReason};
use safeguard_policy_client;
use safeguard_storage::{compliance_config, is_frozen, token_binding, ComplianceConfig};

use crate::sac;

/// Evaluates one operation for `token`, gating the parties listed in
/// `parties` — in the canonical order of [`Operation::parties`] — and
/// returns the combined decision.
///
/// `parties` must name exactly one address per party role the operation
/// declares; a length mismatch is a wiring error and is treated as an
/// invalid configuration (fail-closed, and visible in tests immediately).
pub fn evaluate(
    e: &Env,
    token: &Address,
    operation: Operation,
    parties: &[&Address],
) -> ComplianceDecision {
    // 1. Configuration present? An unconfigured enforcement contract cannot
    //    enforce anything; it must not silently pass operations either.
    let Some(config) = compliance_config(e) else {
        return ComplianceDecision::Deny(RejectionReason::InvalidConfiguration);
    };

    // 2. Token in scope? Unbound tokens are rejected before any gate runs.
    if let Err(reason) = require_token_bound(e, token) {
        return ComplianceDecision::Deny(reason);
    }

    // The token's binding also carries its underlying SAC (when it has one).
    let sac = token_binding(e, token).and_then(|binding| binding.sac);

    let roles = operation.parties();
    if roles.len() != parties.len() {
        return ComplianceDecision::Deny(RejectionReason::InvalidConfiguration);
    }

    let mut decision = ComplianceDecision::Allow;
    for (role, account) in roles.iter().copied().zip(parties.iter().copied()) {
        decision = decision.and_then(screen_party(e, token, role, account, &config, sac.as_ref()));
    }
    decision
}

/// Screens a single party through the gates its role requires.
///
/// Gate order inside a party: freeze (only fund-holding roles) → policy
/// (every role) → SAC (only fund-holding roles, only when enabled).
fn screen_party(
    e: &Env,
    token: &Address,
    role: PartyRole,
    account: &Address,
    config: &ComplianceConfig,
    sac: Option<&Address>,
) -> ComplianceDecision {
    let holds_funds = role.holds_funds();

    // Freeze: a frozen fund-holder can neither send, receive, deposit, nor
    // withdraw. The spender holds no funds and is not freeze-gated.
    if holds_funds && is_frozen(e, token, account) {
        return ComplianceDecision::Deny(RejectionReason::AccountFrozen);
    }

    // Policy: every named party is screened, spender included.
    if let Some(policy) = &config.policy {
        match safeguard_policy_client::is_authorized(e, policy, account, token) {
            Ok(true) => {}
            Ok(false) => return ComplianceDecision::Deny(RejectionReason::PolicyDenied),
            Err(reason) => return ComplianceDecision::Deny(reason),
        }
    }

    // SAC passthrough: compose the issuer's own authorization state, when
    // the token wraps a SAC and the deployment enabled the check.
    if holds_funds && config.sac_passthrough {
        if let Some(sac) = sac {
            match sac::is_authorized(e, sac, account) {
                Ok(true) => {}
                Ok(false) | Err(_) => {
                    return ComplianceDecision::Deny(RejectionReason::SacAuthorizationFailed)
                }
            }
        }
    }

    ComplianceDecision::Allow
}

/// Evaluates an account registration on `token`.
pub fn evaluate_register(e: &Env, token: &Address, account: &Address) -> ComplianceDecision {
    evaluate(
        e,
        token,
        Operation::Register,
        core::slice::from_ref(&account),
    )
}

/// Evaluates a deposit on `token` (external depositor `from` → wrapper
/// account `to`).
pub fn evaluate_deposit(
    e: &Env,
    token: &Address,
    from: &Address,
    to: &Address,
) -> ComplianceDecision {
    let parties = [from, to];
    evaluate(e, token, Operation::Deposit, &parties)
}

/// Evaluates a confidential transfer on `token` (`from` → `to`).
pub fn evaluate_transfer(
    e: &Env,
    token: &Address,
    from: &Address,
    to: &Address,
) -> ComplianceDecision {
    let parties = [from, to];
    evaluate(e, token, Operation::Transfer, &parties)
}

/// Evaluates a withdrawal on `token`: the exiting account is both the
/// source and the destination of the underlying move, so it is gated once
/// per role it plays.
pub fn evaluate_withdraw(e: &Env, token: &Address, account: &Address) -> ComplianceDecision {
    let parties = [account, account];
    evaluate(e, token, Operation::Withdraw, &parties)
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{Address as _, EnvTestConfig};
    use soroban_sdk::{contract, contractimpl, symbol_short};

    use safeguard_storage::{bind_token, set_compliance_config, ComplianceConfig};

    /// Deny-list policy: authorizes every account on the pinned token except
    /// one blocked account. Lets tests put both parties of an operation on
    /// the allow side by default and block a single party at will.
    #[contract]
    struct DenylistPolicy;

    #[contractimpl]
    impl DenylistPolicy {
        pub fn __constructor(e: Env, blocked: Option<Address>, token: Address) {
            e.storage().instance().set(&symbol_short!("blkd"), &blocked);
            e.storage().instance().set(&symbol_short!("tokn"), &token);
        }

        pub fn is_authorized(e: Env, account: Address, token: Address) -> bool {
            let blocked: Option<Address> =
                e.storage().instance().get(&symbol_short!("blkd")).unwrap();
            let bound: Address = e.storage().instance().get(&symbol_short!("tokn")).unwrap();
            token == bound && Some(account) != blocked
        }
    }

    /// A policy that always reverts: models an unavailable policy contract.
    #[contract]
    struct RevertingPolicy;

    #[contractimpl]
    impl RevertingPolicy {
        pub fn is_authorized(_e: Env, _account: Address, _token: Address) -> bool {
            panic!("policy unavailable")
        }
    }

    /// Minimal SAC: authorizes exactly the accounts given at construction.
    #[contract]
    struct MockSac;

    #[contractimpl]
    impl MockSac {
        pub fn __constructor(e: Env, authorized_a: Address, authorized_b: Address) {
            e.storage()
                .instance()
                .set(&symbol_short!("a"), &authorized_a);
            e.storage()
                .instance()
                .set(&symbol_short!("b"), &authorized_b);
        }

        pub fn authorized(e: Env, id: Address) -> bool {
            let a: Address = e.storage().instance().get(&symbol_short!("a")).unwrap();
            let b: Address = e.storage().instance().get(&symbol_short!("b")).unwrap();
            id == a || id == b
        }
    }

    /// A SAC that always reverts.
    #[contract]
    struct RevertingSac;

    #[contractimpl]
    impl RevertingSac {
        pub fn authorized(_e: Env, _id: Address) -> bool {
            panic!("sac unavailable")
        }
    }

    /// The contract whose storage the evaluation reads.
    #[contract]
    struct EvalHost;

    #[contractimpl]
    impl EvalHost {}

    /// Test fixture: a registered host with one bound token (over a SAC that
    /// authorizes both `alice` and `bob`), plus two fresh addresses.
    struct Fixture {
        env: Env,
        host: Address,
        token: Address,
        alice: Address,
        bob: Address,
    }

    fn fixture() -> Fixture {
        let (env, host) = host_env();
        let token = Address::generate(&env);
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        let sac = env.register(MockSac, (&alice, &bob));

        env.as_contract(&host, || {
            bind_token(&env, &token, Some(&sac));
        });

        Fixture {
            env,
            host,
            token,
            alice,
            bob,
        }
    }

    fn host_env() -> (Env, Address) {
        let e = Env::new_with_config(EnvTestConfig {
            capture_snapshot_at_drop: false,
        });
        let host = e.register(EvalHost, ());
        (e, host)
    }

    fn register_policy(f: &Fixture, blocked: Option<&Address>) -> Address {
        f.env.register(DenylistPolicy, (blocked.cloned(), &f.token))
    }

    fn set_policy(f: &Fixture, policy: Option<&Address>, sac_passthrough: bool) {
        f.env.as_contract(&f.host, || {
            set_compliance_config(
                &f.env,
                &ComplianceConfig {
                    policy: policy.cloned(),
                    sac_passthrough,
                },
            );
        });
    }

    #[test]
    fn unconfigured_contract_denies_every_operation() {
        let f = fixture();
        let decision = f.env.as_contract(&f.host, || {
            evaluate_deposit(&f.env, &f.token, &f.alice, &f.bob)
        });
        assert_eq!(
            decision,
            ComplianceDecision::Deny(RejectionReason::InvalidConfiguration)
        );
    }

    #[test]
    fn unbound_token_is_rejected_before_any_gate() {
        let f = fixture();
        let policy = register_policy(&f, None);
        set_policy(&f, Some(&policy), false);
        let stranger = Address::generate(&f.env);

        // `stranger` is not bound, even though the policy would allow both
        // parties.
        let decision = f.env.as_contract(&f.host, || {
            evaluate_deposit(&f.env, &stranger, &f.alice, &f.bob)
        });
        assert_eq!(
            decision,
            ComplianceDecision::Deny(RejectionReason::UnboundToken)
        );
    }

    #[test]
    fn fully_compliant_operation_is_allowed() {
        let f = fixture();
        let policy = register_policy(&f, None);
        set_policy(&f, Some(&policy), false);

        // Nobody blocked, nobody frozen, SAC passthrough off.
        let decision = f.env.as_contract(&f.host, || {
            evaluate_deposit(&f.env, &f.token, &f.alice, &f.bob)
        });
        assert_eq!(decision, ComplianceDecision::Allow);
    }

    #[test]
    fn frozen_sender_is_rejected() {
        let f = fixture();
        let policy = register_policy(&f, None);
        set_policy(&f, Some(&policy), false);
        f.env.as_contract(&f.host, || {
            safeguard_storage::freeze_account(&f.env, &f.token, &f.alice);
        });

        let decision = f.env.as_contract(&f.host, || {
            evaluate_deposit(&f.env, &f.token, &f.alice, &f.bob)
        });
        assert_eq!(
            decision,
            ComplianceDecision::Deny(RejectionReason::AccountFrozen)
        );
    }

    #[test]
    fn frozen_recipient_is_rejected() {
        let f = fixture();
        let policy = register_policy(&f, None);
        set_policy(&f, Some(&policy), false);
        f.env.as_contract(&f.host, || {
            safeguard_storage::freeze_account(&f.env, &f.token, &f.bob);
        });

        // The sender passes; the frozen recipient stops the operation.
        let decision = f.env.as_contract(&f.host, || {
            evaluate_deposit(&f.env, &f.token, &f.alice, &f.bob)
        });
        assert_eq!(
            decision,
            ComplianceDecision::Deny(RejectionReason::AccountFrozen)
        );
    }

    #[test]
    fn freeze_is_reported_before_a_later_policy_denial() {
        let f = fixture();
        // Bob is blocked by policy AND Alice is frozen. The first party's
        // (Alice's) freeze gate fires before any policy round-trip, so the
        // deterministic top-of-chain reason is AccountFrozen.
        let policy = register_policy(&f, Some(&f.bob));
        set_policy(&f, Some(&policy), false);
        f.env.as_contract(&f.host, || {
            safeguard_storage::freeze_account(&f.env, &f.token, &f.alice);
        });

        let decision = f.env.as_contract(&f.host, || {
            evaluate_deposit(&f.env, &f.token, &f.alice, &f.bob)
        });
        assert_eq!(
            decision,
            ComplianceDecision::Deny(RejectionReason::AccountFrozen)
        );
    }

    #[test]
    fn blocked_sender_is_policy_denied() {
        let f = fixture();
        let policy = register_policy(&f, Some(&f.alice));
        set_policy(&f, Some(&policy), false);

        let decision = f.env.as_contract(&f.host, || {
            evaluate_deposit(&f.env, &f.token, &f.alice, &f.bob)
        });
        assert_eq!(
            decision,
            ComplianceDecision::Deny(RejectionReason::PolicyDenied)
        );
    }

    #[test]
    fn blocked_recipient_is_policy_denied() {
        let f = fixture();
        let policy = register_policy(&f, Some(&f.bob));
        set_policy(&f, Some(&policy), false);

        // The sender passes; the blocked recipient denies the operation.
        let decision = f.env.as_contract(&f.host, || {
            evaluate_deposit(&f.env, &f.token, &f.alice, &f.bob)
        });
        assert_eq!(
            decision,
            ComplianceDecision::Deny(RejectionReason::PolicyDenied)
        );
    }

    #[test]
    fn reverting_policy_is_reported_unavailable() {
        let f = fixture();
        let policy = f.env.register(RevertingPolicy, ());
        set_policy(&f, Some(&policy), false);

        let decision = f
            .env
            .as_contract(&f.host, || evaluate_register(&f.env, &f.token, &f.alice));
        assert_eq!(
            decision,
            ComplianceDecision::Deny(RejectionReason::PolicyUnavailable)
        );
    }

    #[test]
    fn missing_policy_gate_skips_policy_entirely() {
        let f = fixture();
        set_policy(&f, None, false);

        let decision = f
            .env
            .as_contract(&f.host, || evaluate_register(&f.env, &f.token, &f.alice));
        assert_eq!(decision, ComplianceDecision::Allow);
    }

    #[test]
    fn sac_passthrough_denies_when_sac_deauthorizes() {
        let f = fixture();
        set_policy(&f, None, true);

        // Carol is not SAC-authorized (the fixture SAC knows only Alice and
        // Bob), so a deposit *by* Carol is denied at the SAC gate.
        let carol = Address::generate(&f.env);
        let decision = f.env.as_contract(&f.host, || {
            evaluate_deposit(&f.env, &f.token, &carol, &f.alice)
        });
        assert_eq!(
            decision,
            ComplianceDecision::Deny(RejectionReason::SacAuthorizationFailed)
        );
    }

    #[test]
    fn sac_passthrough_consults_the_sac() {
        let f = fixture();
        set_policy(&f, None, true);

        // Alice and Bob are both SAC-authorized: allowed.
        let decision = f.env.as_contract(&f.host, || {
            evaluate_deposit(&f.env, &f.token, &f.alice, &f.bob)
        });
        assert_eq!(decision, ComplianceDecision::Allow);
    }

    #[test]
    fn sac_is_not_consulted_when_passthrough_is_off() {
        let f = fixture();
        set_policy(&f, None, false);

        // Carol is SAC-denied but the deployment turned passthrough off, so
        // the SAC is not consulted and the operation proceeds.
        let carol = Address::generate(&f.env);
        let decision = f.env.as_contract(&f.host, || {
            evaluate_deposit(&f.env, &f.token, &carol, &f.alice)
        });
        assert_eq!(decision, ComplianceDecision::Allow);
    }

    #[test]
    fn reverting_sac_fails_closed() {
        let f = fixture();
        let bad_sac = f.env.register(RevertingSac, ());
        f.env.as_contract(&f.host, || {
            bind_token(&f.env, &f.token, Some(&bad_sac));
        });
        set_policy(&f, None, true);

        let decision = f
            .env
            .as_contract(&f.host, || evaluate_register(&f.env, &f.token, &f.alice));
        assert_eq!(
            decision,
            ComplianceDecision::Deny(RejectionReason::SacAuthorizationFailed)
        );
    }

    #[test]
    fn withdraw_gates_the_exiting_account() {
        let f = fixture();
        set_policy(&f, None, false);

        let ok = f
            .env
            .as_contract(&f.host, || evaluate_withdraw(&f.env, &f.token, &f.alice));
        assert_eq!(ok, ComplianceDecision::Allow);

        // A frozen account cannot exit the wrapper to bypass the freeze.
        f.env.as_contract(&f.host, || {
            safeguard_storage::freeze_account(&f.env, &f.token, &f.alice);
        });
        let denied = f
            .env
            .as_contract(&f.host, || evaluate_withdraw(&f.env, &f.token, &f.alice));
        assert_eq!(
            denied,
            ComplianceDecision::Deny(RejectionReason::AccountFrozen)
        );
    }

    #[test]
    fn register_gates_the_registered_account() {
        let f = fixture();
        let policy = register_policy(&f, Some(&f.bob));
        set_policy(&f, Some(&policy), false);

        let ok = f
            .env
            .as_contract(&f.host, || evaluate_register(&f.env, &f.token, &f.alice));
        assert_eq!(ok, ComplianceDecision::Allow);

        // A blocked account cannot register.
        let denied = f
            .env
            .as_contract(&f.host, || evaluate_register(&f.env, &f.token, &f.bob));
        assert_eq!(
            denied,
            ComplianceDecision::Deny(RejectionReason::PolicyDenied)
        );
    }

    #[test]
    fn decisions_are_isolated_per_token() {
        let f = fixture();
        let policy = register_policy(&f, None);
        set_policy(&f, Some(&policy), false);

        // Token B is bound with no SAC; the policy is pinned to Token A.
        let token_b = Address::generate(&f.env);
        f.env.as_contract(&f.host, || {
            bind_token(&f.env, &token_b, None);
        });

        // Alice is fine on Token A, but the same policy denies everyone on
        // Token B (the policy mock checks the token argument) — a decision
        // for one token never leaks into another.
        let on_a = f
            .env
            .as_contract(&f.host, || evaluate_register(&f.env, &f.token, &f.alice));
        let on_b = f
            .env
            .as_contract(&f.host, || evaluate_register(&f.env, &token_b, &f.alice));
        assert_eq!(on_a, ComplianceDecision::Allow);
        assert_eq!(
            on_b,
            ComplianceDecision::Deny(RejectionReason::PolicyDenied)
        );
    }
}
