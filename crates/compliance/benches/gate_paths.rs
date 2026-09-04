//! Criterion benchmarks for the enforcement **gate paths**.
//!
//! Each benchmark times one named path through the evaluator — the rows of
//! the gate/cost table in `docs/performance.md`:
//!
//! * structural denials (unconfigured contract, unbound token) — the two
//!   cheap local-read gates before any party is screened;
//! * freeze denials (first party, and second party after the first screened
//!   clean) — local reads, and at most one policy call on the second-party
//!   case;
//! * a policy denial on the second party;
//! * the allowed paths for each operation shape (register, deposit,
//!   transfer-from with its three parties, and withdraw's deliberate
//!   double-screen of the exiting account);
//! * the full gate with SAC passthrough enabled (freeze + policy + SAC per
//!   fund-holding party).
//!
//! The behavior of every path is pinned by the unit tests in
//! `crates/compliance/src/evaluator.rs` (exact decisions) and the
//! counting-policy tests (exact number of cross-contract calls); the mock
//! contracts below are minimal stand-ins registered purely so a bench
//! target can drive the paths. The benchmarks add what those tests cannot:
//! wall-clock cost per path on a real `Env`.
//!
//! Run with `cargo bench -p safeguard-compliance` (the `--test` flag runs
//! every benchmark once to verify the fixtures without timing).

use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};
use soroban_sdk::testutils::{Address as _, EnvTestConfig};
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

use safeguard_compliance::{
    evaluate_deposit, evaluate_register, evaluate_transfer_from, evaluate_withdraw,
};
use safeguard_hook_core::{ComplianceDecision, RejectionReason};
use safeguard_storage::{bind_token, freeze_account, set_compliance_config, ComplianceConfig};

/// Storage host whose instance/persistent storage the evaluator reads.
/// Mirrors the `EvalHost` of the unit tests: all evaluation happens under
/// this contract's address.
#[contract]
struct Host;

#[contractimpl]
impl Host {}

/// Deny-list policy over the `safeguard-policy` wire contract: authorizes
/// every account except the constructor-pinned one (`None` = allow-all).
/// Behaviorally equivalent to the test mock; kept read-only so repeated
/// iterations time a stable policy call.
#[contract]
struct DenyPolicy;

#[contractimpl]
impl DenyPolicy {
    pub fn __constructor(e: Env, blocked: Option<Address>) {
        e.storage().instance().set(&symbol_short!("blkd"), &blocked);
    }

    pub fn is_authorized(e: Env, account: Address, _token: Address) -> bool {
        let blocked: Option<Address> = e.storage().instance().get(&symbol_short!("blkd")).unwrap();
        Some(account) != blocked
    }
}

/// Minimal Stellar Asset Contract: authorizes exactly the two fixture
/// accounts. Only consulted on the SAC-passthrough path.
#[contract]
struct MockSac;

#[contractimpl]
impl MockSac {
    pub fn __constructor(e: Env, alice: Address, bob: Address) {
        e.storage().instance().set(&symbol_short!("a"), &alice);
        e.storage().instance().set(&symbol_short!("b"), &bob);
    }

    pub fn authorized(e: Env, id: Address) -> bool {
        let alice: Address = e.storage().instance().get(&symbol_short!("a")).unwrap();
        let bob: Address = e.storage().instance().get(&symbol_short!("b")).unwrap();
        id == alice || id == bob
    }
}

/// One registered host with a bound token (over a SAC authorizing both
/// fixture accounts), plus the addresses a gate path needs. Configuration
/// and freeze state are written per benchmark so each one times exactly the
/// named path.
struct Fixture {
    env: Env,
    host: Address,
    token: Address,
    stranger: Address,
    alice: Address,
    bob: Address,
    spender: Address,
}

fn fixture() -> Fixture {
    let env = Env::new_with_config(EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    let host = env.register(Host, ());
    let token = Address::generate(&env);
    let stranger = Address::generate(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    let spender = Address::generate(&env);
    let sac = env.register(MockSac, (&alice, &bob));

    env.as_contract(&host, || {
        bind_token(&env, &token, Some(&sac));
    });

    Fixture {
        env,
        host,
        token,
        stranger,
        alice,
        bob,
        spender,
    }
}

/// Registers a deny-list policy (blocking `blocked`, or allow-all when
/// `None`) and activates it in the compliance configuration.
fn configure(f: &Fixture, blocked: Option<&Address>, sac_passthrough: bool) {
    let policy = f.env.register(DenyPolicy, (blocked.cloned(),));
    f.env.as_contract(&f.host, || {
        set_compliance_config(
            &f.env,
            &ComplianceConfig {
                policy: Some(policy),
                sac_passthrough,
            },
        );
    });
}

fn measure(
    c: &mut Criterion,
    name: &str,
    fixture: &Fixture,
    expected: ComplianceDecision,
    timed: impl Fn(&Fixture) -> ComplianceDecision,
) {
    // Prove the fixture actually drives the named path before timing it; a
    // benchmark of the wrong path would silently measure the wrong cost.
    let decision = timed(fixture);
    assert_eq!(decision, expected, "benchmark `{name}` fixture drifted");

    c.bench_function(name, |b| {
        b.iter(|| std::hint::black_box(timed(std::hint::black_box(fixture))))
    });
}

fn structural_denial_unconfigured(c: &mut Criterion) {
    // No compliance configuration at all: the single instance-storage read
    // fails closed before any gate runs.
    let f = fixture();
    measure(
        c,
        "gate/deny_unconfigured",
        &f,
        ComplianceDecision::Deny(RejectionReason::InvalidConfiguration),
        |f| {
            f.env
                .as_contract(&f.host, || evaluate_register(&f.env, &f.token, &f.alice))
        },
    );
}

fn structural_denial_unbound_token(c: &mut Criterion) {
    // Configured and bound, but the operation names a token with no binding
    // entry: rejected at the token-scope gate, before any party is screened.
    let f = fixture();
    configure(&f, None, false);
    measure(
        c,
        "gate/deny_unbound_token",
        &f,
        ComplianceDecision::Deny(RejectionReason::UnboundToken),
        |f| {
            f.env
                .as_contract(&f.host, || evaluate_register(&f.env, &f.stranger, &f.alice))
        },
    );
}

fn freeze_denial_first_party(c: &mut Criterion) {
    // A frozen sender: denied at the local freeze gate of the first party —
    // zero cross-contract calls.
    let f = fixture();
    configure(&f, None, false);
    f.env.as_contract(&f.host, || {
        freeze_account(&f.env, &f.token, &f.alice);
    });
    measure(
        c,
        "gate/deny_frozen_first_party",
        &f,
        ComplianceDecision::Deny(RejectionReason::AccountFrozen),
        |f| {
            f.env.as_contract(&f.host, || {
                evaluate_deposit(&f.env, &f.token, &f.alice, &f.bob)
            })
        },
    );
}

fn freeze_denial_second_party(c: &mut Criterion) {
    // The sender screens clean (one policy call), then the frozen recipient
    // denies at its local freeze gate — the chain stops at the first
    // failing party.
    let f = fixture();
    configure(&f, None, false);
    f.env.as_contract(&f.host, || {
        freeze_account(&f.env, &f.token, &f.bob);
    });
    measure(
        c,
        "gate/deny_frozen_second_party",
        &f,
        ComplianceDecision::Deny(RejectionReason::AccountFrozen),
        |f| {
            f.env.as_contract(&f.host, || {
                evaluate_deposit(&f.env, &f.token, &f.alice, &f.bob)
            })
        },
    );
}

fn policy_denial_second_party(c: &mut Criterion) {
    // The sender passes the policy gate; the blocked recipient is denied on
    // its policy call.
    let f = fixture();
    configure(&f, Some(&f.bob), false);
    measure(
        c,
        "gate/deny_policy_second_party",
        &f,
        ComplianceDecision::Deny(RejectionReason::PolicyDenied),
        |f| {
            f.env.as_contract(&f.host, || {
                evaluate_deposit(&f.env, &f.token, &f.alice, &f.bob)
            })
        },
    );
}

fn allow_register_single_party(c: &mut Criterion) {
    // The single-party allow path: freeze read + one policy call.
    let f = fixture();
    configure(&f, None, false);
    measure(
        c,
        "gate/allow_register_single_party",
        &f,
        ComplianceDecision::Allow,
        |f| {
            f.env
                .as_contract(&f.host, || evaluate_register(&f.env, &f.token, &f.alice))
        },
    );
}

fn allow_deposit_two_parties(c: &mut Criterion) {
    // The two-party allow path: freeze read + policy call per party.
    let f = fixture();
    configure(&f, None, false);
    measure(
        c,
        "gate/allow_deposit_two_parties",
        &f,
        ComplianceDecision::Allow,
        |f| {
            f.env.as_contract(&f.host, || {
                evaluate_deposit(&f.env, &f.token, &f.alice, &f.bob)
            })
        },
    );
}

fn allow_transfer_from_three_parties(c: &mut Criterion) {
    // Delegated flow: the spender is screened by policy only, `from` and
    // `to` pass the full gate — three policy calls in total.
    let f = fixture();
    configure(&f, None, false);
    measure(
        c,
        "gate/allow_transfer_from_three_parties",
        &f,
        ComplianceDecision::Allow,
        |f| {
            f.env.as_contract(&f.host, || {
                evaluate_transfer_from(&f.env, &f.token, &f.spender, &f.alice, &f.bob)
            })
        },
    );
}

fn allow_withdraw_double_screen(c: &mut Criterion) {
    // Withdraw names the exiting account in both roles and screens it twice
    // (the documented, deliberate redundancy): two policy calls on one
    // account.
    let f = fixture();
    configure(&f, None, false);
    measure(
        c,
        "gate/allow_withdraw_double_screen",
        &f,
        ComplianceDecision::Allow,
        |f| {
            f.env
                .as_contract(&f.host, || evaluate_withdraw(&f.env, &f.token, &f.alice))
        },
    );
}

fn full_gate_sac_passthrough(c: &mut Criterion) {
    // The most expensive allowed path: policy *and* SAC passthrough enabled,
    // so each fund-holding party pays freeze read + policy call + SAC call.
    let f = fixture();
    configure(&f, None, true);
    measure(
        c,
        "gate/allow_full_gate_sac_passthrough",
        &f,
        ComplianceDecision::Allow,
        |f| {
            f.env.as_contract(&f.host, || {
                evaluate_deposit(&f.env, &f.token, &f.alice, &f.bob)
            })
        },
    );
}

criterion_group! {
    name = gate_paths;
    config = Criterion::default().measurement_time(Duration::from_secs(2));
    targets =
        structural_denial_unconfigured,
        structural_denial_unbound_token,
        freeze_denial_first_party,
        freeze_denial_second_party,
        policy_denial_second_party,
        allow_register_single_party,
        allow_deposit_two_parties,
        allow_transfer_from_three_parties,
        allow_withdraw_double_screen,
        full_gate_sac_passthrough,
}

criterion_main!(gate_paths);
