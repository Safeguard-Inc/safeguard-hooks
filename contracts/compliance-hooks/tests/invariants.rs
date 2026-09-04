//! Invariant suite for the `compliance-hooks` contract.
//!
//! The invariants asserted here are the system-level properties behind the
//! design (`docs/enforcement-model.md`, `docs/security.md`):
//!
//! 1. **Enforcement is read-only with respect to its own state.** Hook
//!    evaluations (allowed or denied) never write bindings, freeze flags, or
//!    configuration; the only writers are the admin-gated administration
//!    entry points.
//! 2. **Frozen until unfrozen.** No sequence of policy rotations or config
//!    changes thaws a frozen account — only an admin `unfreeze` does.
//! 3. **Outcomes match the enforcement oracle exhaustively.** For every
//!    operation × party combination × token, the contract's answer equals
//!    the predicted answer derived from party roles and gate order — which
//!    pins down "an allowed operation implies nobody it names is frozen,
//!    blocked, or SAC-denied".
//! 4. **Out of scope never allows.** Unbound tokens, unconfigured
//!    contracts, and unbound-after-unbind never admit an operation.

mod common;

use common::*;
use soroban_sdk::testutils::{Address as _, EnvTestConfig};
use soroban_sdk::{Address, Env};

/// The observable enforcement state used for snapshot comparisons: the
/// configuration version, which tokens are bound, and who is frozen where.
/// The configuration version only moves on admin rewrites; hook evaluations
/// must never bump it.
fn snapshot(c: &Ctx) -> Vec<u32> {
    let tokens = [&c.token_a, &c.token_b];
    let accounts = [&c.alice, &c.bob, &c.carol];
    let mut s = Vec::with_capacity(2 + 6 + 1);
    s.push(view_u32(&c.env, &c.hooks, "config_version", ()));
    for t in &tokens {
        s.push(c.token_is_bound(t) as u32);
    }
    for t in &tokens {
        for a in &accounts {
            s.push(c.is_frozen(t, a) as u32);
        }
    }
    s
}

#[test]
fn hook_evaluations_never_write_contract_state() {
    let c = deploy();

    // Intended state changes first: freeze Alice on A and Bob on B, and
    // block Bob by policy — so the traffic below yields a mix of allows
    // and denials of every flavor.
    c.freeze(&c.token_a, &c.alice);
    c.freeze(&c.token_b, &c.bob);
    c.rotate_policy(Some(&c.bob));
    let before = snapshot(&c);

    // A spread of allowed and denied evaluations across both tokens and all
    // six operations.
    let ops = [
        ("register", vec![c.carol.clone()]),
        ("deposit", vec![c.alice.clone(), c.bob.clone()]), // to Bob: blocked
        ("deposit", vec![c.carol.clone(), c.alice.clone()]), // Carol: SAC-denied
        ("deposit", vec![c.carol.clone(), c.carol.clone()]), // Carol as to: SAC-denied
        ("transfer", vec![c.alice.clone(), c.alice.clone()]), // Alice frozen
        ("transfer", vec![c.bob.clone(), c.carol.clone()]), // Bob frozen
        ("withdraw", vec![c.bob.clone()]),                 // frozen
        ("merge", vec![c.carol.clone()]),                  // allowed
        (
            "transfer_from",
            vec![c.spender.clone(), c.carol.clone(), c.bob.clone()],
        ),
        (
            "transfer_from",
            vec![c.spender.clone(), c.spender.clone(), c.carol.clone()],
        ),
    ];
    for (op, parties) in &ops {
        for token in [&c.token_a, &c.token_b] {
            // The outcome does not matter for this invariant; run it as a
            // token would, and ignore success/failure.
            let _ = c.hook(op, token, parties);
        }
    }

    // None of the evaluations above touched enforcement state.
    assert_eq!(snapshot(&c), before);
}

#[test]
fn frozen_until_unfrozen_regardless_of_policy_configuration() {
    let c = deploy();
    c.freeze(&c.token_a, &c.alice);

    // Every configuration state must keep refusing operations that name the
    // frozen account — even when the policy blocks a *different* party (the
    // blocked party is then the first denial, per gate order, but the freeze
    // must never be lifted) or when SAC passthrough is off entirely. A
    // freeze belongs to the contract's own state, so no policy rotation or
    // configuration change may thaw it: outcomes must equal the oracle's
    // under each configuration.
    // The discriminants pick the exact admin transition: 0/1 rotate to a
    // policy contract (allow-all / blocking Bob), 2/3 rewrite the config
    // with no policy at all (SAC off / on).
    let kinds: [(u8, &str, Option<&Address>, bool); 4] = [
        (0, "allow-all policy + SAC on", None, true),
        (
            1,
            "policy blocking another account + SAC on",
            Some(&c.bob),
            true,
        ),
        (2, "no policy, SAC off", None, false),
        (3, "no policy, SAC on", None, true),
    ];
    for (kind, name, blocked, sac_passthrough) in kinds {
        match kind {
            0 => c.rotate_policy(None),
            1 => c.rotate_policy(blocked),
            2 => c.disable_policy(false),
            3 => c.disable_policy(true),
            _ => unreachable!(),
        }
        assert!(
            c.is_frozen(&c.token_a, &c.alice),
            "admin rotations must never thaw a frozen account ({name})"
        );
        assert_matrix_matches_oracle(
            &c,
            &[&c.token_a, &c.token_b],
            true,
            blocked,
            sac_passthrough,
        );
    }

    // Only an admin unfreeze restores access.
    c.unfreeze(&c.token_a, &c.alice);
    assert!(!c.is_frozen(&c.token_a, &c.alice));
    assert_eq!(c.deposit(&c.token_a, &c.alice, &c.alice), Ok(()));
}

/// Enumerates every party combination of `arity` drawn from `pool`.
fn combos(arity: usize, pool: &[Address]) -> Vec<Vec<Address>> {
    fn build(arity: usize, pool: &[Address], cur: &mut Vec<Address>, out: &mut Vec<Vec<Address>>) {
        if cur.len() == arity {
            out.push(cur.clone());
            return;
        }
        for p in pool {
            cur.push(p.clone());
            build(arity, pool, cur, out);
            cur.pop();
        }
    }
    let mut out = Vec::new();
    build(arity, pool, &mut Vec::new(), &mut out);
    out
}

/// All-account pool used by the exhaustive matrix.
fn pool(c: &Ctx) -> Vec<Address> {
    vec![c.alice.clone(), c.bob.clone(), c.carol.clone()]
}

/// Asserts that the contract's answer for every (token, op, parties)
/// combination equals the oracle's prediction under the given state and
/// configuration.
fn assert_matrix_matches_oracle(
    c: &Ctx,
    tokens: &[&Address],
    frozen_alice_on_a: bool,
    blocked: Option<&Address>,
    sac_passthrough: bool,
) {
    let sac = |p: &Address| p == &c.alice || p == &c.bob;
    let pool = pool(c);

    for token in tokens.iter().copied() {
        let frozen = |p: &Address| frozen_alice_on_a && token == &c.token_a && p == &c.alice;
        for (op, arity) in [
            ("register", 1usize),
            ("merge", 1),
            ("withdraw", 1),
            ("deposit", 2),
            ("transfer", 2),
            ("transfer_from", 3),
        ] {
            for parties in combos(arity, &pool) {
                let expected = predict(
                    op,
                    true, // token bound
                    true, // config active
                    sac_passthrough,
                    sac,
                    frozen,
                    blocked,
                    &parties,
                );
                let actual = c.hook(op, token, &parties);
                assert_eq!(
                    actual,
                    expected,
                    "oracle mismatch for {op} on token {} with parties {parties:?}",
                    if token == &c.token_a { "A" } else { "B" }
                );
            }
        }
    }
}

#[test]
fn every_outcome_matches_the_oracle_in_the_open_state() {
    let c = deploy();
    assert_matrix_matches_oracle(&c, &[&c.token_a, &c.token_b], false, None, true);
}

#[test]
fn every_outcome_matches_the_oracle_with_frozen_and_blocked_parties() {
    let c = deploy();
    c.freeze(&c.token_a, &c.alice);
    c.rotate_policy(Some(&c.bob));
    assert_matrix_matches_oracle(&c, &[&c.token_a, &c.token_b], true, Some(&c.bob), true);
}

#[test]
fn out_of_scope_never_allows_an_operation() {
    let c = deploy();
    let stranger = Address::generate(&c.env);
    let pool = vec![c.alice.clone(), c.bob.clone()];

    // An unbound token is refused for every operation, whatever the
    // parties — the binding gate precedes all party gates.
    for op in [
        "register",
        "deposit",
        "transfer",
        "withdraw",
        "merge",
        "transfer_from",
    ] {
        let arity = match op {
            "transfer_from" => 3,
            "deposit" | "transfer" => 2,
            _ => 1,
        };
        for parties in combos(arity, &pool) {
            assert_eq!(
                c.hook(op, &stranger, &parties),
                Err(ContractError::UnboundToken)
            );
        }
    }

    // Unbinding a formerly bound token has the same effect for that token
    // only (Token B remains in scope).
    authorized_call(&c.env, &c.hooks, "unbind_token", (c.token_a.clone(),)).unwrap();
    for parties in combos(2, &pool) {
        assert_eq!(
            c.hook("transfer", &c.token_a, &parties),
            Err(ContractError::UnboundToken)
        );
    }
    assert_eq!(
        c.hook("transfer", &c.token_b, &[c.alice.clone(), c.bob.clone()]),
        Ok(())
    );
}

#[test]
fn unconfigured_contract_never_allows_an_operation() {
    let env = Env::new_with_config(EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    let hooks = env.register(ComplianceHooks, ());
    let token = Address::generate(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);

    // Initialize and bind, but never write a configuration.
    call(&env, &hooks, "initialize", (Address::generate(&env),)).unwrap();
    authorized_call(
        &env,
        &hooks,
        "bind_token",
        (token.clone(), Option::<Address>::None),
    )
    .unwrap();

    // Fail-closed: no configuration, no allows — every operation reverts
    // with InvalidConfiguration, even for fully compliant parties.
    for op in ["register", "deposit", "transfer", "withdraw", "merge"] {
        let parties = match op {
            "deposit" | "transfer" => vec![alice.clone(), bob.clone()],
            _ => vec![alice.clone()],
        };
        assert_eq!(
            call_args(
                &env,
                &hooks,
                &format!("before_{op}"),
                tuple_of(&env, &token, &parties)
            ),
            Err(ContractError::InvalidConfiguration),
            "{op} must fail closed on an unconfigured contract"
        );
    }
}

/// Builds a `(token, parties…)` argument vector for the raw helpers.
fn tuple_of(
    env: &soroban_sdk::Env,
    token: &Address,
    parties: &[Address],
) -> soroban_sdk::Vec<soroban_sdk::Val> {
    use soroban_sdk::{IntoVal, Val};
    let mut args: soroban_sdk::Vec<Val> = (token.clone(),).into_val(env);
    for p in parties {
        let v: Val = p.clone().into_val(env);
        args.push_back(v);
    }
    args
}
