//! Deterministic property suite for the `compliance-hooks` contract.
//!
//! A seeded PRNG (no external dependency; the seeds make every run fully
//! reproducible) drives a long random sequence of admin transitions and
//! hook evaluations against a **state mirror**. After every step the
//! contract's answer must equal the enforcement oracle's prediction derived
//! from the mirror — which the mirror only mutates when the contract
//! confirms the transition. This catches, over thousands of interleavings:
//!
//! * gate-order or party-role regressions that a hand-written case misses;
//! * state drift between the mirror and the contract's actual storage
//!   (freeze flags surviving an unbind, bindings persisting, etc.);
//! * cross-token or cross-account contamination in randomized states;
//! * an admin transition silently failing while the mirror moves on.
//!
//! The mirror is deliberately small: binding state, per-(token, account)
//! freeze flags, the blocked account of the shared (token-agnostic) policy,
//! and the SAC-passthrough flag. SAC authorization is fixed to Alice and
//! Bob by the fixture SAC registered on every bind.
//!
//! This is a property test, not a true fuzzer: it never shrinks inputs. Its
//! value is breadth over a deterministic distribution, in CI time.

mod common;

use common::*;
use soroban_sdk::Address;

/// Small deterministic PRNG (splitmix64). `u64` arithmetic is fully
/// specified in Rust, so any seed reproduces the identical sequence on
/// every platform.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }
}

/// The four addresses the randomized sequences draw from, indexed 0–3.
const ACCOUNTS: [usize; 4] = [0, 1, 2, 3]; // alice, bob, carol, spender

/// The operations the hook surface exposes, with their party arity.
const OPS: [(&str, usize); 6] = [
    ("register", 1),
    ("merge", 1),
    ("withdraw", 1),
    ("deposit", 2),
    ("transfer", 2),
    ("transfer_from", 3),
];

/// State mirror: what the oracle believes the contract holds.
struct Model {
    bound: [bool; 2],
    frozen: [[bool; 4]; 2], // [token][account index]
    blocked: Option<usize>, // account index denied by the policy (None = no gate)
    sac_passthrough: bool,
}

fn pool(c: &Ctx) -> Vec<Address> {
    vec![
        c.alice.clone(),
        c.bob.clone(),
        c.carol.clone(),
        c.spender.clone(),
    ]
}

fn account_at(pool: &[Address], j: usize) -> Address {
    pool[j].clone()
}

/// Reads the contract's observable state and asserts it equals the mirror.
fn assert_views_match(c: &Ctx, m: &Model, pool: &[Address], seed: u64, step: usize) {
    for ti in 0..2 {
        let token = if ti == 0 { &c.token_a } else { &c.token_b };
        assert_eq!(
            c.token_is_bound(token),
            m.bound[ti],
            "seed {seed} step {step}: binding drift on token {ti}"
        );
        for j in ACCOUNTS {
            assert_eq!(
                c.is_frozen(token, &pool[j]),
                m.frozen[ti][j],
                "seed {seed} step {step}: freeze drift on token {ti} account {j}"
            );
        }
    }
}

/// The oracle prediction for one hook call under the mirror's state.
fn predict_for(
    c: &Ctx,
    m: &Model,
    pool: &[Address],
    ti: usize,
    op: &str,
    parties: &[Address],
) -> Result<(), ContractError> {
    let sac_authorized = |p: &Address| p == &c.alice || p == &c.bob; // fixture SAC authorizes Alice and Bob.
    let frozen = |p: &Address| match pool.iter().position(|a| a == p) {
        Some(j) => m.frozen[ti][j],
        None => false,
    };
    predict(
        op,
        m.bound[ti], // token bound?
        true,        // configuration is written once at deploy and never cleared.
        m.sac_passthrough,
        sac_authorized,
        frozen,
        m.blocked.map(|j| &pool[j]),
        parties,
    )
}

fn token_at(c: &Ctx, ti: usize) -> &Address {
    if ti == 0 {
        &c.token_a
    } else {
        &c.token_b
    }
}

/// One random admin transition or hook evaluation, mirror-synchronized.
fn step(c: &Ctx, rng: &mut Rng, m: &mut Model, pool: &[Address], seed: u64, step_no: usize) {
    let roll = rng.next() % 100;
    let ti = rng.below(2);
    let token = token_at(c, ti);
    let j = rng.below(ACCOUNTS.len());

    match roll {
        // freeze (admin): requires the token to be in an active scope.
        0..12 => {
            let expected = if !m.bound[ti] {
                Err(ContractError::UnboundToken)
            } else {
                Ok(())
            };
            let res = authorized_call(
                &c.env,
                &c.hooks,
                "freeze",
                (token.clone(), account_at(pool, j)),
            );
            assert_eq!(
                res, expected,
                "seed {seed} step {step_no}: freeze({ti}, {j}) diverged"
            );
            if res.is_ok() {
                m.frozen[ti][j] = true;
            }
        }
        // unfreeze (admin): requires the token to be in an active scope.
        12..24 => {
            let expected = if !m.bound[ti] {
                Err(ContractError::UnboundToken)
            } else {
                Ok(())
            };
            let res = authorized_call(
                &c.env,
                &c.hooks,
                "unfreeze",
                (token.clone(), account_at(pool, j)),
            );
            assert_eq!(
                res, expected,
                "seed {seed} step {step_no}: unfreeze({ti}, {j}) diverged"
            );
            if res.is_ok() {
                m.frozen[ti][j] = false;
            }
        }
        // Policy rotation / SAC-flag rewrite (admin).
        24..40 => {
            let sac_passthrough = rng.chance(50);
            let blocked = if rng.chance(25) {
                None // no policy gate at all.
            } else {
                let bj = rng.below(ACCOUNTS.len());
                let addr = account_at(pool, bj);
                let policy = c.env.register(Policy, (Some(addr),));
                m.blocked = Some(bj);
                Some(policy)
            };
            let res = authorized_call(
                &c.env,
                &c.hooks,
                "set_config",
                (blocked.clone(), sac_passthrough),
            );
            assert_eq!(
                res,
                Ok(()),
                "seed {seed} step {step_no}: set_config diverged"
            );
            if blocked.is_none() {
                m.blocked = None;
            }
            m.sac_passthrough = sac_passthrough;
        }
        // unbind (admin): idempotent; freezes survive unbinding.
        40..52 => {
            let res = authorized_call(&c.env, &c.hooks, "unbind_token", (token.clone(),));
            assert_eq!(res, Ok(()), "seed {seed} step {step_no}: unbind diverged");
            m.bound[ti] = false;
        }
        // bind (admin): re-enters scope; the fixture SAC again authorizes
        // Alice and Bob only. Freeze flags set before the unbind persist.
        52..64 => {
            let sac = c.env.register(Sac, (&c.alice, &c.bob));
            let res = authorized_call(&c.env, &c.hooks, "bind_token", (token.clone(), Some(sac)));
            assert_eq!(res, Ok(()), "seed {seed} step {step_no}: bind diverged");
            m.bound[ti] = true;
        }
        // A random hook evaluation: the contract's answer must equal the
        // oracle's prediction for the mirrored state.
        _ => {
            let (op, arity) = OPS[rng.below(OPS.len())];
            let mut parties = Vec::with_capacity(arity);
            for _ in 0..arity {
                parties.push(account_at(pool, rng.below(ACCOUNTS.len())));
            }
            let expected = predict_for(c, m, pool, ti, op, &parties);
            let actual = c.hook(op, token, &parties);
            assert_eq!(
                actual, expected,
                "seed {seed} step {step_no}: hook {op} on token {ti} with {parties:?} diverged"
            );
        }
    }
}

/// Runs `steps` random steps under `seed`, asserting oracle parity at every
/// step and full view/mirror equality at the end.
fn run_sequence(seed: u64, steps: usize) {
    let c = deploy();
    let pool = pool(&c);
    let mut m = Model {
        bound: [true, true], // `deploy` binds both tokens.
        frozen: [[false; 4]; 2],
        blocked: None, // `deploy`'s policy is allow-all.
        sac_passthrough: true,
    };
    let mut rng = Rng(seed);

    for step_no in 0..steps {
        step(&c, &mut rng, &mut m, &pool, seed, step_no);
        if step_no % 64 == 63 {
            assert_views_match(&c, &m, &pool, seed, step_no);
        }
    }
    assert_views_match(&c, &m, &pool, seed, steps);
}

#[test]
fn random_sequences_match_the_oracle_seed_a() {
    run_sequence(0x5a17_6a1f_cafe_0001, 600);
}

#[test]
fn random_sequences_match_the_oracle_seed_b() {
    run_sequence(0x5a17_6a1f_cafe_0002, 600);
}

#[test]
fn random_sequences_match_the_oracle_seed_c() {
    run_sequence(0x5a17_6a1f_cafe_0003, 600);
}
