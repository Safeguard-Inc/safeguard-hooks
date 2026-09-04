//! Phase 3 security suite: explicit threat-model attacks against the
//! `compliance-hooks` contract surface.
//!
//! Each test drives the *real* entry points through raw `try_invoke_contract`
//! (so denial codes are asserted exactly) and names the attack from
//! `docs/threat-model.md` it is exercising:
//!
//! * token spoofing — unbound tokens cannot trigger enforcement;
//! * bypass — frozen and policy-blocked accounts cannot route around a gate
//!   through any operation, and removing the policy does not lift a freeze;
//! * cross-token contamination — freeze, binding, and unbind state stay
//!   isolated per token;
//! * configuration attacks — unauthorized configuration, binding, unbinding,
//!   freezing, and re-initialization all revert and leave state untouched.
//!
//! Test doubles, invocation helpers, and the deployment context live in
//! `common/mod.rs` (shared with the invariant and property suites).

mod common;

use common::*;
use soroban_sdk::testutils::{Address as _, EnvTestConfig};
use soroban_sdk::{Address, Env};

// ################## TOKEN SPOOFING ##################

#[test]
fn unbound_token_cannot_trigger_enforcement() {
    let c = deploy();
    let stranger = Address::generate(&c.env);

    // The policy and SAC would allow Alice and Bob — only the missing
    // binding stands between the stranger and the gate. Enforcement is
    // refused outright, and the same operation on a bound token passes,
    // proving the binding — not the parties — was the blocker.
    assert_eq!(
        c.hook("deposit", &stranger, &[c.alice.clone(), c.bob.clone()]),
        Err(ContractError::UnboundToken)
    );
    assert_eq!(c.deposit(&c.token_a, &c.alice, &c.bob), Ok(()));
}

#[test]
fn token_cannot_borrow_another_tokens_binding() {
    let c = deploy();
    let stranger = Address::generate(&c.env);

    // Bindings are per-token admission, never transferable: Token B is
    // admitted while the stranger claiming the same operations is rejected.
    assert_eq!(c.deposit(&c.token_b, &c.alice, &c.bob), Ok(()));
    assert_eq!(
        c.deposit(&stranger, &c.alice, &c.bob),
        Err(ContractError::UnboundToken)
    );
}

// ################## BYPASS ATTEMPTS ##################

#[test]
fn frozen_account_cannot_bypass_through_any_operation() {
    let c = deploy();
    c.freeze(&c.token_a, &c.alice);

    // Every operation Alice could use to move or create value — including
    // exiting the wrapper and delegating — is refused with AccountFrozen.
    assert_eq!(
        c.register(&c.token_a, &c.alice),
        Err(ContractError::AccountFrozen)
    );
    assert_eq!(
        c.deposit(&c.token_a, &c.alice, &c.bob),
        Err(ContractError::AccountFrozen)
    );
    assert_eq!(
        c.transfer(&c.token_a, &c.alice, &c.bob),
        Err(ContractError::AccountFrozen)
    );
    assert_eq!(
        c.withdraw(&c.token_a, &c.alice),
        Err(ContractError::AccountFrozen)
    );
    assert_eq!(
        c.merge(&c.token_a, &c.alice),
        Err(ContractError::AccountFrozen)
    );
    assert_eq!(
        c.transfer_from(&c.token_a, &c.spender, &c.alice, &c.bob),
        Err(ContractError::AccountFrozen)
    );

    // A frozen account also cannot *receive*.
    assert_eq!(
        c.transfer(&c.token_a, &c.bob, &c.alice),
        Err(ContractError::AccountFrozen)
    );

    // The other token is untouched (cross-token check folded in).
    assert_eq!(c.deposit(&c.token_b, &c.alice, &c.bob), Ok(()));
}

#[test]
fn policy_blocked_account_cannot_bypass_through_any_operation() {
    let c = deploy();
    c.rotate_policy(Some(&c.alice)); // Now block Alice everywhere.

    // Rejections across every operation Alice could use, inbound included.
    assert_eq!(
        c.register(&c.token_a, &c.alice),
        Err(ContractError::PolicyDenied)
    );
    assert_eq!(
        c.deposit(&c.token_a, &c.alice, &c.bob),
        Err(ContractError::PolicyDenied)
    );
    assert_eq!(
        c.transfer(&c.token_a, &c.alice, &c.bob),
        Err(ContractError::PolicyDenied)
    );
    assert_eq!(
        c.withdraw(&c.token_a, &c.alice),
        Err(ContractError::PolicyDenied)
    );
    assert_eq!(
        c.merge(&c.token_a, &c.alice),
        Err(ContractError::PolicyDenied)
    );
    assert_eq!(
        c.transfer_from(&c.token_a, &c.spender, &c.alice, &c.bob),
        Err(ContractError::PolicyDenied)
    );
    assert_eq!(
        c.transfer(&c.token_a, &c.bob, &c.alice),
        Err(ContractError::PolicyDenied)
    );

    // Bob remains fully compliant: the block is account-scoped.
    assert_eq!(c.deposit(&c.token_a, &c.bob, &c.bob), Ok(()));
}

#[test]
fn delegation_cannot_route_around_a_blocked_owner() {
    let c = deploy();
    c.rotate_policy(Some(&c.alice));

    // A compliant spender cannot move value out of a blocked owner…
    assert_eq!(
        c.transfer_from(&c.token_a, &c.spender, &c.alice, &c.bob),
        Err(ContractError::PolicyDenied)
    );
    // …nor into one.
    assert_eq!(
        c.transfer_from(&c.token_a, &c.spender, &c.bob, &c.alice),
        Err(ContractError::PolicyDenied)
    );
}

#[test]
fn disabling_the_policy_does_not_lift_a_freeze() {
    let c = deploy();
    c.freeze(&c.token_a, &c.alice);

    // Rotate the policy away entirely (policy: None, SAC off). The freeze
    // gate is part of the contract, not the policy: it still holds.
    c.disable_policy(false);

    assert_eq!(
        c.deposit(&c.token_a, &c.alice, &c.bob),
        Err(ContractError::AccountFrozen)
    );
    assert!(c.is_frozen(&c.token_a, &c.alice));
}

#[test]
fn sac_passthrough_still_denies_unauthorized_depositors() {
    let c = deploy();

    // Carol is not SAC-authorized (the fixture SAC knows Alice and Bob).
    assert_eq!(
        c.deposit(&c.token_a, &c.carol, &c.alice),
        Err(ContractError::SacAuthorizationFailed)
    );
}

// ################## CROSS-TOKEN CONTAMINATION ##################

#[test]
fn freeze_state_never_leaks_across_tokens() {
    let c = deploy();
    c.freeze(&c.token_a, &c.alice);
    c.freeze(&c.token_b, &c.bob);

    assert!(c.is_frozen(&c.token_a, &c.alice));
    assert!(!c.is_frozen(&c.token_b, &c.alice));
    assert!(c.is_frozen(&c.token_b, &c.bob));
    assert!(!c.is_frozen(&c.token_a, &c.bob));

    // Alice is blocked on Token A but fully operational on Token B; Bob is
    // the mirror image — one token's freeze never contaminates another.
    assert_eq!(
        c.deposit(&c.token_a, &c.alice, &c.alice),
        Err(ContractError::AccountFrozen)
    );
    assert_eq!(c.deposit(&c.token_b, &c.alice, &c.alice), Ok(()));
    assert_eq!(
        c.deposit(&c.token_b, &c.bob, &c.bob),
        Err(ContractError::AccountFrozen)
    );
    assert_eq!(c.deposit(&c.token_a, &c.bob, &c.bob), Ok(()));
}

#[test]
fn unbinding_one_token_revokes_only_that_scope() {
    let c = deploy();

    authorized_call(&c.env, &c.hooks, "unbind_token", (c.token_a.clone(),)).unwrap();

    assert!(!c.token_is_bound(&c.token_a));
    assert!(c.token_is_bound(&c.token_b));
    assert_eq!(
        c.deposit(&c.token_a, &c.alice, &c.bob),
        Err(ContractError::UnboundToken)
    );
    assert_eq!(c.deposit(&c.token_b, &c.alice, &c.bob), Ok(()));
}

// ################## CONFIGURATION ATTACKS ##################

#[test]
fn unauthorized_configuration_rotation_reverts_and_leaves_state() {
    let c = deploy();

    // An attacker (no admin signature) tries to rotate the policy to one
    // that would block Alice.
    let attacker_policy = c.env.register(Policy, (Some(c.alice.clone()),));
    assert_reverted(&c.env, &c.hooks, "set_config", (attacker_policy, true));

    // The rotation never landed: Alice is still allowed by the active config.
    assert_eq!(c.deposit(&c.token_a, &c.alice, &c.alice), Ok(()));
}

#[test]
fn unauthorized_bind_and_unbind_revert_and_leave_state() {
    let c = deploy();
    let stranger = Address::generate(&c.env);

    // Attacker binds their own token…
    assert_reverted(
        &c.env,
        &c.hooks,
        "bind_token",
        (stranger.clone(), Option::<Address>::None),
    );
    assert!(!c.token_is_bound(&stranger));

    // …and tries to unbind a victim token.
    assert_reverted(&c.env, &c.hooks, "unbind_token", (c.token_a.clone(),));
    assert!(c.token_is_bound(&c.token_a));
    assert_eq!(c.deposit(&c.token_a, &c.alice, &c.bob), Ok(()));
}

#[test]
fn unauthorized_freeze_reverts_and_leaves_state() {
    let c = deploy();

    assert_reverted(
        &c.env,
        &c.hooks,
        "freeze",
        (c.token_a.clone(), c.alice.clone()),
    );

    // No freeze landed: Alice can still operate, and the admin can still
    // freeze her afterwards (the admin remains in control).
    assert!(!c.is_frozen(&c.token_a, &c.alice));
    assert_eq!(c.deposit(&c.token_a, &c.alice, &c.alice), Ok(()));
    c.freeze(&c.token_a, &c.alice);
    assert!(c.is_frozen(&c.token_a, &c.alice));
}

#[test]
fn double_initialization_cannot_rotate_the_admin() {
    let env = Env::new_with_config(EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    let hooks = env.register(ComplianceHooks, ());
    let admin1 = Address::generate(&env);
    let admin2 = Address::generate(&env);
    let token = Address::generate(&env);

    call(&env, &hooks, "initialize", (admin1.clone(),)).unwrap();

    // admin2 tries to re-initialize (which would rotate the admin).
    let res = call(&env, &hooks, "initialize", (admin2.clone(),));
    assert_eq!(res, Err(ContractError::AlreadyInitialized));

    // admin2 cannot administer…
    assert_reverted(
        &env,
        &hooks,
        "bind_token",
        (token.clone(), Option::<Address>::None),
    );

    // …and admin1 still can: the authority was never rotated.
    authorized_call(
        &env,
        &hooks,
        "bind_token",
        (token.clone(), Option::<Address>::None),
    )
    .unwrap();
    assert!(view_bool(&env, &hooks, "token_is_bound", (token,)));
}

#[test]
fn admin_policy_rotation_is_effective_and_gated() {
    let c = deploy();
    assert_eq!(c.deposit(&c.token_a, &c.alice, &c.bob), Ok(()));

    // The admin rotates to a policy that blocks Bob…
    c.rotate_policy(Some(&c.bob));

    // …and the new policy governs immediately.
    assert_eq!(
        c.deposit(&c.token_a, &c.alice, &c.bob),
        Err(ContractError::PolicyDenied)
    );
    assert_eq!(c.deposit(&c.token_a, &c.alice, &c.alice), Ok(()));

    // A non-admin cannot undo it.
    let allow_all = c.env.register(Policy, (None::<Address>,));
    assert_reverted(&c.env, &c.hooks, "set_config", (allow_all, true));
    assert_eq!(
        c.deposit(&c.token_a, &c.alice, &c.bob),
        Err(ContractError::PolicyDenied)
    );
}
