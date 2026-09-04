//! Phase 3 security suite: explicit threat-model attacks against the
//! `compliance-hooks` contract surface.
//!
//! Each test drives the *real* entry points (raw `try_invoke_contract`, so
//! denial codes are asserted exactly) and names the attack from
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
//! Auth model: everything runs on a single strict `Env`. Admin-gated calls
//! go through [`authorized_call`], which snapshots the auth manager, mocks
//! all auths for the one call, and restores the snapshot afterwards — the
//! same scoping the generated clients apply. Every other call therefore
//! runs with no authorization and must revert if it requires the admin.

use compliance_hooks::{ComplianceHooks, ContractError};
use soroban_sdk::testutils::{Address as _, EnvTestConfig};
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env, IntoVal, Symbol, Val, Vec};

// ################## TEST DOUBLES ##################

/// Token-agnostic deny-list policy: blocks one account everywhere.
#[contract]
struct Policy;

#[contractimpl]
impl Policy {
    pub fn __constructor(e: Env, blocked: Option<Address>) {
        e.storage().instance().set(&symbol_short!("blkd"), &blocked);
    }

    pub fn is_authorized(e: Env, account: Address, _token: Address) -> bool {
        let blocked: Option<Address> = e.storage().instance().get(&symbol_short!("blkd")).unwrap();
        Some(account) != blocked
    }
}

/// SAC authorizing a fixed pair of accounts.
#[contract]
struct Sac;

#[contractimpl]
impl Sac {
    pub fn __constructor(e: Env, a: Address, b: Address) {
        e.storage().instance().set(&symbol_short!("a"), &a);
        e.storage().instance().set(&symbol_short!("b"), &b);
    }

    pub fn authorized(e: Env, id: Address) -> bool {
        let a: Address = e.storage().instance().get(&symbol_short!("a")).unwrap();
        let b: Address = e.storage().instance().get(&symbol_short!("b")).unwrap();
        id == a || id == b
    }
}

// ################## INVOCATION HELPERS ##################

/// Runs a contract function whose arguments encode into a value vector
/// (any tuple of `Address`/`Option<Address>`/`bool`), returning its outcome
/// as a typed result. Host-level failures (e.g. a failed `require_auth`)
/// surface as `Err(Err(..))` and are reported through `assert_reverted`.
fn call<A>(env: &Env, hooks: &Address, func: &str, args: A) -> Result<(), ContractError>
where
    A: IntoVal<Env, Vec<Val>>,
{
    let symbol = Symbol::new(env, func);
    match env.try_invoke_contract::<(), ContractError>(hooks, &symbol, args.into_val(env)) {
        Ok(_) => Ok(()),
        Err(Ok(err)) => Err(err),
        Err(Err(_)) => panic!("host-level failure in {func}"),
    }
}

/// Runs an admin-gated function as the stored admin: the auth manager is
/// snapshotted, all auths are mocked for this single invocation, and the
/// snapshot is restored afterwards (the generated clients scope their
/// `mock_all_auths` exactly this way).
fn authorized_call<A>(env: &Env, hooks: &Address, func: &str, args: A) -> Result<(), ContractError>
where
    A: IntoVal<Env, Vec<Val>>,
{
    let old = env.host().snapshot_auth_manager().unwrap();
    env.mock_all_auths();
    let res = call(env, hooks, func, args);
    env.host().set_auth_manager(old).unwrap();
    res
}

/// Asserts the invocation failed (any reason — contract code or host auth).
fn assert_reverted<A>(env: &Env, hooks: &Address, func: &str, args: A)
where
    A: IntoVal<Env, Vec<Val>>,
{
    let symbol = Symbol::new(env, func);
    let res = env.try_invoke_contract::<(), ContractError>(hooks, &symbol, args.into_val(env));
    assert!(res.is_err(), "{func} unexpectedly succeeded");
}

/// Reads a boolean view (e.g. `is_frozen`, `token_is_bound`).
fn view_bool<A>(env: &Env, hooks: &Address, func: &str, args: A) -> bool
where
    A: IntoVal<Env, Vec<Val>>,
{
    let symbol = Symbol::new(env, func);
    match env.try_invoke_contract::<bool, ContractError>(hooks, &symbol, args.into_val(env)) {
        Ok(Ok(b)) => b,
        Ok(Err(_)) => panic!("{func} returned a non-boolean"),
        Err(_) => panic!("{func} failed at the host level"),
    }
}

// ################## DEPLOYMENT CONTEXT ##################

/// A deployed, configured, two-token enforcement contract.
struct Ctx {
    env: Env,
    hooks: Address,
    token_a: Address,
    token_b: Address,
    admin: Address,
    alice: Address,
    bob: Address,
    spender: Address,
    carol: Address,
}

fn deploy(blocked: Option<&Address>) -> Ctx {
    let env = Env::new_with_config(EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    let hooks = env.register(ComplianceHooks, ());
    let admin = Address::generate(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    let spender = Address::generate(&env);
    let carol = Address::generate(&env);
    let token_a = Address::generate(&env);
    let token_b = Address::generate(&env);
    let sac = env.register(Sac, (&alice, &bob));
    let policy = env.register(Policy, (blocked.cloned(),));

    let c = Ctx {
        env,
        hooks,
        token_a,
        token_b,
        admin,
        alice,
        bob,
        spender,
        carol,
    };
    c.init(policy, sac);
    c
}

impl Ctx {
    fn init(&self, policy: Address, sac: Address) {
        // initialize needs no authorization.
        call(&self.env, &self.hooks, "initialize", (self.admin.clone(),)).unwrap();
        authorized_call(&self.env, &self.hooks, "set_config", (policy, true)).unwrap();
        authorized_call(
            &self.env,
            &self.hooks,
            "bind_token",
            (self.token_a.clone(), sac.clone()),
        )
        .unwrap();
        authorized_call(
            &self.env,
            &self.hooks,
            "bind_token",
            (self.token_b.clone(), sac),
        )
        .unwrap();
    }

    fn rotate_policy(&self, blocked: &Address) {
        let policy = self.env.register(Policy, (Some(blocked.clone()),));
        authorized_call(&self.env, &self.hooks, "set_config", (policy, true)).unwrap();
    }

    fn freeze(&self, token: &Address, account: &Address) {
        authorized_call(
            &self.env,
            &self.hooks,
            "freeze",
            (token.clone(), account.clone()),
        )
        .unwrap();
    }

    // Operation shorthands (invoked without auth, like a token).
    fn register(&self, token: &Address, account: &Address) -> Result<(), ContractError> {
        call(
            &self.env,
            &self.hooks,
            "before_register",
            (token.clone(), account.clone()),
        )
    }
    fn deposit(&self, token: &Address, from: &Address, to: &Address) -> Result<(), ContractError> {
        call(
            &self.env,
            &self.hooks,
            "before_deposit",
            (token.clone(), from.clone(), to.clone()),
        )
    }
    fn transfer(&self, token: &Address, from: &Address, to: &Address) -> Result<(), ContractError> {
        call(
            &self.env,
            &self.hooks,
            "before_transfer",
            (token.clone(), from.clone(), to.clone()),
        )
    }
    fn withdraw(&self, token: &Address, account: &Address) -> Result<(), ContractError> {
        call(
            &self.env,
            &self.hooks,
            "before_withdraw",
            (token.clone(), account.clone()),
        )
    }
    fn merge(&self, token: &Address, account: &Address) -> Result<(), ContractError> {
        call(
            &self.env,
            &self.hooks,
            "before_merge",
            (token.clone(), account.clone()),
        )
    }
    fn transfer_from(
        &self,
        token: &Address,
        spender: &Address,
        from: &Address,
        to: &Address,
    ) -> Result<(), ContractError> {
        call(
            &self.env,
            &self.hooks,
            "before_transfer_from",
            (token.clone(), spender.clone(), from.clone(), to.clone()),
        )
    }
    fn is_frozen(&self, token: &Address, account: &Address) -> bool {
        view_bool(
            &self.env,
            &self.hooks,
            "is_frozen",
            (token.clone(), account.clone()),
        )
    }
    fn token_is_bound(&self, token: &Address) -> bool {
        view_bool(&self.env, &self.hooks, "token_is_bound", (token.clone(),))
    }
}

// ################## TOKEN SPOOFING ##################

#[test]
fn unbound_token_cannot_trigger_enforcement() {
    let c = deploy(None);
    let stranger = Address::generate(&c.env);

    // The policy and SAC would allow Alice and Bob — only the missing
    // binding stands between the stranger and the gate. Enforcement is
    // refused outright, and the same operation on a bound token passes,
    // proving the binding — not the parties — was the blocker.
    assert_eq!(
        c.deposit(&stranger, &c.alice, &c.bob),
        Err(ContractError::UnboundToken)
    );
    assert_eq!(c.deposit(&c.token_a, &c.alice, &c.bob), Ok(()));
}

#[test]
fn token_cannot_borrow_another_tokens_binding() {
    let c = deploy(None);
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
    let c = deploy(None);
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
    let c = deploy(None);
    c.rotate_policy(&c.alice); // Now block Alice everywhere.

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
    let c = deploy(None);
    c.rotate_policy(&c.alice);

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
    let c = deploy(None);
    c.freeze(&c.token_a, &c.alice);

    // Rotate the policy away entirely (policy: None, SAC off). The freeze
    // gate is part of the contract, not the policy: it still holds.
    authorized_call(
        &c.env,
        &c.hooks,
        "set_config",
        (Option::<Address>::None, false),
    )
    .unwrap();

    assert_eq!(
        c.deposit(&c.token_a, &c.alice, &c.bob),
        Err(ContractError::AccountFrozen)
    );
    assert!(c.is_frozen(&c.token_a, &c.alice));
}

#[test]
fn sac_passthrough_still_denies_unauthorized_depositors() {
    let c = deploy(None);

    // Carol is not SAC-authorized (the fixture SAC knows Alice and Bob).
    assert_eq!(
        c.deposit(&c.token_a, &c.carol, &c.alice),
        Err(ContractError::SacAuthorizationFailed)
    );
}

// ################## CROSS-TOKEN CONTAMINATION ##################

#[test]
fn freeze_state_never_leaks_across_tokens() {
    let c = deploy(None);
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
    let c = deploy(None);

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
    let c = deploy(None);

    // An attacker (no admin signature) tries to rotate the policy to one
    // that would block Alice.
    let attacker_policy = c.env.register(Policy, (Some(c.alice.clone()),));
    assert_reverted(&c.env, &c.hooks, "set_config", (attacker_policy, true));

    // The rotation never landed: Alice is still allowed by the active config.
    assert_eq!(c.deposit(&c.token_a, &c.alice, &c.alice), Ok(()));
}

#[test]
fn unauthorized_bind_and_unbind_revert_and_leave_state() {
    let c = deploy(None);
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
    let c = deploy(None);

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
    let c = deploy(None);
    assert_eq!(c.deposit(&c.token_a, &c.alice, &c.bob), Ok(()));

    // The admin rotates to a policy that blocks Bob…
    c.rotate_policy(&c.bob);

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
