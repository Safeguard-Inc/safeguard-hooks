//! Shared support for the `compliance-hooks` integration test suites.
//!
//! Each binary in `tests/` includes this module (`mod common;`) and gets
//! the same deployment context, mock policy/SAC contracts, raw-invocation
//! helpers, and the enforcement *prediction oracle* used by the invariant
//! and property suites to assert actual outcomes against expected ones.
//!
//! Auth model: everything runs on a single strict `Env`. Admin-gated calls
//! go through [`authorized_call`], which snapshots the auth manager, mocks
//! all auths for the one call, and restores the snapshot afterwards — the
//! same scoping the generated clients apply. Every other call runs with no
//! authorization and must revert if it requires the admin.

#![allow(dead_code)]
#![allow(clippy::too_many_arguments)] // `predict` mirrors the evaluator's gate order.

pub use compliance_hooks::{ComplianceHooks, ContractError};
use soroban_sdk::testutils::{Address as _, EnvTestConfig};
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env, IntoVal, Symbol, Val, Vec};

// ################## TEST DOUBLES ##################

/// Token-agnostic deny-list policy: blocks one account everywhere.
#[contract]
pub struct Policy;

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
pub struct Sac;

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

/// Underlying invocation on a pre-built argument vector.
pub fn call_args(
    env: &Env,
    hooks: &Address,
    func: &str,
    args: Vec<Val>,
) -> Result<(), ContractError> {
    let symbol = Symbol::new(env, func);
    match env.try_invoke_contract::<(), ContractError>(hooks, &symbol, args) {
        Ok(_) => Ok(()),
        Err(Ok(err)) => Err(err),
        Err(Err(_)) => panic!("host-level failure in {func}"),
    }
}

/// Runs a contract function whose arguments encode into a value vector
/// (any tuple of `Address`/`Option<Address>`/`bool`), returning its outcome
/// as a typed result.
pub fn call<A>(env: &Env, hooks: &Address, func: &str, args: A) -> Result<(), ContractError>
where
    A: IntoVal<Env, Vec<Val>>,
{
    call_args(env, hooks, func, args.into_val(env))
}

/// Runs an admin-gated function as the stored admin: the auth manager is
/// snapshotted, all auths are mocked for this single invocation, and the
/// snapshot is restored afterwards (the generated clients scope their
/// `mock_all_auths` exactly this way).
pub fn authorized_call<A>(
    env: &Env,
    hooks: &Address,
    func: &str,
    args: A,
) -> Result<(), ContractError>
where
    A: IntoVal<Env, Vec<Val>>,
{
    let old = env.host().snapshot_auth_manager().unwrap();
    env.mock_all_auths();
    let res = call_args(env, hooks, func, args.into_val(env));
    env.host().set_auth_manager(old).unwrap();
    res
}

/// Asserts the invocation failed (any reason — contract code or host auth).
pub fn assert_reverted<A>(env: &Env, hooks: &Address, func: &str, args: A)
where
    A: IntoVal<Env, Vec<Val>>,
{
    let symbol = Symbol::new(env, func);
    let res = env.try_invoke_contract::<(), ContractError>(hooks, &symbol, args.into_val(env));
    assert!(res.is_err(), "{func} unexpectedly succeeded");
}

/// Reads a boolean view (e.g. `is_frozen`, `token_is_bound`).
pub fn view_bool<A>(env: &Env, hooks: &Address, func: &str, args: A) -> bool
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
///
/// The fixture policy blocks nobody and SAC passthrough is on; the SAC
/// authorizes `alice` and `bob` only. `carol` is a party that fails the SAC
/// gate (and is never frozen or blocked by default).
pub struct Ctx {
    pub env: Env,
    pub hooks: Address,
    pub token_a: Address,
    pub token_b: Address,
    pub admin: Address,
    pub alice: Address,
    pub bob: Address,
    pub spender: Address,
    pub carol: Address,
}

pub fn deploy() -> Ctx {
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
    // Note: the SAC is (re)registered inside `configure`, which also binds
    // the tokens against it.
    let policy = env.register(Policy, (None::<Address>,));

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
    c.configure(policy, true);
    c
}

impl Ctx {
    /// Deploys and configures a fresh contract against the given policy and
    /// SAC-passthrough flag, binding both tokens.
    pub fn deploy_with(policy_blocked: Option<&Address>, sac_passthrough: bool) -> Ctx {
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
        let policy = env.register(Policy, (policy_blocked.cloned(),));

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
        c.configure(policy, sac_passthrough);
        c
    }

    /// Runs `initialize` plus admin configuration and binding (both tokens).
    fn configure(&self, policy: Address, sac_passthrough: bool) {
        call(&self.env, &self.hooks, "initialize", (self.admin.clone(),)).unwrap();
        authorized_call(
            &self.env,
            &self.hooks,
            "set_config",
            (policy, sac_passthrough),
        )
        .unwrap();
        let sac_addr = self.env.register(Sac, (&self.alice, &self.bob));
        authorized_call(
            &self.env,
            &self.hooks,
            "bind_token",
            (self.token_a.clone(), sac_addr.clone()),
        )
        .unwrap();
        authorized_call(
            &self.env,
            &self.hooks,
            "bind_token",
            (self.token_b.clone(), sac_addr),
        )
        .unwrap();
    }

    /// Rotates the policy (admin) to block the given account, or to allow
    /// all when `None`.
    pub fn rotate_policy(&self, blocked: Option<&Address>) {
        let policy = self.env.register(Policy, (blocked.cloned(),));
        authorized_call(&self.env, &self.hooks, "set_config", (policy, true)).unwrap();
    }

    /// Rewrites the configuration with no policy gate (admin).
    pub fn disable_policy(&self, sac_passthrough: bool) {
        authorized_call(
            &self.env,
            &self.hooks,
            "set_config",
            (Option::<Address>::None, sac_passthrough),
        )
        .unwrap();
    }

    pub fn freeze(&self, token: &Address, account: &Address) {
        authorized_call(
            &self.env,
            &self.hooks,
            "freeze",
            (token.clone(), account.clone()),
        )
        .unwrap();
    }

    pub fn unfreeze(&self, token: &Address, account: &Address) {
        authorized_call(
            &self.env,
            &self.hooks,
            "unfreeze",
            (token.clone(), account.clone()),
        )
        .unwrap();
    }

    pub fn is_frozen(&self, token: &Address, account: &Address) -> bool {
        view_bool(
            &self.env,
            &self.hooks,
            "is_frozen",
            (token.clone(), account.clone()),
        )
    }

    pub fn token_is_bound(&self, token: &Address) -> bool {
        view_bool(&self.env, &self.hooks, "token_is_bound", (token.clone(),))
    }

    /// Invokes the named enforcement hook with the given parties in their
    /// canonical argument order (e.g. `transfer_from` takes
    /// `[spender, from, to]`). Supported: `register`, `deposit`, `transfer`,
    /// `withdraw`, `merge`, `transfer_from`.
    pub fn hook(
        &self,
        op: &str,
        token: &Address,
        parties: &[Address],
    ) -> Result<(), ContractError> {
        let mut args: Vec<Val> = (token.clone(),).into_val(&self.env);
        for party in parties {
            let v: Val = party.clone().into_val(&self.env);
            args.push_back(v);
        }
        call_args(&self.env, &self.hooks, &format!("before_{op}"), args)
    }

    // Named shorthands over [`Ctx::hook`], for readability in tests.
    pub fn register(&self, token: &Address, account: &Address) -> Result<(), ContractError> {
        self.hook("register", token, std::slice::from_ref(account))
    }
    pub fn deposit(
        &self,
        token: &Address,
        from: &Address,
        to: &Address,
    ) -> Result<(), ContractError> {
        self.hook("deposit", token, &[from.clone(), to.clone()])
    }
    pub fn transfer(
        &self,
        token: &Address,
        from: &Address,
        to: &Address,
    ) -> Result<(), ContractError> {
        self.hook("transfer", token, &[from.clone(), to.clone()])
    }
    pub fn withdraw(&self, token: &Address, account: &Address) -> Result<(), ContractError> {
        self.hook("withdraw", token, std::slice::from_ref(account))
    }
    pub fn merge(&self, token: &Address, account: &Address) -> Result<(), ContractError> {
        self.hook("merge", token, std::slice::from_ref(account))
    }
    pub fn transfer_from(
        &self,
        token: &Address,
        spender: &Address,
        from: &Address,
        to: &Address,
    ) -> Result<(), ContractError> {
        self.hook(
            "transfer_from",
            token,
            &[spender.clone(), from.clone(), to.clone()],
        )
    }
}

// ################## PREDICTION ORACLE ##################

/// Expected outcome of one operation, mirroring the evaluator's gate order
/// and party-role semantics. Tests compare `hook`'s result against this.
///
/// `frozen` and `blocked` are predicates over the current on-chain state
/// the test maintains; `sac_authorized` mirrors the fixture SAC (Alice and
/// Bob only).
pub fn predict<F, B>(
    op: &str,
    token_bound: bool,
    config_active: bool,
    sac_passthrough: bool,
    sac_authorized: F,
    frozen: B,
    blocked: Option<&Address>,
    parties: &[Address],
) -> Result<(), ContractError>
where
    F: Fn(&Address) -> bool,
    B: Fn(&Address) -> bool,
{
    if !config_active {
        return Err(ContractError::InvalidConfiguration);
    }
    if !token_bound {
        return Err(ContractError::UnboundToken);
    }

    // Roles per operation, in canonical gate order. Fund-holding roles are
    // freeze- and SAC-gated; `transfer_from`'s spender is policy-only.
    let roles: &[bool] = match op {
        // [account] for register/merge; withdraw evaluates the single
        // account twice but the checks are identical.
        "register" | "merge" | "withdraw" => &[true],
        "deposit" | "transfer" => &[true, true],
        "transfer_from" => &[false, true, true],
        _ => panic!("unknown operation {op}"),
    };
    debug_assert_eq!(roles.len(), parties.len());

    for (holds_funds, party) in roles.iter().copied().zip(parties.iter()) {
        // Freeze first, and only for fund holders.
        if holds_funds && frozen(party) {
            return Err(ContractError::AccountFrozen);
        }
        // Policy screens every party, spender included.
        if blocked == Some(party) {
            return Err(ContractError::PolicyDenied);
        }
        // SAC passthrough applies to fund holders only.
        if holds_funds && sac_passthrough && !sac_authorized(party) {
            return Err(ContractError::SacAuthorizationFailed);
        }
    }
    Ok(())
}
