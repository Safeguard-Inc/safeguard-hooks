#![no_std]

//! # compliance-hooks
//!
//! The Soroban enforcement contract of the Safeguard Hooks polyrepo
//! (ENFORCE). A confidential token that opts into compliance consults this
//! contract before every state-changing operation; when the contract
//! reverts, the token's own operation reverts with it — *rejected operation
//! = no state change*.
//!
//! ## Lifecycle
//!
//! ```text
//! 1. initialize(admin)            — deployment: sets the admin authority.
//! 2. set_config(policy, sac)      — admin: turns enforcement on. Until this
//!                                   write happens the contract is inert and
//!                                   every hook reverts (fail-closed), so a
//!                                   token cannot silently run ungated.
//! 3. bind_token(token, sac)       — admin: admits a token into scope.
//!                                   Unbound tokens are rejected outright.
//! 4. freeze / unfreeze            — admin: per-(token, account) freeze state,
//!                                   emitted as events for the audit bridge.
//! 5. token invokes before_*        — enforcement runs per operation.
//! ```
//!
//! Enforcement *cannot* be turned off once configured: the config fields may
//! be relaxed (policy `None`, SAC passthrough `false`) but the freeze gate
//! always applies to a configured contract.
//!
//! ## Caller model
//!
//! Soroban contracts cannot introspect their caller, so every `before_*`
//! entry point takes the token as an explicit argument and the binding gate
//! (an unbound token reverts with [`ContractError::UnboundToken`]) is the
//! admission control. Signature checks for the operation's *parties*
//! (registering account, delegating owner, admin behind a freeze) happen at
//! the token, which holds the balance and allowance state; this contract
//! gates what it holds — its own configuration, bindings, and freeze flags —
//! and enforces the external policy's decision. See
//! `crates/authorization/src/lib.rs` for the full boundary.
//!
//! ## Atomicity and privacy
//!
//! Gated entry points return `Err(ContractError)` on a denial. The invoking
//! token performs a plain (non-`try`) call, so a denial fails the nested
//! call and reverts the whole transaction: no balance update, partial
//! event, or half-written state survives it. No `before_*` entry point
//! accepts an amount, so private financial data never reaches this contract.
//!
//! ## Error model
//!
//! Entry points return [`ContractError`] values whose numeric codes mirror
//! the machine-readable reasons of `safeguard-hook-core` (`docs/errors.md`
//! maps codes to reasons and remediation). Tests assert the exact code via
//! the generated `try_` clients.

use soroban_sdk::{contract, contracterror, contractimpl, Address, Env};

use safeguard_authorization::{is_initialized, require_admin};
use safeguard_compliance::{
    evaluate_deposit, evaluate_merge, evaluate_register, evaluate_transfer, evaluate_transfer_from,
    evaluate_withdraw,
};
use safeguard_events::{
    emit_account_frozen, emit_account_unfrozen, emit_compliance_config_changed, emit_token_bound,
    emit_token_unbound,
};
use safeguard_hook_core::{ComplianceDecision, RejectionReason};
use safeguard_storage::{
    bind_token as storage_bind, bump_config_version, compliance_config as storage_config,
    config_version as storage_config_version, freeze_account as storage_freeze,
    is_frozen as storage_is_frozen, is_token_bound, set_admin, set_compliance_config,
    token_binding, unbind_token as storage_unbind, unfreeze_account as storage_unfreeze,
    ComplianceConfig,
};

/// Contract errors surfaced by reverts. Codes mirror
/// [`RejectionReason`] codes 1–11; contract-specific codes follow.
#[contracterror]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContractError {
    /// The caller was not authorized to perform the operation.
    UnauthorizedCaller = 1,
    /// The token the operation concerns is not bound to this contract.
    UnboundToken = 2,
    /// The configured policy denied an account.
    PolicyDenied = 3,
    /// An account holding funds is frozen.
    AccountFrozen = 4,
    /// The spender of a delegated flow is not authorized.
    SpenderNotAuthorized = 5,
    /// The policy's sanctions screen blocked the account.
    SanctionsBlocked = 6,
    /// The policy's jurisdiction rule blocked the account.
    JurisdictionRestricted = 7,
    /// The underlying SAC authorization check failed.
    SacAuthorizationFailed = 8,
    /// The contract configuration is invalid or absent.
    InvalidConfiguration = 9,
    /// The policy contract could not be evaluated (fail-closed).
    PolicyUnavailable = 10,
    /// The operation requires a registered account.
    RegistrationRequired = 11,
    /// `initialize` was called on an already-initialized contract.
    AlreadyInitialized = 12,
}

impl From<RejectionReason> for ContractError {
    fn from(reason: RejectionReason) -> Self {
        match reason {
            RejectionReason::UnauthorizedCaller => ContractError::UnauthorizedCaller,
            RejectionReason::UnboundToken => ContractError::UnboundToken,
            RejectionReason::PolicyDenied => ContractError::PolicyDenied,
            RejectionReason::AccountFrozen => ContractError::AccountFrozen,
            RejectionReason::SpenderNotAuthorized => ContractError::SpenderNotAuthorized,
            RejectionReason::SanctionsBlocked => ContractError::SanctionsBlocked,
            RejectionReason::JurisdictionRestricted => ContractError::JurisdictionRestricted,
            RejectionReason::SacAuthorizationFailed => ContractError::SacAuthorizationFailed,
            RejectionReason::InvalidConfiguration => ContractError::InvalidConfiguration,
            RejectionReason::PolicyUnavailable => ContractError::PolicyUnavailable,
            RejectionReason::RegistrationRequired => ContractError::RegistrationRequired,
        }
    }
}

/// The compliance enforcement contract.
#[contract]
pub struct ComplianceHooks;

#[contractimpl]
impl ComplianceHooks {
    // ################## DEPLOYMENT & ADMINISTRATION ##################

    /// Initializes the contract with `admin` as the sole administrative
    /// authority. Fails when already initialized (an attacker must not be
    /// able to rotate the admin by re-initializing).
    pub fn initialize(e: Env, admin: Address) -> Result<(), ContractError> {
        if is_initialized(&e) {
            return Err(ContractError::AlreadyInitialized);
        }
        set_admin(&e, &admin);
        Ok(())
    }

    /// Writes the compliance configuration (admin-gated). Until this write,
    /// enforcement is off and every hook fails with
    /// [`ContractError::InvalidConfiguration`].
    ///
    /// A rewrite that changes nothing is a no-op (no event, no version
    /// bump); a real change — including a policy rotation — bumps the
    /// configuration version and emits a `ComplianceConfigChanged` event
    /// for the audit bridge.
    pub fn set_config(
        e: Env,
        policy: Option<Address>,
        sac_passthrough: bool,
    ) -> Result<(), ContractError> {
        admin_gate(&e)?;
        let next = ComplianceConfig {
            policy,
            sac_passthrough,
        };
        if storage_config(&e).as_ref() == Some(&next) {
            return Ok(());
        }
        set_compliance_config(&e, &next);
        bump_config_version(&e);
        emit_compliance_config_changed(&e, &next.policy, next.sac_passthrough);
        Ok(())
    }

    /// Admits `token` into enforcement scope (admin-gated), recording its
    /// underlying SAC when it has one. Binding a token to the same SAC it is
    /// already bound to is a no-op; a real binding change emits a
    /// `TokenBound` event.
    pub fn bind_token(e: Env, token: Address, sac: Option<Address>) -> Result<(), ContractError> {
        admin_gate(&e)?;
        let same = token_binding(&e, &token)
            .map(|binding| binding.sac == sac)
            .unwrap_or(false);
        if same {
            return Ok(());
        }
        storage_bind(&e, &token, sac.as_ref());
        emit_token_bound(&e, &token);
        Ok(())
    }

    /// Removes `token` from enforcement scope (admin-gated). Unbinding an
    /// unbound token is a no-op; a real removal emits a `TokenUnbound`
    /// event.
    pub fn unbind_token(e: Env, token: Address) -> Result<(), ContractError> {
        admin_gate(&e)?;
        if !is_token_bound(&e, &token) {
            return Ok(());
        }
        storage_unbind(&e, &token);
        emit_token_unbound(&e, &token);
        Ok(())
    }

    // ################## FREEZE ADMINISTRATION ##################

    /// Freezes `account` on `token` (admin-gated): the account can neither
    /// send, receive, deposit, nor withdraw on that token. Requires an active
    /// enforcement configuration and a bound token. Emits `AccountFrozen`
    /// only when the freeze is an actual state change — freezing an already
    /// frozen account is an idempotent no-op that emits nothing.
    pub fn freeze(e: Env, token: Address, account: Address) -> Result<(), ContractError> {
        admin_gate(&e)?;
        scope_gate(&e, &token)?;
        if !storage_is_frozen(&e, &token, &account) {
            storage_freeze(&e, &token, &account);
            emit_account_frozen(&e, &token, &account);
        }
        Ok(())
    }

    /// Unfreezes `account` on `token` (admin-gated). Emits `AccountUnfrozen`
    /// only when the unfreeze is an actual state change — unfreezing an
    /// unfrozen account is an idempotent no-op that emits nothing.
    pub fn unfreeze(e: Env, token: Address, account: Address) -> Result<(), ContractError> {
        admin_gate(&e)?;
        scope_gate(&e, &token)?;
        if storage_is_frozen(&e, &token, &account) {
            storage_unfreeze(&e, &token, &account);
            emit_account_unfrozen(&e, &token, &account);
        }
        Ok(())
    }

    // ################## HOOK ENTRY POINTS (invoked by the token) ##################

    /// Gates an account registration on `token`.
    pub fn before_register(e: Env, token: Address, account: Address) -> Result<(), ContractError> {
        enforce(evaluate_register(&e, &token, &account))
    }

    /// Gates a deposit on `token` (depositor `from` → wrapper account `to`).
    pub fn before_deposit(
        e: Env,
        token: Address,
        from: Address,
        to: Address,
    ) -> Result<(), ContractError> {
        enforce(evaluate_deposit(&e, &token, &from, &to))
    }

    /// Gates a confidential transfer on `token` (`from` → `to`).
    pub fn before_transfer(
        e: Env,
        token: Address,
        from: Address,
        to: Address,
    ) -> Result<(), ContractError> {
        enforce(evaluate_transfer(&e, &token, &from, &to))
    }

    /// Gates a withdrawal on `token` for the exiting `account`.
    pub fn before_withdraw(e: Env, token: Address, account: Address) -> Result<(), ContractError> {
        enforce(evaluate_withdraw(&e, &token, &account))
    }

    /// Gates a merge on `token` for the merging `account`.
    pub fn before_merge(e: Env, token: Address, account: Address) -> Result<(), ContractError> {
        enforce(evaluate_merge(&e, &token, &account))
    }

    /// Gates a delegated transfer on `token`. The `spender` is screened by
    /// policy only; `from` and `to` pass the full gate.
    pub fn before_transfer_from(
        e: Env,
        token: Address,
        spender: Address,
        from: Address,
        to: Address,
    ) -> Result<(), ContractError> {
        enforce(evaluate_transfer_from(&e, &token, &spender, &from, &to))
    }

    // ################## PUBLIC READS ##################

    /// Whether `token` is bound to this contract.
    pub fn token_is_bound(e: Env, token: Address) -> bool {
        is_token_bound(&e, &token)
    }

    /// Whether the contract has been initialized.
    pub fn initialized(e: Env) -> bool {
        is_initialized(&e)
    }

    /// The active compliance configuration, if enforcement is configured.
    pub fn config(e: Env) -> Option<ComplianceConfig> {
        storage_config(&e)
    }

    /// How many times the compliance configuration has been rewritten (0
    /// until the first `set_config`). Rotating the policy is a rewrite, so
    /// this is the on-chain ordering anchor `safeguard-audit` pairs with
    /// `ComplianceConfigChanged` events.
    pub fn config_version(e: Env) -> u32 {
        storage_config_version(&e).unwrap_or(0)
    }

    /// Whether `account` is frozen on `token`.
    pub fn is_frozen(e: Env, token: Address, account: Address) -> bool {
        storage_is_frozen(&e, &token, &account)
    }
}

/// Runs the admin authority gate, mapping an uninitialized contract onto the
/// contract's own error code. An initialized contract whose admin did not
/// sign reverts inside `require_admin` (host authorization error).
fn admin_gate(e: &Env) -> Result<(), ContractError> {
    require_admin(e).map_err(ContractError::from)
}

/// Ensures per-token administration (freeze) only targets an active
/// enforcement scope: the contract must be configured and the token bound.
fn scope_gate(e: &Env, token: &Address) -> Result<(), ContractError> {
    if storage_config(e).is_none() {
        return Err(ContractError::InvalidConfiguration);
    }
    if !is_token_bound(e, token) {
        return Err(ContractError::UnboundToken);
    }
    Ok(())
}

/// Turns a denial into an `Err` the invoking token must treat as a failed
/// call. The whole point of the hooks layer: a rejected operation must not
/// leave any state behind.
fn enforce(decision: ComplianceDecision) -> Result<(), ContractError> {
    match decision {
        ComplianceDecision::Allow => Ok(()),
        ComplianceDecision::Deny(reason) => Err(ContractError::from(reason)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{Address as _, EnvTestConfig, Events as _};
    use soroban_sdk::{contract, contractimpl, symbol_short, Event as _, IntoVal, Symbol};

    use safeguard_events::{
        AccountFrozen, AccountUnfrozen, ComplianceConfigChanged, TokenBound, TokenUnbound,
    };

    /// Deny-list policy pinned to one token (see the compliance crate tests).
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

    /// SAC that authorizes a fixed set of accounts.
    #[contract]
    struct MockSac;

    #[contractimpl]
    impl MockSac {
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

    /// Token-agnostic deny-list policy: blocks one account on every token it
    /// is asked about. Used by the multi-token tests to show that a single
    /// policy can serve several bound tokens while freeze and binding state
    /// stay isolated per token.
    #[contract]
    struct MultiTokenPolicy;

    #[contractimpl]
    impl MultiTokenPolicy {
        pub fn __constructor(e: Env, blocked: Option<Address>) {
            e.storage().instance().set(&symbol_short!("blkd"), &blocked);
        }

        pub fn is_authorized(e: Env, account: Address, _token: Address) -> bool {
            let blocked: Option<Address> =
                e.storage().instance().get(&symbol_short!("blkd")).unwrap();
            Some(account) != blocked
        }
    }

    /// A registered, configured, single-token deployment for tests: an
    /// allow-all policy, SAC passthrough on, and two SAC-authorized accounts.
    struct Fixture {
        env: Env,
        hooks: Address,
        token: Address,
        alice: Address,
        bob: Address,
    }

    fn fixture() -> Fixture {
        let env = Env::new_with_config(EnvTestConfig {
            capture_snapshot_at_drop: false,
        });
        let hooks = env.register(ComplianceHooks, ());
        let token = Address::generate(&env);
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        let sac = env.register(MockSac, (&alice, &bob));

        let client = ComplianceHooksClient::new(&env, &hooks);
        client.initialize(&Address::generate(&env));
        client
            .mock_all_auths()
            .set_config(&Some(policy_allowing(&env, &token)), &true);
        client.mock_all_auths().bind_token(&token, &Some(sac));

        Fixture {
            env,
            hooks,
            token,
            alice,
            bob,
        }
    }

    fn policy_address(env: &Env, blocked: &Address, token: &Address) -> Address {
        env.register(DenylistPolicy, (Some(blocked.clone()), token.clone()))
    }

    fn policy_allowing(env: &Env, token: &Address) -> Address {
        env.register(DenylistPolicy, (None::<Address>, token.clone()))
    }

    fn try_before_merge(
        env: &Env,
        hooks: &Address,
        token: &Address,
        account: &Address,
    ) -> Result<(), ContractError> {
        let func = Symbol::new(env, "before_merge");
        let args = (token.clone(), account.clone()).into_val(env);
        match env.try_invoke_contract::<(), ContractError>(hooks, &func, args) {
            Ok(_) => Ok(()),
            Err(Ok(err)) => Err(err),
            Err(Err(_)) => panic!("invocation failed at the host level"),
        }
    }

    fn try_before_transfer_from(
        env: &Env,
        hooks: &Address,
        token: &Address,
        spender: &Address,
        from: &Address,
        to: &Address,
    ) -> Result<(), ContractError> {
        let func = Symbol::new(env, "before_transfer_from");
        let args = (token.clone(), spender.clone(), from.clone(), to.clone()).into_val(env);
        match env.try_invoke_contract::<(), ContractError>(hooks, &func, args) {
            Ok(_) => Ok(()),
            Err(Ok(err)) => Err(err),
            Err(Err(_)) => panic!("invocation failed at the host level"),
        }
    }

    fn try_before_deposit(
        env: &Env,
        hooks: &Address,
        token: &Address,
        from: &Address,
        to: &Address,
    ) -> Result<(), ContractError> {
        let func = Symbol::new(env, "before_deposit");
        let args = (token.clone(), from.clone(), to.clone()).into_val(env);
        match env.try_invoke_contract::<(), ContractError>(hooks, &func, args) {
            Ok(_) => Ok(()),
            Err(Ok(err)) => Err(err),
            Err(Err(_)) => panic!("invocation failed at the host level"),
        }
    }

    #[test]
    fn uninitialized_contract_rejects_everything() {
        let env = Env::new_with_config(EnvTestConfig {
            capture_snapshot_at_drop: false,
        });
        let hooks = env.register(ComplianceHooks, ());
        let token = Address::generate(&env);
        let admin = Address::generate(&env);

        // Admin ops revert before initialization…
        let res = env.try_invoke_contract::<(), ContractError>(
            &hooks,
            &Symbol::new(&env, "bind_token"),
            (token.clone(), Option::<Address>::None).into_val(&env),
        );
        assert!(matches!(res, Err(Ok(ContractError::InvalidConfiguration))));
        let _ = admin;

        // …and hooks fail closed with InvalidConfiguration, never silently
        // passing an operation.
        assert_eq!(
            try_before_deposit(
                &env,
                &hooks,
                &token,
                &Address::generate(&env),
                &Address::generate(&env)
            ),
            Err(ContractError::InvalidConfiguration)
        );
    }

    #[test]
    fn double_initialization_reverts() {
        let env = Env::new_with_config(EnvTestConfig {
            capture_snapshot_at_drop: false,
        });
        let hooks = env.register(ComplianceHooks, ());
        let admin = Address::generate(&env);

        let client = ComplianceHooksClient::new(&env, &hooks);
        client.initialize(&admin);

        // A second initialize is an admin-rotation attempt.
        let res = env.try_invoke_contract::<(), ContractError>(
            &hooks,
            &Symbol::new(&env, "initialize"),
            (Address::generate(&env),).into_val(&env),
        );
        assert!(matches!(res, Err(Ok(ContractError::AlreadyInitialized))));
    }

    #[test]
    fn unauthorized_admin_operations_revert() {
        let f = fixture();
        let attacker = Address::generate(&f.env);
        let stranger_token = Address::generate(&f.env);

        // No mock: the stored admin did not authorize `bind_token`.
        let res = f.env.try_invoke_contract::<(), ContractError>(
            &f.hooks,
            &Symbol::new(&f.env, "bind_token"),
            (stranger_token, Option::<Address>::None).into_val(&f.env),
        );
        // Signature failures surface as host auth errors, not contract codes.
        let _ = attacker;
        assert!(res.is_err());
    }

    #[test]
    fn fully_compliant_operations_are_allowed() {
        let env = Env::new_with_config(EnvTestConfig {
            capture_snapshot_at_drop: false,
        });
        let hooks = env.register(ComplianceHooks, ());
        let token = Address::generate(&env);
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        let sac = env.register(MockSac, (&alice, &bob));
        let policy = policy_allowing(&env, &token);

        let client = ComplianceHooksClient::new(&env, &hooks);
        let admin = Address::generate(&env);
        client.initialize(&admin);
        client.mock_all_auths().set_config(&Some(policy), &true);
        client.mock_all_auths().bind_token(&token, &Some(sac));

        // Register, deposit, transfer, and withdraw all pass.
        let c = client.mock_all_auths();
        c.before_register(&token, &alice);
        c.before_deposit(&token, &alice, &bob);
        c.before_transfer(&token, &alice, &bob);
        c.before_withdraw(&token, &alice);
        assert!(client.token_is_bound(&token));
        assert!(client.initialized());
    }

    #[test]
    fn blocked_party_reverts_with_policy_denied() {
        let env = Env::new_with_config(EnvTestConfig {
            capture_snapshot_at_drop: false,
        });
        let hooks = env.register(ComplianceHooks, ());
        let token = Address::generate(&env);
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        let sac = env.register(MockSac, (&alice, &bob));
        let policy = policy_address(&env, &bob, &token); // Bob blocked.

        let client = ComplianceHooksClient::new(&env, &hooks);
        let admin = Address::generate(&env);
        client.initialize(&admin);
        client.mock_all_auths().set_config(&Some(policy), &true);
        client.mock_all_auths().bind_token(&token, &Some(sac));

        // The deposit to blocked Bob reverts with the exact reason code.
        assert_eq!(
            try_before_deposit(&env, &hooks, &token, &alice, &bob),
            Err(ContractError::PolicyDenied)
        );
    }

    #[test]
    fn unbound_token_reverts_before_any_gate() {
        let f = fixture();
        let stranger = Address::generate(&f.env);

        // The policy and freeze state would allow this transfer, but the
        // token is not bound, so enforcement never runs.
        assert_eq!(
            try_before_deposit(&f.env, &f.hooks, &stranger, &f.alice, &f.bob),
            Err(ContractError::UnboundToken)
        );
    }

    #[test]
    fn frozen_party_reverts_with_account_frozen() {
        let f = fixture();

        // Freeze Alice through the real admin-gated entry point.
        let client = ComplianceHooksClient::new(&f.env, &f.hooks);
        client.mock_all_auths().freeze(&f.token, &f.alice);
        assert!(client.is_frozen(&f.token, &f.alice));

        assert_eq!(
            try_before_deposit(&f.env, &f.hooks, &f.token, &f.alice, &f.bob),
            Err(ContractError::AccountFrozen)
        );
    }

    #[test]
    fn freeze_is_an_admin_gated_state_change_with_one_event() {
        let f = fixture();
        let client = ComplianceHooksClient::new(&f.env, &f.hooks);

        assert!(!client.is_frozen(&f.token, &f.alice));
        client.mock_all_auths().freeze(&f.token, &f.alice);

        // The state change is recorded as exactly one event naming the
        // token and the account — nothing else.
        assert_eq!(
            f.env.events().all(),
            [AccountFrozen {
                token: f.token.clone(),
                account: f.alice.clone()
            }
            .to_xdr(&f.env, &f.hooks)]
        );
        assert!(client.is_frozen(&f.token, &f.alice));

        // Freezing an already-frozen account is an idempotent no-op that
        // emits no second event (events describe state transitions).
        client.mock_all_auths().freeze(&f.token, &f.alice);
        assert_eq!(f.env.events().all(), []);
    }

    #[test]
    fn unfreeze_restores_access_and_emits_one_event() {
        let f = fixture();
        let client = ComplianceHooksClient::new(&f.env, &f.hooks);

        client.mock_all_auths().freeze(&f.token, &f.alice);
        assert_eq!(
            try_before_deposit(&f.env, &f.hooks, &f.token, &f.alice, &f.bob),
            Err(ContractError::AccountFrozen)
        );

        client.mock_all_auths().unfreeze(&f.token, &f.alice);
        assert_eq!(
            f.env.events().all(),
            [AccountUnfrozen {
                token: f.token.clone(),
                account: f.alice.clone()
            }
            .to_xdr(&f.env, &f.hooks)]
        );
        assert!(!client.is_frozen(&f.token, &f.alice));

        // The unfrozen account can operate again.
        assert_eq!(
            try_before_deposit(&f.env, &f.hooks, &f.token, &f.alice, &f.bob),
            Ok(())
        );

        // Unfreezing an unfrozen account emits nothing.
        client.mock_all_auths().unfreeze(&f.token, &f.alice);
        assert_eq!(f.env.events().all(), []);
    }

    #[test]
    fn freeze_requires_a_bound_token() {
        let f = fixture();
        let client = ComplianceHooksClient::new(&f.env, &f.hooks);
        let stranger = Address::generate(&f.env);

        let res = client.mock_all_auths().try_freeze(&stranger, &f.alice);
        assert!(matches!(res, Err(Ok(ContractError::UnboundToken))));
        assert!(!client.is_frozen(&stranger, &f.alice));
    }

    #[test]
    fn freeze_requires_an_active_configuration() {
        let env = Env::new_with_config(EnvTestConfig {
            capture_snapshot_at_drop: false,
        });
        let hooks = env.register(ComplianceHooks, ());
        let token = Address::generate(&env);
        let alice = Address::generate(&env);

        let client = ComplianceHooksClient::new(&env, &hooks);
        client.initialize(&Address::generate(&env));
        // Bind the token but never configure enforcement.
        client.mock_all_auths().bind_token(&token, &None);

        let res = client.mock_all_auths().try_freeze(&token, &alice);
        assert!(matches!(res, Err(Ok(ContractError::InvalidConfiguration))));
    }

    #[test]
    fn unauthorized_freeze_reverts() {
        let f = fixture();

        // No auth mocked: the stored admin did not authorize the freeze.
        let res = f.env.try_invoke_contract::<(), ContractError>(
            &f.hooks,
            &Symbol::new(&f.env, "freeze"),
            (f.token.clone(), f.alice.clone()).into_val(&f.env),
        );
        assert!(res.is_err());
    }

    #[test]
    fn sac_denied_party_reverts_with_sac_authorization_failed() {
        let env = Env::new_with_config(EnvTestConfig {
            capture_snapshot_at_drop: false,
        });
        let hooks = env.register(ComplianceHooks, ());
        let token = Address::generate(&env);
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        let carol = Address::generate(&env); // Not SAC-authorized.
        let sac = env.register(MockSac, (&alice, &bob));
        let policy = policy_allowing(&env, &token);

        let client = ComplianceHooksClient::new(&env, &hooks);
        let admin = Address::generate(&env);
        client.initialize(&admin);
        client.mock_all_auths().set_config(&Some(policy), &true);
        client.mock_all_auths().bind_token(&token, &Some(sac));

        assert_eq!(
            try_before_deposit(&env, &hooks, &token, &carol, &alice),
            Err(ContractError::SacAuthorizationFailed)
        );
    }

    #[test]
    fn reads_reflect_configuration() {
        let f = fixture();
        let client = ComplianceHooksClient::new(&f.env, &f.hooks);

        assert!(client.token_is_bound(&f.token));
        assert!(client.initialized());
        let config = client.config();
        assert_eq!(config.as_ref().map(|c| c.sac_passthrough), Some(true));

        // Unbinding takes the token out of scope.
        client.mock_all_auths().unbind_token(&f.token);
        assert!(!client.token_is_bound(&f.token));
        assert_eq!(
            try_before_deposit(&f.env, &f.hooks, &f.token, &f.alice, &f.bob),
            Err(ContractError::UnboundToken)
        );
    }

    #[test]
    fn merge_and_delegated_hooks_are_gated() {
        let f = fixture();
        let client = ComplianceHooksClient::new(&f.env, &f.hooks);
        let spender = Address::generate(&f.env);

        // Merge and a compliant delegation pass.
        client.mock_all_auths().before_merge(&f.token, &f.alice);
        assert_eq!(
            try_before_transfer_from(&f.env, &f.hooks, &f.token, &spender, &f.alice, &f.bob),
            Ok(())
        );

        // A frozen spender does not stop the delegation (policy-only role);
        // a frozen `from` does.
        client.mock_all_auths().freeze(&f.token, &spender);
        assert_eq!(
            try_before_transfer_from(&f.env, &f.hooks, &f.token, &spender, &f.alice, &f.bob),
            Ok(())
        );
        // A frozen `from` stops the delegation, and a frozen account cannot
        // merge either.
        client.mock_all_auths().freeze(&f.token, &f.alice);
        assert_eq!(
            try_before_transfer_from(&f.env, &f.hooks, &f.token, &spender, &f.alice, &f.bob),
            Err(ContractError::AccountFrozen)
        );
        assert_eq!(
            try_before_merge(&f.env, &f.hooks, &f.token, &f.alice),
            Err(ContractError::AccountFrozen)
        );

        // Unfreezing restores both flows.
        client.mock_all_auths().unfreeze(&f.token, &f.alice);
        client.mock_all_auths().before_merge(&f.token, &f.alice);
        assert_eq!(
            try_before_transfer_from(&f.env, &f.hooks, &f.token, &spender, &f.alice, &f.bob),
            Ok(())
        );
    }

    #[test]
    fn blocked_spender_is_rejected_at_the_hook() {
        let env = Env::new_with_config(EnvTestConfig {
            capture_snapshot_at_drop: false,
        });
        let hooks = env.register(ComplianceHooks, ());
        let token = Address::generate(&env);
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        let spender = Address::generate(&env);
        let sac = env.register(MockSac, (&alice, &bob));
        let policy = policy_address(&env, &spender, &token); // Spender blocked.

        let client = ComplianceHooksClient::new(&env, &hooks);
        client.initialize(&Address::generate(&env));
        client.mock_all_auths().set_config(&Some(policy), &true);
        client.mock_all_auths().bind_token(&token, &Some(sac));

        assert_eq!(
            try_before_transfer_from(&env, &hooks, &token, &spender, &alice, &bob),
            Err(ContractError::PolicyDenied)
        );
    }

    #[test]
    fn config_rewrites_bump_the_version_and_emit_events_only_on_changes() {
        let f = fixture();
        let client = ComplianceHooksClient::new(&f.env, &f.hooks);

        // The fixture's initial set_config landed on version 1.
        assert_eq!(client.config_version(), 1);

        // Rewriting the identical configuration is a no-op: no event, no
        // version bump.
        let current = client.config().unwrap();
        client
            .mock_all_auths()
            .set_config(&current.policy, &current.sac_passthrough);
        assert_eq!(f.env.events().all(), []);
        assert_eq!(client.config_version(), 1);

        // A policy rotation is a real rewrite: one event, one bump.
        let policy_b = policy_allowing(&f.env, &f.token);
        client
            .mock_all_auths()
            .set_config(&Some(policy_b.clone()), &true);
        assert_eq!(
            f.env.events().all(),
            [ComplianceConfigChanged {
                policy: Some(policy_b.clone()),
                sac_passthrough: true,
            }
            .to_xdr(&f.env, &f.hooks)]
        );
        assert_eq!(client.config_version(), 2);

        // Flipping only the SAC flag is also a rewrite.
        client
            .mock_all_auths()
            .set_config(&Some(policy_b.clone()), &false);
        assert_eq!(
            f.env.events().all(),
            [ComplianceConfigChanged {
                policy: Some(policy_b),
                sac_passthrough: false,
            }
            .to_xdr(&f.env, &f.hooks)]
        );
        assert_eq!(client.config_version(), 3);
    }

    #[test]
    fn config_version_is_zero_until_the_first_write() {
        let env = Env::new_with_config(EnvTestConfig {
            capture_snapshot_at_drop: false,
        });
        let hooks = env.register(ComplianceHooks, ());
        let client = ComplianceHooksClient::new(&env, &hooks);

        assert_eq!(client.config_version(), 0);
    }

    #[test]
    fn bind_and_unbind_emit_events_only_on_state_changes() {
        let env = Env::new_with_config(EnvTestConfig {
            capture_snapshot_at_drop: false,
        });
        let hooks = env.register(ComplianceHooks, ());
        let token = Address::generate(&env);
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        let sac = env.register(MockSac, (&alice, &bob));
        let policy = policy_allowing(&env, &token);

        let client = ComplianceHooksClient::new(&env, &hooks);
        client.initialize(&Address::generate(&env));
        client.mock_all_auths().set_config(&Some(policy), &true);
        client
            .mock_all_auths()
            .bind_token(&token, &Some(sac.clone()));

        // Re-binding to the same SAC is a no-op.
        client.mock_all_auths().bind_token(&token, &Some(sac));
        assert_eq!(env.events().all(), []);

        // Re-binding with a different binding (no SAC) is a real change.
        client.mock_all_auths().bind_token(&token, &None);
        assert_eq!(
            env.events().all(),
            [TokenBound {
                token: token.clone()
            }
            .to_xdr(&env, &hooks)]
        );
        assert!(client.token_is_bound(&token));

        // Unbinding a bound token emits one event and revokes scope.
        client.mock_all_auths().unbind_token(&token);
        assert_eq!(
            env.events().all(),
            [TokenUnbound {
                token: token.clone()
            }
            .to_xdr(&env, &hooks)]
        );
        assert!(!client.token_is_bound(&token));

        // Unbinding an unbound token is a no-op.
        client.mock_all_auths().unbind_token(&token);
        assert_eq!(env.events().all(), []);
    }

    #[test]
    fn multi_token_binding_keeps_enforcement_isolated() {
        let env = Env::new_with_config(EnvTestConfig {
            capture_snapshot_at_drop: false,
        });
        let hooks = env.register(ComplianceHooks, ());
        let admin = Address::generate(&env);
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        let token_a = Address::generate(&env);
        let token_b = Address::generate(&env);
        let sac_a = env.register(MockSac, (&alice, &bob));
        let sac_b = env.register(MockSac, (&alice, &bob));
        // One policy serves both bound tokens; it blocks Bob everywhere.
        let policy = env.register(MultiTokenPolicy, (Some(bob.clone()),));

        let client = ComplianceHooksClient::new(&env, &hooks);
        client.initialize(&admin);
        client.mock_all_auths().set_config(&Some(policy), &true);
        client.mock_all_auths().bind_token(&token_a, &Some(sac_a));
        client.mock_all_auths().bind_token(&token_b, &Some(sac_b));

        // Both tokens admit the same compliant flow…
        assert_eq!(
            try_before_deposit(&env, &hooks, &token_a, &alice, &alice),
            Ok(())
        );
        assert_eq!(
            try_before_deposit(&env, &hooks, &token_b, &alice, &alice),
            Ok(())
        );
        // …and reject the same blocked party.
        assert_eq!(
            try_before_deposit(&env, &hooks, &token_a, &alice, &bob),
            Err(ContractError::PolicyDenied)
        );
        assert_eq!(
            try_before_deposit(&env, &hooks, &token_b, &alice, &bob),
            Err(ContractError::PolicyDenied)
        );

        // Freeze Alice on Token A only: Token B is untouched, so the same
        // operation still passes there (multi-token freeze isolation through
        // the full contract surface).
        client.mock_all_auths().freeze(&token_a, &alice);
        assert!(client.is_frozen(&token_a, &alice));
        assert!(!client.is_frozen(&token_b, &alice));
        assert_eq!(
            try_before_deposit(&env, &hooks, &token_a, &alice, &alice),
            Err(ContractError::AccountFrozen)
        );
        assert_eq!(
            try_before_deposit(&env, &hooks, &token_b, &alice, &alice),
            Ok(())
        );

        // Unbinding Token B revokes scope for B alone.
        client.mock_all_auths().unbind_token(&token_b);
        assert_eq!(
            try_before_deposit(&env, &hooks, &token_b, &alice, &alice),
            Err(ContractError::UnboundToken)
        );
    }
}
