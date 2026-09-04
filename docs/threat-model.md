# Threat model

Threats against the enforcement layer, the control that addresses each, and
where it is tested. Shaded controls are defense in depth — Soroban's execution
model makes the primary defense architectural (see `docs/authorization.md`).

## Token spoofing

An attacker deploys a contract that claims to be a bound token and invokes the
hook surface.

* **Control:** the token-scope gate — the claimed token must have a binding
  entry, else `UnboundToken`. Even a *bound* token cannot use a spoofed call to
  affect another token's state: gates never write token-visible state.
* **Primary defense:** the confidential token only consults its configured
  compliance address; impersonating the *hooks contract* is what matters, and
  that is decided at token deployment.
* **Tested:** `authorization` scope tests; `compliance` unbound-token test;
  `contracts` `unbound_token_reverts_before_any_gate`.

## Cross-token contamination

Token A's compliance state (freeze, bindings) is used to gate Token B, or a
decision for A is reused for B.

* **Control:** all per-token state is keyed by `(token, …)`; the evaluator keys
  every read by the operation's token; the policy receives the token on every
  call so a shared registry can distinguish tokens.
* **Tested:** storage isolation tests; `compliance` `decisions_are_isolated_per_token`.

## Unauthorized administration / configuration attack

An attacker rotates the policy, binds an attacker token, unbinds a victim
token, or freezes/unfreezes at will.

* **Control:** every admin entry point runs the admin gate (`require_auth` of
  the stored admin); `initialize` cannot be replayed to rotate the admin;
  uninitialized contracts fail closed.
* **Tested:** `authorization` admin tests; `contracts` double-initialization,
  unauthorized-admin, and uninitialized-contract tests.

## Hook bypass

A blocked party routes around a hook — e.g. a frozen account withdrawing to
escape the freeze, or executing an operation without the policy check.

* **Control:** the *token* invokes hooks for every state-changing operation
  before applying state (this is the token's compliance contract). Within the
  enforcement layer, every gate path is exercised per operation and party
  role; a withdrawal is gated exactly like any other fund movement.
* **Tested:** `compliance` withdraw/register/deposit tests including the
  frozen-exiting-account case.

## Policy spoofing / compromise

The policy address in config is not the real policy, or a configured policy
misbehaves.

* **Control:** config writes are admin-gated; the policy client fails closed on
  a reverting or non-boolean policy (`PolicyUnavailable`) rather than
  misinterpreting it. Policy *compromise* is outside this layer's controls —
  the policy is deployment trust surface (DoS at worst; it cannot move funds).
* **Tested:** `policy-client` reverting/missing tests; `compliance`
  `reverting_policy_is_reported_unavailable`.

## SAC unavailability

The underlying Stellar Asset Contract cannot be reached during a gated
operation.

* **Control:** the SAC check fails closed (`SacAuthorizationFailed`). When
  passthrough is off, the SAC is never consulted — a deployment choice.
* **Tested:** `sac` reverting/missing tests; `compliance` reverting-SAC and
  passthrough-off tests.

## Event leakage / audit poisoning

Private data leaks through events, or spoofed events poison the audit trail.

* **Control:** event structs carry addresses and booleans only; the contract
  emits events only for state changes *it* applies. Per-operation approvals are
  never emitted (spoofable), and denials revert (reverts discard events).
* **Tested:** `events` topic/attribution tests.

## Replay / re-entrancy

A previously authorized context is replayed, or nested calls re-enter state
writes.

* **Control:** signature replay prevention is the host's job
  (`require_auth`); the enforcement surface writes no state during hook calls,
  so there is nothing to re-enter mid-operation. Freeze administration is
  single-write and admin-gated.
* **Tested:** re-entrancy and replay scenarios are part of the Phase 3
  hardening suite.

## Denial of service

Spamming the hook surface or forcing repeated cross-contract calls.

* **Control:** hook calls write nothing, so spam is bounded by the caller's
  own fees. Cross-contract policy/SAC calls are bounded per operation by the
  number of named parties. Budget exhaustion of a *bound* token's operations is
  gated by the token's own flow.
* **Follow-up:** cost accounting is part of the Phase 3 benchmark work.
