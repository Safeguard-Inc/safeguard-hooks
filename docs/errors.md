# Errors

"Compliance failed" is not an error. Every denial the enforcement layer can
produce has a stable numeric code on the contract error
([`ContractError`](../contracts/compliance-hooks/src/lib.rs)) and a stable
machine-readable name ([`RejectionReason`](../crates/hook-core/src/reason.rs)).
The two are kept in lockstep — the contract error's `From<RejectionReason>`
mapping is exhaustive, so adding a reason without a code fails to compile.

## Completeness audit

The codes below are the result of a completeness audit: every code is
*produced* by a real gate, and every denial path maps to a distinct code.
Reasons no code path could ever emit were removed rather than kept as dead
surface:

* **Admin-caller failures** are not contract errors. The admin gate uses the
  host-level `require_auth`, which reverts before the contract returns — so
  there is deliberately no "unauthorized caller" code (former code 1).
* **Sanctions/jurisdiction distinctions** are invisible on the
  `is_authorized(account, token) -> bool` policy wire — the policy answers a
  single boolean, so the old `sanctions_blocked` (6) and
  `jurisdiction_restricted` (7) codes could never be emitted. Policy-level
  reasons remain distinct on `safeguard-policy`.
* **Registration state** does not exist on this contract — the old
  `registration_required` (11) code had no producer.

Codes are **non-dense by design**: removed codes are never reissued to a new
variant, so numbers in the field, in saved incidents, and in audit tooling
never shift meaning.

## Code table

| Code | Contract error | Reason name | Meaning |
| ---: | -------------- | ----------- | ------- |
| 2 | `UnboundToken` | `unbound_token` | The token the operation concerns is not bound to this contract. |
| 3 | `PolicyDenied` | `policy_denied` | The configured policy denied an account. |
| 4 | `AccountFrozen` | `account_frozen` | An account holding funds is frozen. |
| 5 | `SpenderNotAuthorized` | `spender_not_authorized` | The spender of a delegated flow is denied by policy. The spender holds no funds, so its denial is distinct from the fund-holders' denial (3). |
| 8 | `SacAuthorizationFailed` | `sac_authorization_failed` | The underlying SAC authorization check failed or was unreachable. |
| 9 | `InvalidConfiguration` | `invalid_configuration` | The contract configuration is invalid or absent. |
| 10 | `PolicyUnavailable` | `policy_unavailable` | The policy contract could not be reached or evaluated (fail-closed). |
| 12 | `AlreadyInitialized` | *(contract only)* | `initialize` was called on an already-initialized contract. |

Every code is pinned by a test that asserts it is reachable and stable (see
the contract test suite and `cli/tests/cli.rs`).

## Where an error surfaces

* **Gate failures** (2, 3, 4, 5, 8, 10): the hook entry point returns
  `Err(ContractError)`, failing the token's nested call. The transaction
  reverts.
* **Administration on an uninitialized contract** (9): every admin entry point
  first runs the admin gate; with no admin stored it fails closed with
  `InvalidConfiguration`.
* **Re-initialization** (12): `initialize` on an initialized contract fails —
  re-initialization would be an admin rotation, and rotations must be
  authorized.
* **Signature failures**: when the contract is initialized but the caller is
  not the admin, the SDK's `require_auth` reverts with the host authorization
  error. This is not a contract code; it is the host-level equivalent of the
  removed `unauthorized_caller`. Tests distinguish it from contract codes.

## Fail-closed principle

There is no "unknown, proceed" state. An evaluation that cannot complete —
missing configuration, unbound token, unreachable policy, unreachable SAC — is
a denial. The enforcement layer would rather revert a legitimate operation than
let a blocked one through.