# Errors

"Compliance failed" is not an error. Every denial the enforcement layer can
produce has a stable numeric code on the contract error
([`ContractError`](../contracts/compliance-hooks/src/lib.rs)) and a stable
machine-readable name ([`RejectionReason`](../crates/hook-core/src/reason.rs)).
The two are kept in lockstep — the contract error's `From<RejectionReason>`
mapping is exhaustive, so adding a reason without a code fails to compile.

## Code table

| Code | Contract error | Reason name | Meaning |
| ---: | -------------- | ----------- | ------- |
| 1 | `UnauthorizedCaller` | `unauthorized_caller` | The caller was not authorized for the operation. |
| 2 | `UnboundToken` | `unbound_token` | The token the operation concerns is not bound to this contract. |
| 3 | `PolicyDenied` | `policy_denied` | The configured policy denied an account. |
| 4 | `AccountFrozen` | `account_frozen` | An account holding funds is frozen. |
| 5 | `SpenderNotAuthorized` | `spender_not_authorized` | The spender of a delegated flow is not authorized. |
| 6 | `SanctionsBlocked` | `sanctions_blocked` | The policy's sanctions screen blocked the account. |
| 7 | `JurisdictionRestricted` | `jurisdiction_restricted` | The policy's jurisdiction rule blocked the account. |
| 8 | `SacAuthorizationFailed` | `sac_authorization_failed` | The underlying SAC authorization check failed or was unreachable. |
| 9 | `InvalidConfiguration` | `invalid_configuration` | The contract configuration is invalid or absent. |
| 10 | `PolicyUnavailable` | `policy_unavailable` | The policy contract could not be evaluated. |
| 11 | `RegistrationRequired` | `registration_required` | The operation requires a registered account. |
| 12 | `AlreadyInitialized` | *(contract only)* | `initialize` was called on an already-initialized contract. |

Codes 6, 7, and 11 are produced by policy deployments on `safeguard-policy`
and reserved here so every layer names the same rejection; the current
enforcement path surfaces them through the single `is_authorized` boolean as
`PolicyDenied`.

## Where an error surfaces

* **Gate failures** (2, 3, 4, 8, 9, 10): the hook entry point returns
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
  error. This is not a contract code; it maps semantically to
  `unauthorized_caller` (1). Tests distinguish it from contract codes.

## Fail-closed principle

There is no "unknown, proceed" state. An evaluation that cannot complete —
missing configuration, unbound token, unreachable policy, unreachable SAC — is
a denial. The enforcement layer would rather revert a legitimate operation than
let a blocked one through.
