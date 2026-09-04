# Authorization

Authorization and compliance are different questions, and the enforcement
layer keeps them apart:

> **Authorization:** is this *caller* allowed to perform this operation?
>
> **Compliance:** is this *account* permitted under the configured rules?

A compliant account can still be unauthorized to act, and an authorized caller
can still be stopped by compliance:

```text
Alice is KYC-approved       (compliance)
+ Alice is not frozen       (compliance)
+ Alice signed the call     (authorization)
= Alice may transact
```

```text
Alice is KYC-approved + Bob is sanctions-blocked
= transfer Alice → Bob rejected        (compliance, not authorization)
```

## What this contract can authorize

The enforcement contract answers exactly two authority questions, because it
holds exactly two things it can vouch for:

1. **Who may change enforcement state?** A single admin authority, stored at
   `initialize`, gates every state-changing entry point — `set_config`,
   `bind_token`, `unbind_token` (and, in Phase 2, `freeze`/`unfreeze`). The
   gate is `admin.require_auth()`: the stored admin must have signed. There is
   no anonymous configuration, no unbind without the admin, no re-initialization
   (an `initialize` on an initialized contract fails with `AlreadyInitialized`
   because re-initialization would rotate the admin).

2. **Which tokens are within enforcement scope?** A token must be *bound*
   before any gate runs for it. The binding gate rejects unbound tokens with
   `UnboundToken`, which is the defense behind token-spoofing and cross-token
   contamination protection.

## What this contract cannot authorize (the caller model)

Soroban contracts cannot introspect their caller. When a confidential token
invokes `before_deposit`, this contract cannot tell "the bound token" from an
impersonator — it sees only arguments. It therefore does not pretend to check
who called. Instead:

* The **token** is the gatekeeper of its own compliance: it is constructed with
  its compliance hook address and only consults that address, so impersonating
  the hooks contract is impossible from the token's side.
* Signature checks that matter — an account authorizing its own `register`, a
  delegating owner authorizing a spender, the party behind an allowance —
  happen **at the token**, which holds the balance, allowance, and registration
  state, before the token ever calls a hook.
* The enforcement contract gates what *it* holds: its admin, its binding table,
  its freeze flags, and the external policy's decision.

This is why there is no account- or spender-scoped authorization module in this
repo: re-checking signatures against state the contract does not hold would be
impossible (no caller identity) and redundant (the token already checked).
The boundary is documented in `crates/authorization/src/lib.rs`.

## Separation of duties

A single admin is the default. Deployments that need distinct freeze, policy,
and clawback signers swap the check at the entry point (e.g. an RBAC contract
behind the admin gate); the storage and authorization shapes do not change.
See the OpenZeppelin confidential-token compliance note on composing access
control.
