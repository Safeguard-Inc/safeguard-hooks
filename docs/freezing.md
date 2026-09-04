# Freezing

Freeze administration is the one piece of state the hooks contract writes
beyond its own configuration and bindings. It is the enforcement-layer
circuit breaker: a frozen account is stopped regardless of what the policy
would say, until an admin unfreezes it.

## State model

Freeze state is **per (token, account)** — an account frozen on Token A is
untouched on Token B, and freezing requires the token to be in scope
(configuration present and token bound, else `#9`/`#2`).

```text
is_frozen(token, account) -> bool
```

## Administration

`freeze(token, account)` and `unfreeze(token, account)` are admin-gated
entry points (`docs/authorization.md`). Both are idempotent: freezing an
already-frozen account (or unfreezing an unfrozen one) is a no-op that
emits nothing. A real transition emits exactly one event —
`AccountFrozen` / `AccountUnfrozen` — naming the token and the account for
the audit bridge (`docs/events.md`).

## What a freeze blocks

A frozen **fund-holder** can neither send, receive, deposit, merge, nor
withdraw on that token:

| Operation | Frozen party | Result |
| --------- | ------------ | ------ |
| `register` | the account | `AccountFrozen` |
| `deposit` | `from` or `to` | `AccountFrozen` |
| `merge` | the account | `AccountFrozen` |
| `transfer` | `from` or `to` | `AccountFrozen` |
| `withdraw` | the exiting account | `AccountFrozen` |
| `transfer_from` | `from` or `to` | `AccountFrozen` |

The freeze gate runs *before* the policy and SAC gates for each party, so a
frozen party is stopped locally — no cross-contract cost is paid
(`docs/performance.md`).

## What a freeze does not block

* **The spender of a `transfer_from`.** A spender holds no funds, so it is
  not freeze-gated (policy only). Freezing the *owner* (`from`) does stop
  the delegation.
* **Other tokens.** Isolation is per token.
* **Policy rotations or unbinding.** A freeze survives every admin
  transition on the token — including unbinding and re-binding — until an
  admin unfreezes it (proven by the invariant and property suites in
  `contracts/compliance-hooks/tests/`).
* **SAC-level freezes when passthrough is off.** When passthrough is on,
  the underlying SAC's own `authorized()` state composes transitively
  (`docs/sac-passthrough.md`); the two freeze mechanisms are independent.

## Why withdrawal is covered

A frozen account cannot bypass the freeze by *exiting* the wrapper: the
withdrawal hook gates the exiting account through the same freeze (and
policy) check, so value cannot leave a frozen confidential balance into the
underlying asset.
