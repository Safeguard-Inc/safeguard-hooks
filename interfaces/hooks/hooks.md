# Hook entry points (`before_*`)

A token opts into enforcement by calling these entry points *before* it
applies a state change. The call is a plain (non-`try`) nested call: when it
fails, the whole transaction reverts — **rejected operation = no state
change**. No entry point accepts an amount; balances, commitments, and
proofs never reach the enforcement layer.

Implemented in `contracts/compliance-hooks/src/lib.rs`; the evaluation
pipeline behind them lives in `crates/compliance` and the gate order is
documented in `docs/enforcement-model.md`.

## Common shape

```text
before_<operation>(env, token, <parties…>) -> Result<(), ContractError>
```

* `token` is the caller's own address. Soroban contracts cannot introspect
  their caller, so every entry point takes the token explicitly and the
  binding gate rejects unbound tokens (`Error(Contract, #2)`).
* The returned error code maps onto a `RejectionReason`
  (`schemas/rejection.schema.json`, `docs/errors.md`).

## Entry points

| Operation | Signature | Parties gated |
| --------- | --------- | ------------- |
| `register` | `before_register(env, token, account)` | `account`: freeze → policy → SAC |
| `deposit` | `before_deposit(env, token, from, to)` | `from`, `to`: full gate |
| `merge` | `before_merge(env, token, account)` | `account`: full gate |
| `transfer` | `before_transfer(env, token, from, to)` | `from`, `to`: full gate |
| `transfer_from` | `before_transfer_from(env, token, spender, from, to)` | `spender`: policy only; `from`, `to`: full gate |
| `withdraw` | `before_withdraw(env, token, account)` | `account` (both roles): full gate |

The `spender` of a delegated flow holds no funds, so freeze and SAC gates do
not apply to it; it is still screened by the external policy
(`docs/delegated-transfers.md`).

## Freeze administration (admin-gated)

`freeze(env, token, account)` and `unfreeze(env, token, account)` are not
token-facing hooks — they are the admin authority surface that writes
per-(token, account) freeze state and emits the audit events.

## Reads

`token_is_bound(token) -> bool`, `initialized() -> bool`,
`config() -> Option<ComplianceConfig>`, `config_version() -> u32`, and
`is_frozen(token, account) -> bool` expose the enforcement state to tooling
(the operator CLI reads these through simulations).
