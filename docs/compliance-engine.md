# Compliance engine

The evaluation pipeline behind every hook entry point. Implemented in
`crates/compliance/src/evaluator.rs`; the domain model it works on lives in
`crates/hook-core`.

## The evaluation order

```text
evaluate(token, operation, parties)
  1. configuration present?        — else InvalidConfiguration (#9)
  2. token bound?                  — else UnboundToken (#2)
  3. per party, in Operation::parties order:
       freeze?                     — fund-holding roles only (AccountFrozen, #4)
       policy is_authorized?       — every role, when a policy is configured
                                    (PolicyDenied #3 / PolicyUnavailable #10)
       SAC authorized()?           — fund-holding roles, when passthrough is on
                                    (SacAuthorizationFailed #8)
```

Three properties make the ordering safe and cheap:

1. **Deterministic.** A failure's reason is always the first failing gate in
   canonical order, so the top of a rejection chain is reproducible.
2. **Cheap gates before expensive ones.** The configuration and binding
   checks are local storage reads; within a party the freeze read precedes
   the cross-contract policy and SAC calls.
3. **Short-circuit.** Once any gate denies, evaluation stops — no later
   party is screened, so a denial never pays a subsequent party's
   cross-contract call. The counting-policy tests in this crate pin the cost
   table (`docs/performance.md`).

## Party roles

`crates/hook-core` models who holds funds per operation
(`crates/hook-core/src/party.rs`):

* `account` / `from` / `to` — **full gate**: freeze, policy, and SAC.
* `spender` (delegated `transfer_from`) — **policy only**: it holds no
  funds, so freezing and SAC gates do not apply, but the policy still
  screens it.

Operations name their parties in canonical order
(`Operation::parties`): a non-compliant spender is rejected before any
fund-holder gate runs.

## Why the engine holds no rules

The evaluator decides *nothing* about eligibility. Policy answers come from
the external contract through the fail-closed client; rule evaluation
(allowlists, sanctions, jurisdictions) lives in `safeguard-policy`. This
module only enforces the returned boolean and translates an unevaluable
policy into a denial — keeping the ENFORCE polyrepo from growing a second
policy engine (`docs/policy-integration.md`, `docs/architecture.md`).

## Operation wrappers

`evaluate_register`, `evaluate_deposit`, `evaluate_merge`,
`evaluate_transfer`, `evaluate_transfer_from`, and `evaluate_withdraw`
bind the engine to each operation's party set; `withdraw` gates the exiting
account in both the `from` and `to` roles, which keeps the top-of-chain
reason deterministic for every operation shape.
