# Performance and cost model

This document records what a state-changing token operation costs when it
passes through the enforcement layer, and — more importantly — what a
**denied** operation is guaranteed *not* to cost. The guarantees here are
proven by the counting-policy tests in `crates/compliance` and hold for the
contract on a real ledger.

## Gate ordering

`crates/compliance/src/evaluator.rs` runs the gates in a deliberate order.
Every gate before a given point is cheaper than every gate after it:

```text
evaluate(token, operation, parties)
  │
  ├─ 1. compliance_config present?          local storage read
  ├─ 2. token bound?                        local storage read   (else UnboundToken)
  │
  └─ per party, in Operation::parties order:
       ├─ freeze?                           local storage read   (fund-holding roles only)
       ├─ policy is_authorized?             CROSS-CONTRACT call  (every role, if policy set)
       └─ SAC authorized?                   CROSS-CONTRACT call  (fund-holding roles, if enabled)
```

Local reads cost nothing compared with cross-contract calls, so structural
and freeze denials never pay the policy round-trip for the party they stop.

## Short-circuit guarantees

1. **Cheap gates run first within a party.** A frozen fund-holder is denied
   at the local freeze gate; its policy and SAC calls are never made.
2. **The chain stops at the first failing party.** Once any gate denies,
   the operation is dead and *no later party is screened at all*. A denial
   never pays a subsequent party's cross-contract policy or SAC call.
3. **Allowed paths pay exactly one policy call per party.** An allowed
   `deposit` screens its two parties — exactly two policy calls. An allowed
   `register` or `merge` screens one.

These are the only cost properties the enforcement layer promises. They are
asserted by `CountingPolicy` tests that pin a policy contract recording how
often it was consulted:

| Scenario | Policy consultations | Proof |
| -------- | -------------------: | ----- |
| Unbound-token operation | 0 | `denials_short_circuit_before_the_policy_call` |
| Frozen first party | 0 | same |
| Frozen second party (first party allowed) | 1 (the first party only) | same |
| Allowed deposit | 2 | `allowed_path_consults_the_policy_exactly_once_per_party` |
| Allowed register | 3 cumulative | same |

### What is deliberately not optimized

Screening happens **once per named party per operation**, by design: parties
are distinct addresses in the normal flows (`from` and `to` are different
accounts). `withdraw` names the exiting account in both the `from` and `to`
roles and screens it through the full gate twice — the second pass is a
no-op against an account that just passed, and the redundancy is what makes
the reason at the top of the rejection chain deterministic for every
operation shape. Do not "optimize" that away without re-running the
oracle-parity suites (`tests/invariants.rs`, `tests/fuzz.rs`).

## The policy-integration boundary

The performance properties above assume the policy wire contract is the
one `safeguard-policy` defines:

```text
is_authorized(account: Address, token: Address) -> bool
```

One call, one boolean, fail-closed. Everything beyond that boundary —
allowlists and denylists, sanctions lists, jurisdiction rules, identity
registries, per-token rule sets, and policy *versions* — is policy-side
concern (the DEFINE polyrepo). The enforcement layer never:

* iterates policy lists or evaluates policy rules itself;
* knows how many versions a policy has or which one is live;
* routes an operation to more than one policy contract.

If a deployment needs richer authorization (multi-policy routing, staged
escalation, rule versions consulted by the decision), it belongs in
`safeguard-policy`: it can expose any number of `is_authorized`-shaped
entry points or an internal registry, and the hooks contract simply invokes
the configured policy address. Keeping that seam at a single boolean call
is what bounds enforcement cost at one cross-contract trip per screened
party and keeps the two polyrepos from re-implementing each other.
