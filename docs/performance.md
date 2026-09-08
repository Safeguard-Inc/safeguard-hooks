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

## Measuring the gate paths

The call-count guarantees above are proven by the counting-policy tests;
**wall-clock** cost per gate path is measured by the criterion suite in
`crates/compliance/benches/gate_paths.rs`. Each benchmark first asserts the
fixture really drives the named path (so a drift in gate order fails the
benchmark instead of silently timing the wrong thing), then times it:

```bash
cargo bench -p safeguard-compliance          # full timings
cargo bench -p safeguard-compliance -- --test  # fixture check, no timing
```

| Benchmark | Gate path timed | Cross-contract calls (same as the table above) |
| --------- | --------------- | -------------------------------------------: |
| `gate/deny_unconfigured` | no config → `InvalidConfiguration` | 0 |
| `gate/deny_unbound_token` | unbound token → `UnboundToken` | 0 |
| `gate/deny_frozen_first_party` | frozen sender → `AccountFrozen` | 0 |
| `gate/deny_frozen_second_party` | frozen recipient after a clean first party | 1 |
| `gate/deny_policy_second_party` | policy-denied recipient | 2 |
| `gate/allow_register_single_party` | single-party allow | 1 |
| `gate/allow_deposit_two_parties` | two-party allow | 2 |
| `gate/allow_transfer_from_three_parties` | spender (policy-only) + `from` + `to` | 3 |
| `gate/allow_withdraw_double_screen` | exiting account screened twice | 2 |
| `gate/allow_full_gate_sac_passthrough` | freeze + policy + SAC per fund-holder | 4 |

Two caveats. First, the numbers are produced on a host-emulated `Env` in
`crates/compliance`, not on a ledger — they are for *relative* gate cost and
regression watching (a change that adds a cross-contract call shows up as a
step-change) rather than absolute budget. Second, the timings are
machine-dependent; the machine-independent cost contract is the
call-count table above, which the counting-policy tests pin.

## Measured on-chain gas (Testnet, 2026-09-08)

The wall-clock benches above are for *relative* gate cost. The number a
token holder actually pays is the **fee charged** for a real transaction
(stroops; 1 XLM = 10,000,000 stroops) — it includes CPU instructions,
ledger footprint, storage rent and tx size. Measured with
`scripts/bench-gas.sh` against the deployment recorded in
`deployments/testnet/configuration.json` (repeat runs vary by a few
percent):

| Function | Stroops | XLM |
| -------- | ------: | ---: |
| `initialized` / `config` (reads) | 3,144 / 3,585 | ~0.00034 |
| `token_is_bound` / `is_frozen` (reads) | 3,930 / 4,230 | ~0.00041 |
| `before_register` (1 party, 1 policy call) | 8,866 | 0.000887 |
| `before_deposit` (2 parties, 2 policy calls) | 11,480 | 0.001148 |
| `before_transfer` (2 parties, 2 policy calls) | 11,480 | 0.001148 |
| `before_withdraw` (double screen, 2 policy calls) | 9,470 | 0.000947 |
| `freeze` (write, incl. new-entry rent) | 29,141 | 0.002914 |
| `unfreeze` (write) | 8,991 | 0.000899 |

So a compliant `before_deposit` — the most expensive regular operation —
costs **≈ 0.0011 XLM (~0.0004 USD)** on Testnet. Denied paths are strictly
cheaper (the short-circuit guarantees above: they stop at the first failing
local gate and never pay the cross-contract policy call for the party they
stop).

### 2026-09-08 optimization: release profile

The workspace previously built wasm with cargo's default release profile.
The contract's release profile now mirrors `safeguard-policy`'s:
`opt-level = "z"`, `lto = true`, `codegen-units = 1`, `panic = "abort"`,
`strip = "symbols"`, `overflow-checks = true` (fail-closed arithmetic stays
on — it is a correctness guarantee, not a cost to trade away). Effect:

| Metric | Before | After |
| ------ | -----: | ----: |
| `compliance_hooks.wasm` size | 27,138 B | 25,687 B (−5%) |
| `sample_policy.wasm` size | 3,166 B | 2,485 B (−21%) |
| `before_deposit` / `before_transfer` | 12,779 | 11,480 (**−10%**) |
| `before_withdraw` | 10,768 | 9,470 (**−12%**) |
| `before_register` | 10,039 | 8,866 (**−12%**) |
| state reads (`initialized`, `config`, …) | ~3–4k | unchanged (noise) |

The cross-contract policy call remains the dominant term in the allowed
paths — that is the architecture's cost, and it also dropped because the
policy side optimized its own `is_authorized` (see safeguard-policy
`docs/gas.md`): the two optimizations compound per screened party.

### Caveats

* Fees drift with network pricing (`stellar network settings --network
  <net>`); re-run `bash scripts/bench-gas.sh testnet` for current numbers.
* Storage **rent** is charged on writes and TTL extension; a read that
  happens to bump an entry's TTL shows a one-off spike (observed once:
  `token_is_bound` at 57,587 stroops vs. 3,930 steady-state). The stable
  numbers above are steady-state.
