# Hook lifecycle

What happens between a token deciding to change state and the state change
actually applying. One operation, end to end:

```text
Confidential token operation
          │
          ▼
  1. Hook invocation (before_<op>, token passes its own address)
          │
          ▼
  2. Enforcement evaluation (crates/compliance)
     ├─ configuration present?            else InvalidConfiguration
     ├─ token bound?                      else UnboundToken
     └─ per party, canonical order:
         freeze → policy → SAC            first failing gate wins
          │
          ▼
  3. Decision
     ├─ ALLOW  → the hook returns Ok(())
     │           └─ the token applies its state change (its own proof/signature model)
     └─ DENY   → the hook returns Err(ContractError)
                 └─ the nested call fails → the WHOLE transaction reverts
```

## The rules that make it safe

1. **Fail-closed.** An evaluation that cannot decide (policy unavailable,
   invalid configuration) is a denial, never an allow.
2. **Atomic.** A denial is a revert: no balance update, no partial event, no
   half-written state. `Rejected operation = no state transition.`
3. **Cheap-first, short-circuiting.** Structural checks (configuration,
   binding) run before any party gate; inside a party, the local freeze read
   runs before the cross-contract policy and SAC calls; and once any gate
   denies, no later party is screened at all (`docs/performance.md`).
4. **Parties are screened in canonical order.** The first failing party in
   that order names the reason at the top of the chain, so rejection codes
   are deterministic and reproducible.
5. **No amounts.** No hook entry point accepts an amount, so the lifecycle
   never observes private financial data (`docs/privacy.md`).

## Where each step runs

| Step | Owner |
| ---- | ----- |
| Operation + party signature checks | the confidential token (balances/allowances live there) |
| Compliance evaluation | this repo — `crates/compliance` behind the `compliance-hooks` contract |
| Eligibility decision | the external `safeguard-policy` contract, reached via `crates/policy-client` |
| On-chain record of admin transitions | this repo — freeze/bind/config events (`docs/events.md`) |

The token remains the gatekeeper of its own flows; the enforcement layer is
consulted, and when it says no, the token's operation dies with it.
