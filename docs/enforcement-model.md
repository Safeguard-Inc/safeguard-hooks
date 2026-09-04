# Enforcement model

The enforcement layer answers one question per operation: **may this
state-changing operation on this token proceed?** If not, the operation is
reverted atomically.

```text
Confidential token operation
          │
          ▼
  Hook invocation (before_*) — token passes its own address
          │
          ▼
  Configuration present? ── no ──▶ REVERT (InvalidConfiguration)
          │ yes
          ▼
  Token bound? ────────── no ──▶ REVERT (UnboundToken)
          │ yes
          ▼
  For each party the operation names, in canonical order:
     │
     ├─ fund-holding party frozen? ──────────▶ REVERT (AccountFrozen)
     ├─ party screened by policy? denied ────▶ REVERT (PolicyDenied)
     │        policy unreachable ────────────▶ REVERT (PolicyUnavailable)
     └─ SAC passthrough on and party not
        authorized on the underlying SAC ─────▶ REVERT (SacAuthorizationFailed)
          │
          ▼
       ALLOW — the token applies its state change
```

## Operations and their parties

| Operation | Parties gated | Roles |
| --------- | ------------- | ----- |
| `register` | account | full (freeze, policy, SAC) |
| `deposit` | depositor `from`, wrapper `to` | full |
| `transfer` | `from`, `to` | full |
| `withdraw` | exiting account | full |
| `merge` *(Phase 2)* | account | full |
| `transfer_from` *(Phase 2)* | `spender`, `from`, `to` | spender: policy only |

The spender of a delegated flow holds no funds — the value stays the owner's —
so freezing and SAC gates (which protect fund ownership) do not apply to it.
It is still screened by the external policy. This mirrors the allowance models
of the OpenZeppelin library's fungible and RWA tokens.

## Gate ordering

Order is deliberate:

1. **Configuration** — an unconfigured enforcement contract cannot enforce
   anything. Failing closed here (rather than silently passing operations)
   means a token can never run ungated by pointing at a half-deployed
   contract.
2. **Binding** — unbound tokens are rejected before any gate runs. This is the
   admission control behind token-spoofing and cross-token contamination
   protection.
3. **Per party**: freeze → policy → SAC.

Cheap, local gates (freeze is a storage read) run before expensive
cross-contract gates (policy, SAC). When multiple parties or gates fail, the
*first* failure in canonical order is reported, so the top of the rejection
chain is deterministic.

## Policy and SAC gates

* **Policy**: one `is_authorized(account, token)` call per party to the
  configured `safeguard-policy` contract. `Ok(true)` passes, `Ok(false)` is a
  denial, and an unevaluable policy (reverted, missing, non-boolean answer) is
  a denial — never a silent pass. The policy receives the token on every call
  so one registry can apply per-token rules.
* **SAC passthrough**: when enabled and the token wraps a Stellar Asset
  Contract, each fund-holding party is additionally checked against the SAC's
  standardized `authorized(account)` view. This composes the issuer's own
  freeze/deauthorize without mirroring state (transitive compliance).
  A SAC that cannot be reached is a denial.

## Atomicity

A denial is an `Err(ContractError)` returned to the invoking token. The token
performs a plain (non-`try`) nested call, so the denial fails that call and the
whole transaction reverts. There is no state in which a balance was updated and
a compliance rejection was then produced:

> **Rejected operation = no state transition.**

This invariant is exercised by the invariant and security test suites
(dedicated suites land with Phase 2 hardening; the evaluator and contract
tests already assert every gate path above).
