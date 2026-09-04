# SAC passthrough

Optional composition with a token's underlying Stellar Asset Contract.
When a confidential token wraps a SAC, the issuer may already manage
authorization on the SAC (e.g. freezing or deauthorizing an account). SAC
passthrough lets enforcement inherit that state transitively instead of
mirroring it.

## Model

```text
Confidential token operation
        │
        ▼
compliance-hooks (bound token carries its SAC address)
        │
        ▼
SAC.authorized(account)?   ── standard SAC authorization view
        │
        ├─ yes → continue
        └─ no / unreachable → REJECT (SacAuthorizationFailed, #8)
```

* Enabled per deployment via `set_config(policy, sac_passthrough: bool)`.
  The flag is part of the compliance configuration
  (`docs/storage.md`) and a real flip emits `ComplianceConfigChanged`.
* The SAC address comes from the token's binding
  (`bind_token(token, sac)`); a token bound with no SAC simply has nothing
  to compose.
* Only **fund-holding parties** are SAC-gated. The spender of a delegated
  flow holds no funds and is not checked against the SAC.
* A SAC that cannot be reached fails closed: `authorized()` that reverts or
  misbehaves is a denial, never a silent pass.

## Interaction with other gates

Per party the gate order is **freeze → policy → SAC** (`docs/compliance-engine.md`),
so the local freeze and the policy screening happen before the SAC round
trip, and once any gate denies the remaining gates are skipped.

| Freeze state | Policy | SAC passthrough | Result |
| ------------ | ------ | --------------- | ------ |
| unfrozen | allow | on, authorized | ALLOW |
| frozen | — | — | `AccountFrozen` (before any SAC call) |
| unfrozen | deny | — | `PolicyDenied` |
| unfrozen | allow | on, not authorized | `SacAuthorizationFailed` |
| unfrozen | allow | off | ALLOW (SAC never consulted) |

The trade-off is documented: SAC passthrough adds one cross-contract call
per fund-holding party per operation when enabled (`docs/performance.md`),
and it makes issuer-side SAC freezes effective at the confidential layer —
the confidential and SAC authorization states stay aligned without the
hooks contract holding SAC state.
