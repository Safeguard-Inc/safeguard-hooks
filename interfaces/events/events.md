# Events (audit bridge)

State-transition events emitted by the hooks contract, consumed by
`safeguard-audit` (VERIFY). Emitters live in `crates/events`; each event is
a Soroban contract event whose topics name the event type and whose payload
carries the transition.

## The emission discipline

* **Events describe state transitions, not operations.** Only events that
  mark an actual on-chain change are emitted: freezing, unfreezing,
  binding, unbinding, and configuration rewrites. Idempotent repeats (e.g.
  freezing an already-frozen account, rewriting the identical config) emit
  nothing.
* **Per-operation approvals are never emitted.** Any contract can invoke
  the hook surface (Soroban has no caller introspection), so an approval
  record would be spoofable audit poison; and a *denial* reverts, which
  discards events. See `crates/events/src/lib.rs` for the full rationale.
* **No private data.** Events carry addresses and booleans only — never
  amounts, balances, commitments, or proofs.

## Event catalog

| Event | Topic | Payload | Emitted by |
| ----- | ----- | ------- | ---------- |
| `AccountFrozen` | `AccountFrozen` | `token`, `account` | admin `freeze` on a real change |
| `AccountUnfrozen` | `AccountUnfrozen` | `token`, `account` | admin `unfreeze` on a real change |
| `TokenBound` | `TokenBound` | `token` | admin `bind_token` on a real change |
| `TokenUnbound` | `TokenUnbound` | `token` | admin `unbind_token` on a real change |
| `ComplianceConfigChanged` | `ComplianceConfigChanged` | `policy` (or `None`), `sac_passthrough` | admin `set_config` on a real change |

## Ordering anchor

Every real `set_config` also bumps the monotonic `config_version()`
(`docs/storage.md`). `safeguard-audit` pairs a `ComplianceConfigChanged`
event with the version to reconstruct the exact policy timeline a
historical rejection refers to.

Structured documentation form: `schemas/compliance-event.schema.json`.
