# Events

The on-chain record `safeguard-audit` (VERIFY) consumes. Emitted by the
hooks contract on **actual state transitions** — never on approvals, never
with private data. Implementation: `crates/events`; protocol reference:
`interfaces/events/events.md`; structured form:
`schemas/compliance-event.schema.json`.

## Catalog

| Event | Payload | Meaning |
| ----- | ------- | ------- |
| `AccountFrozen` | `token`, `account` | Admin froze the account on the token |
| `AccountUnfrozen` | `token`, `account` | Admin unfroze the account on the token |
| `TokenBound` | `token` | Admin admitted the token into scope |
| `TokenUnbound` | `token` | Admin removed the token from scope |
| `ComplianceConfigChanged` | `policy` (or none), `sac_passthrough` | Admin rewrote the compliance configuration |

## Why only transitions

* **Idempotent writes emit nothing.** Freezing an already-frozen account,
  unbinding an unbound token, or rewriting the identical configuration is a
  no-op — events describe state *changes*, and the exact-event tests pin
  this (`contracts/compliance-hooks/src/lib.rs`).
* **Per-operation approvals are never emitted.** Soroban contracts cannot
  introspect their caller, so any contract can invoke the hook surface; an
  "approved" record would be spoofable audit poison.
* **Denials cannot be emitted.** A rejection reverts the transaction, and
  reverts discard events. What an auditor can rely on is the *absence* of a
  transition for a rejected operation — the atomicity invariant
  (`docs/enforcement-model.md`).

## Privacy rule

Events carry **addresses and booleans only** — token, account, policy,
`sac_passthrough`. Never amounts, balances, commitments, or proof material
(`docs/privacy.md`).

## Ordering anchor

Each real `set_config` bumps the monotonic `config_version()`; audit pairs
a `ComplianceConfigChanged` event with the version to place every
historical rejection on the exact policy timeline it was evaluated under
(`docs/storage.md`).
