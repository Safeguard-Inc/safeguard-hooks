# Storage

Enforcement state is deliberately small: the contract stores only what it needs
to *make the transaction obey the decision*. Policy rules live in
`safeguard-policy`; account registrations and allowances live at the
confidential token; nothing is mirrored here that can be consulted where it
lives.

## Entries

| Key | Class | Holds |
| --- | ----- | ----- |
| `Admin` | instance | the administrative authority (single address) |
| `Config` | instance | the active [`ComplianceConfig`] — `policy` address and `sac_passthrough` flag |
| `ConfigVersion` | instance | monotonic count of configuration rewrites (policy rotation included) — the audit ordering anchor |
| `Version` | instance | state-layout version, stamped at `initialize` (and self-healed by admin config writes for deployments upgraded in place) — read via `state_version()` |

## State-layout versioning and upgrades

`Version` records which layout a deployment's state is written in. It is
stamped at `initialize` (the one authoritative, admin-authorized birth
moment) and exposed as `state_version()`; it reads `0` only for a never-
initialized contract. Upgrade tooling compares `state_version()` against the
new code's compiled-in `VERSION` (`crates/storage/src/versions.rs`) to
decide whether a migration must run before the upgraded code serves
traffic.

Deployments upgraded in place from pre-stamping code self-heal: the first
admin-gated `set_config` after the upgrade stamps the layout that code
actually runs (guarded — an existing stamp is never overwritten). The
security guarantee is unchanged either way: `initialize` requires the
prospective admin's authorization, so only the deployment's admin (or the
bootstrap transaction itself) can influence the stamp.
| `TokenBinding(token)` | persistent | whether `token` is in scope and, when it wraps a SAC, the SAC address |
| `Freeze(token, account)` | persistent | per-(token, account) freeze flag |

Every key is a variant of the single `DataKey` enum so the full state surface
is auditable in one place.

## Design rules

* **Key by token *and* account.** Freeze state and bindings are namespaced per
  token so a decision for Token A can never bleed into Token B
  (multi-token isolation, exercised by tests).
* **No caller authorization in storage.** Storage helpers write what they are
  told; authorization lives in the entry points
  (`safeguard-authorization` and the contract). Every write helper documents
  exactly what it does *not* check.
* **No policy registry here.** The hook layer needs only the *decision*
  reference — the policy address — not the rules. Registries, allowlists, and
  jurisdictions are `safeguard-policy`'s job.
* **TTL maintenance.** Reads of persistent entries (e.g. freeze flags) renew
  their lifetime so an actively-used flag never silently expires.

## Configuration semantics

`Config` absent means the enforcement contract was never activated: admin
entry points fail closed with `InvalidConfiguration` and hooks reject every
operation. `Config` present — even with `policy: None` and
`sac_passthrough: false` — means enforcement is on: the freeze gate always
applies, and bindings are meaningful. This is the fail-closed lifecycle
described in `docs/enforcement-model.md`.

### Configuration versioning

`ConfigVersion` counts real configuration rewrites: the first `set_config`
lands on `1`, a no-op rewrite (identical policy and SAC flag) changes
nothing, and every policy rotation or SAC-flag change bumps the counter.
The count is exposed as `config_version()` and paired with each
`ComplianceConfigChanged` event, so `safeguard-audit` can order
configuration changes and detect a missed event (gap detection). The same
transition discipline applies to bindings: `TokenBound`/`TokenUnbound`
events fire only when the binding actually changes, and hook evaluations
never write — or bump — any of this state.

[`ComplianceConfig`]: ../crates/storage/src/config.rs
