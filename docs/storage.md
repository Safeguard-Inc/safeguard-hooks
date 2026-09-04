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
| `Version` | instance | state-layout version for forward migrations |
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

[`ComplianceConfig`]: ../crates/storage/src/config.rs
