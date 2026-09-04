# Architecture

Safeguard is a three-polyrepo compliance stack for Stellar Confidential Tokens
built around a single pipeline:

```text
                    SAFEGUARD
                       │
          ┌────────────┼────────────┐
          │            │            │
          ▼            ▼            ▼
     DEFINE         ENFORCE       VERIFY
          │            │            │
          ▼            ▼            ▼
safeguard-policy  safeguard-hooks  safeguard-audit
```

| Polyrepo | Concern | Question |
| -------- | ------- | -------- |
| `safeguard-policy` | Define | "What should happen?" |
| **`safeguard-hooks`** (this repo) | Enforce | "Make it happen." |
| `safeguard-audit` | Verify | "What happened?" |

This repository is the enforcement layer. It must never become a second policy
engine (no rule definition here) and never a second audit store (no reporting
here). Its job is narrow: given a state-changing operation on a bound token,
decide whether it may proceed, and make the operation revert when it may not.

## Repositories in this repo

```text
contracts/compliance-hooks   deployable Soroban contract — thin entry surface
crates/
  hook-core                  environment-free domain model (operations, parties,
                             decisions, rejection reasons)
  storage                    state keys + persistence (admin, config, bindings,
                             freeze, version)
  authorization              authority gates: admin, token enforcement scope
  policy-client              typed fail-closed bridge to safeguard-policy
  compliance                 the gate-ordering evaluation pipeline (freeze →
                             policy → SAC) and the SAC authorized() view
  events                     typed #[contractevent] structs (audit bridge)
```

## Where each decision lives

* **Policy rules** (allowlists, denylists, sanctions, jurisdictions, identity
  registries) — `safeguard-policy`. Reached only through `policy-client`'s
  single `is_authorized(account, token)` wire contract.
* **Enforcement state** — this repo's contract: its own admin, per-token
  bindings, per-(token, account) freeze flags, and the active compliance
  configuration.
* **Gate ordering** — `safeguard-compliance`: configuration → binding →
  per-party freeze → policy → SAC.
* **Who may touch enforcement state** — `safeguard-authorization` (admin gate)
  and the contract (admin-gated entry points).
* **Evidence** — events emitted by this contract's admin operations feed
  `safeguard-audit`. Per-operation approvals are deliberately never emitted:
  any contract can invoke the hook surface (Soroban has no caller
  introspection), so approval records would be spoofable audit poison. Denials
  cannot be emitted — a rejected operation reverts, and reverts discard events.
  See `crates/events/src/lib.rs` for the full rationale.

## Relationship to the confidential token

The enforcement contract is *consulted by* a confidential token. The token is
deployed with its compliance hook address; before applying a state change it
invokes the matching `before_*` hook here and applies nothing when the call
fails. The token remains the gatekeeper of its own flows: signature checks for
operation parties happen at the token, where balances and allowances live.

Phases 1–3 of the roadmap are implemented: the six foundation crates
and the `compliance-hooks` contract with `initialize`, `set_config`,
`bind_token` / `unbind_token`, admin-gated `freeze` / `unfreeze` (emitting
`AccountFrozen` / `AccountUnfrozen` events for the audit bridge), and hook
enforcement for all six confidential-token operations. Typed error codes
mirror `hook-core` reasons end to end; multi-token binding is exercised
through the full contract surface. Phase 3 added the explicit security,
invariant, and deterministic property suites described in
`docs/security.md` — 113 tests pass across the workspace.
