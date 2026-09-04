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
contracts/sample-policy      demo implementation of the policy wire contract
cli/                         operator CLI (thin; shells to the stellar CLI)
schemas/                     JSON Schemas for every wire surface
fixtures/ + examples/        schema-validated reference data and scenarios
interfaces/                  canonical hook/policy/event protocol references
```

### Where the planned module tree lives

The original structure sketch split the contract into per-concern module
directories (`hooks/`, `authorization/`, `policy/`, `compliance/`,
`state/`, `events/`, `errors/`, `types/`) and the CLI into
`commands/`. This repository keeps the same separation in a form that is
actually shareable and testable: each concern is a `crates/` library the
contract binary composes (and the suites test directly), and the CLI's
command surface is `cli/src/`. The contract and CLI stay thin. The
equivalent mapping:

| Planned module | Lives in |
| -------------- | -------- |
| hooks/register..withdraw, freeze | `crates/compliance` + contract `before_*` entry points |
| authorization/ (account, spender, admin, token) | `crates/authorization` + `crates/hook-core` party roles |
| policy/ (client, decision, request, response, errors) | `crates/policy-client` + `interfaces/policy` + `schemas/policy-*.schema.json` |
| compliance/ (evaluator, restrictions, jurisdiction, sanctions) | `crates/compliance` evaluator; rule evaluation stays policy-side |
| state/ (storage, bindings, frozen, versions) | `crates/storage` |
| events/ (topics, payloads) | `crates/events` + `interfaces/events` |
| errors/ | `crates/hook-core` reasons + contract error codes |
| types/ | `crates/hook-core` (operations, parties, decisions, config) |
| policy-adapter contract | `crates/policy-client` + `contracts/sample-policy` |
| cli commands/ | `cli/src/main.rs` command surface |

Reference data and protocol documentation that the sketch kept out of the
crates — `interfaces/`, `schemas/`, `fixtures/`, `examples/` — are real
directories here; `schemas/` is validated in CI by
`scripts/check-schema.sh` (`docs/testing.md`).

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

Phases 1–4 of the roadmap are implemented: the six foundation crates
and the `compliance-hooks` contract with `initialize`, `set_config`,
`bind_token` / `unbind_token`, admin-gated `freeze` / `unfreeze` (emitting
`AccountFrozen` / `AccountUnfrozen` events for the audit bridge), and hook
enforcement for all six confidential-token operations. Typed error codes
mirror `hook-core` reasons end to end; multi-token binding is exercised
through the full contract surface. Phase 3 added the explicit security,
invariant, and deterministic property suites described in
`docs/security.md` — 146 tests pass across the workspace.

Phase 4 closed the audit and operational gaps and pinned the performance
model. Configuration versioning and state-transition events: `set_config`
bumps a monotonic configuration version and emits
`ComplianceConfigChanged`, and binding changes emit `TokenBound` /
`TokenUnbound` — each only when state actually changes. Deployment
tooling brings up a full deployment from the config in one command
(`safeguard-hooks deploy`, `docs/cli.md`). The evaluation pipeline now
short-circuits — the chain stops at the first failing party, so denials
never pay a later party's cross-contract call — with the cost model and
guarantees recorded in `docs/performance.md`. Advanced policy integration
(rule versions, multi-policy routing, richer rule sets) is closed as a
documented boundary: it belongs to `safeguard-policy` behind the single
`is_authorized` seam, so the enforcement layer stays one boolean call per
screened party.
