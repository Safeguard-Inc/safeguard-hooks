# Changelog

All notable changes to Safeguard Hooks, the ENFORCE layer of the Safeguard
compliance stack for Stellar Confidential Tokens.

The project shipped in the four roadmap phases defined in the architecture
(see `docs/architecture.md`). Each phase landed as a batch of
single-improvement commits.

## [Unreleased]

### Added — Phase 4 completion (documentation and reference surface)

* `schemas/` — eight JSON Schemas for the wire surfaces (compliance config,
  policy request/response, authorization decision, rejection reasons,
  compliance events, freeze state, token bindings) with a validator
  (`scripts/check-schema.sh`) wired into CI.
* `fixtures/` — schema-validated reference data (token bindings, account
  states, request/decision pairs for all six operations, DEFINE-side policy
  rule-sets).
* `examples/` — nine ready-to-adapt deployment configurations.
* `interfaces/` — canonical protocol references for hooks, the policy wire,
  and events.
* Eleven missing docs (`hook-lifecycle`, `compliance-engine`,
  `policy-integration`, `freezing`, `sac-passthrough`, `delegated-transfers`,
  `multi-token`, `events`, `integration`, `testing`, `contributing`).
* Root governance: `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`,
  this changelog.

## [Phases 1–4 — 2026-09]

### Phase 4 (completed)

* **Configuration versioning + state-transition events** — real `set_config`
  rewrites bump a monotonic `config_version` and emit
  `ComplianceConfigChanged`; `bind_token`/`unbind_token` emit
  `TokenBound`/`TokenUnbound` only on real changes; `config_version()` read.
* **Deployment tooling** — `safeguard-hooks deploy`: deploys the hooks
  contract and an optional policy, runs the lifecycle, binds configured
  tokens, and records fresh ids back with `--save`.
* **Performance guarantees** — the evaluator short-circuits at the first
  failing gate/party; counting-policy tests pin the cost table
  (`docs/performance.md`).

### Phase 3 (completed)

* Hardening suites: `tests/security.rs` (threat-model attacks),
  `tests/invariants.rs` (read-only enforcement, frozen-until-unfrozen,
  oracle parity), `tests/fuzz.rs` (deterministic randomized sequences vs an
  enforcement oracle).
* Live-ledger integration (`scripts/integration-local.sh` + CI) against the
  containerized local Soroban network, asserting every revert code.
* Operator CLI `safeguard-hooks` (init/configure/bind/unbind/freeze/
  unfreeze/show/errors/deploy).
* `contracts/sample-policy` — demo of the policy wire contract.

### Phase 2 (completed)

* Delegated `transfer_from` enforcement (policy-only spender); freeze
  administration with `AccountFrozen`/`AccountUnfrozen` events; SAC
  passthrough; multi-token binding.

### Phase 1 (completed)

* Foundation crates: `hook-core`, `policy-client`, `authorization`,
  `compliance`, `storage`, `events`; the `compliance-hooks` contract with
  `register`, `deposit`, `transfer`, `withdraw` enforcement.

## Note

This is a **developer-preview** stack for a developer-preview protocol
(Confidential Tokens on Stellar are testnet-only). Do not treat it as
production financial infrastructure.
