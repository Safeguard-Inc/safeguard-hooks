# Safeguard Hooks

**Enforcement layer of the Safeguard compliance stack for Stellar Confidential Tokens.**

Safeguard is a three-polyrepo system built around a DEFINE → ENFORCE → VERIFY pipeline:

```
                    SAFEGUARD
                       │
          ┌────────────┼────────────┐
          │            │            │
          ▼            ▼            ▼
     DEFINE         ENFORCE       VERIFY
          │            │            │
          ▼            ▼            ▼
safeguard-policy  safeguard-hooks  safeguard-audit
          │            │            │
          │            │            │
          └───────┬────┴───────┬────┘
                  │             │
             Policy API     Audit Events
                  │             │
                  ▼             ▼
             Decision       Evidence
```

| Polyrepo     | Concern                  | Question answered        |
| ------------ | ------------------------ | ------------------------ |
| `safeguard-policy` | Define                 | "What should happen?"    |
| **`safeguard-hooks`** | **Enforce**        | **"Make it happen."**    |
| `safeguard-audit` | Verify               | "What happened?"         |

This repository is the **enforcement layer**. It implements a Soroban-native
compliance-hook contract and the reusable crates behind it. Policy *definition*
(allowlists, denylists, sanctions, jurisdictions, identity registries) belongs to
`safeguard-policy`; *evidence* (history, investigation, reporting) belongs to
`safeguard-audit`. The hooks contract only evaluates whether a state-changing
operation on a bound token may proceed, and reverts the operation when it may not.

## Enforcement model

```
Confidential Token operation
          │
          ▼
   Hook invocation (token passes its own address)
          │
          ▼
   Binding check ── token bound? ── NO ──▶ REVERT
          │ YES
          ▼
   Per-party compliance gates (freeze → policy → SAC)
          │
          ▼
   ALLOW (operation continues atomically) / REVERT
```

The enforcement layer is **fail-closed**:

> If the policy cannot be evaluated, authorization fails, configuration is
> invalid, or a required compliance check errors, the transaction reverts.

A rejected operation is an atomic no-op: **rejected operation = no state
transition**. Enforcement reverts before the token applies any state change, so
there is never a partially-written balance paired with a compliance rejection.

This is a **developer-preview** stack. Confidential Tokens on Stellar are a
developer preview available on Testnet; do not treat this repository as
production financial infrastructure.

## Repository layout

```text
contracts/
  compliance-hooks/    Soroban enforcement contract — all six hooks + freeze ops
  compliance-hooks/tests/  security, invariant, and property suites
  sample-policy/       Demo implementation of the safeguard-policy wire contract
cli/                   Operator CLI (init/configure/bind/unbind/freeze/unfreeze/show/errors/deploy)
scripts/
  integration-local.sh Live-ledger integration against the containerized local network
  check-schema.sh      Validates schemas + fixtures/examples/deployments
crates/
  hook-core/           Environment-free domain model (operations, parties, decisions, reasons)
  policy-client/       Typed fail-closed bridge to the safeguard-policy contract
  authorization/       Admin + token enforcement-scope authority gates
  compliance/          Gate-ordering pipeline: freeze → policy → SAC (short-circuiting)
  storage/             Contract state keys (config, bindings, freeze, admin, versions)
  events/              State-transition contract events (audit bridge)
schemas/               Eight JSON Schemas for the wire surfaces (checked in CI)
fixtures/              Schema-validated policies, accounts, tokens, operation requests
interfaces/            Canonical protocol references: hooks, policy wire, events
examples/              Nine ready-to-adapt deployment configurations
deployments/           Per-environment configuration templates (local + testnet)
docs/                  Architecture, model, ops, and testing documentation
tests/ …               Coverage lives in the crate unit tests and the contract suites (docs/testing.md)
```

**Layout notes.** The module tree of `contracts/compliance-hooks` (hooks,
authorization, policy client, compliance engine, storage, events, types)
and the CLI's command modules live as the `crates/` library crates and
`cli/src/` files — the contract and CLI binaries stay thin entry points over
that shared logic (`docs/architecture.md` maps each spec module to its
home). The role of a separate `policy-adapter` contract is filled by
`crates/policy-client` plus the `sample-policy` demo; the enforcement
deployment keeps one `configuration.json` per environment rather than
splitting ids across `contracts.json`/`policy.json`
(`deployments/README.md`).

## Status: Phases 1–4 complete, spec surface closed

Phase 1 (the foundation), Phase 2, the Phase 3 hardening suites, and
Phase 4 are implemented, tested, and pushed: the six supporting crates and the
deployable `compliance-hooks` contract with hook enforcement for all six
confidential-token operations (`register`, `deposit`, `transfer`,
`transfer_from`, `merge`, `withdraw`), admin-gated freeze/unfreeze with
events for the audit bridge, SAC passthrough, and multi-token binding.
The Phase 3 hardening adds an explicit threat-model security suite, an
invariant suite (read-only enforcement, frozen-until-unfrozen, exhaustive
oracle parity, out-of-scope never allows), and a deterministic
random-sequence property suite that drives thousands of admin/hook
interleavings against an enforcement oracle. The contract compiles to
WebAssembly (`wasm32v1-none`) and 146 tests pass across the workspace.

The enforcement lifecycle is additionally proven against a **real Soroban
ledger**: `scripts/integration-local.sh` deploys the contract on the
containerized local network (`stellar container start local`), walks the
full admin lifecycle with real signed transactions, and asserts every
revert code (`docs/deployment.md`, `docs/testnet.md`); the same flow runs
in CI (`.github/workflows/integration.yml`). The `safeguard-hooks`
operator CLI (`docs/cli.md`) inspects and configures the on-chain layer
through the stellar CLI, decoding revers into the stable rejection names.

Phase 4 is complete within this repository's scope. Delivered:
**configuration versioning and state-transition events** (every real
`set_config` bumps a monotonic `config_version` and emits
`ComplianceConfigChanged`; `bind_token` / `unbind_token` emit
`TokenBound` / `TokenUnbound` only on actual binding changes — verified
live), **deployment tooling** (`safeguard-hooks deploy`: one-command
bring-up from the deployment config that deploys the hooks contract and
an optional policy, runs the full lifecycle, binds every configured
token, and records the fresh ids back with `--save`), and **performance
guarantees** (the evaluator short-circuits — cheap local gates run before
cross-contract calls and the chain stops at the first failing party —
proven by counting-policy tests; see `docs/performance.md`). The
remaining Phase 4 item, advanced policy integration, is closed as a
documented *boundary*: richer policy logic (sanctions, jurisdictions,
rule versions, multi-policy routing) belongs to `safeguard-policy` behind
the single `is_authorized` seam the enforcement layer consumes.

## Building and testing

```bash
cargo build                 # native (host test) build
cargo test --workspace      # full unit + contract test suite
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

Contracts compile to WebAssembly for deployment (the `wasm32v1-none`
target is pinned in `rust-toolchain.toml`):

```bash
cargo build --target wasm32v1-none --release -p compliance-hooks -p sample-policy
```

A live-ledger rehearsal (Docker + stellar CLI ≥ 28 required) runs the
entire deployment and enforcement flow with assertions on every revert
code:

```bash
scripts/integration-local.sh
```

## Phase roadmap

| Phase | Scope | Status |
| ----- | ----- | ------ |
| 1 | `hook-core`, `policy-client`, `authorization`, `compliance`, `storage`, `events`; register / deposit / transfer / withdraw hook enforcement | ✅ done |
| 2 | Delegated transfers, freeze administration with events, SAC passthrough, multi-token binding | ✅ done |
| 3 | Security hardening, invariants, fuzzing, live-ledger integration, operator CLI | ✅ done |
| 4 | Advanced policy integration, policy versioning, deployment tooling, performance | ✅ done (advanced policy integration closed as a documented `safeguard-policy` boundary) |

## Documentation

* `docs/architecture.md` — DEFINE → ENFORCE → VERIFY and this repo's shape
* `docs/enforcement-model.md` — when an operation is allowed or reverted
* `docs/hook-lifecycle.md` / `docs/compliance-engine.md` — the evaluation path and pipeline
* `docs/freezing.md` / `docs/sac-passthrough.md` / `docs/delegated-transfers.md` / `docs/multi-token.md` — the enforcement features
* `docs/policy-integration.md` — the `is_authorized` seam with `safeguard-policy`
* `docs/authorization.md` — the caller model and authority boundaries
* `docs/errors.md` — rejection reason codes and their mapping
* `docs/events.md` — the state-transition audit bridge
* `docs/privacy.md` — what the enforcement layer can and cannot observe
* `docs/storage.md` — the small, auditable state surface
* `docs/security.md` / `docs/threat-model.md` / `SECURITY.md` — posture and threat controls
* `docs/performance.md` — enforcement cost model, short-circuit guarantees, and the policy-integration boundary
* `docs/deployment.md` / `docs/testnet.md` / `docs/cli.md` / `docs/integration.md` — deploy and operate on a real ledger
* `docs/testing.md` / `CONTRIBUTING.md` — test matrix and contribution guide

## License

MIT
