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
  compliance-hooks/    Soroban enforcement contract — all six hooks + freeze ops — ✅ phases 1–2
crates/
  hook-core/           Environment-free domain model (operations, parties, decisions) — ✅
  policy-client/       Typed fail-closed bridge to the safeguard-policy contract — ✅
  authorization/       Admin + token enforcement-scope authority gates — ✅
  compliance/          Gate-ordering pipeline: freeze → policy → SAC — ✅
  storage/             Contract state keys and persistence helpers — ✅
  events/              Structured contract events (audit bridge) — ✅
interfaces/            Trait/interface definitions shared across the Safeguard repos
schemas/               JSON schemas for configs, requests, decisions
fixtures/              Sample policies, accounts, tokens, operations
tests/                 Unit, hook, policy, freezing, sac, security, invariant tests
docs/                  Architecture and operational documentation — ✅ core set
audit/ cli/ …          Follow-on batches (Phase 2–4)
```

## Status: Phases 1–2 complete

Phase 1 (the foundation) and Phase 2 are implemented, tested, and pushed:
the six supporting crates and the deployable `compliance-hooks` contract
with hook enforcement for all six confidential-token operations
(`register`, `deposit`, `transfer`, `transfer_from`, `merge`, `withdraw`),
admin-gated freeze/unfreeze with events for the audit bridge, SAC
passthrough, and multi-token binding. The contract compiles to WebAssembly
(`wasm32v1-none`) and 90 unit tests pass across the workspace.

Phase 3 (security hardening, invariants, fuzzing, testnet integration,
CLI) and Phase 4 follow as separate batches.

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
cargo build --target wasm32v1-none --release -p compliance-hooks
```

## Phase roadmap

| Phase | Scope | Status |
| ----- | ----- | ------ |
| 1 | `hook-core`, `policy-client`, `authorization`, `compliance`, `storage`, `events`; register / deposit / transfer / withdraw hook enforcement | ✅ done |
| 2 | Delegated transfers, freeze administration with events, SAC passthrough, multi-token binding | ✅ done |
| 3 | Security hardening, invariant tests, fuzzing, testnet integration, CLI | next |
| 4 | Advanced policy integration, policy versioning, deployment tooling, performance | |

## Documentation

* `docs/architecture.md` — DEFINE → ENFORCE → VERIFY and this repo's shape
* `docs/enforcement-model.md` — when an operation is allowed or reverted
* `docs/authorization.md` — the caller model and authority boundaries
* `docs/errors.md` — rejection reason codes and their mapping
* `docs/privacy.md` — what the enforcement layer can and cannot observe
* `docs/storage.md` — the small, auditable state surface
* `docs/security.md` / `docs/threat-model.md` — posture and threat controls

## License

MIT
