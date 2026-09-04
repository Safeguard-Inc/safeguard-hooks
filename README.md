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
  compliance-hooks/    Soroban enforcement contract (thin entry surface)
crates/
  hook-core/           Operation/context/decision domain model
  policy-client/       On-chain client for the safeguard-policy contract
  authorization/       Admin authorization primitives
  compliance/          Gate evaluation: freeze, policy, SAC passthrough
  storage/             Contract state keys and persistence helpers
  events/              Structured contract events (audit bridge)
interfaces/            Trait/interface definitions shared across the Safeguard repos
schemas/               JSON schemas for configs, requests, decisions
fixtures/              Sample policies, accounts, tokens, operations
tests/                 Unit, hook, policy, freezing, sac, security, invariant tests
docs/                  Architecture and operational documentation
cli/                   Operator CLI (inspect/configure the on-chain enforcement layer)
```

## Building and testing

```bash
cargo build                 # native (tests) build
cargo test --workspace      # full unit + hook + integration test suite
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
```

Contracts compile to WebAssembly for deployment:

```bash
cargo build --target wasm32-unknown-unknown --release -p safeguard-compliance-hooks
```

## Phase roadmap

| Phase | Scope |
| ----- | ----- |
| 1 | `hook-core`, `policy-client`, `authorization`, `compliance`, `storage`, `events` crates; register / deposit / transfer / withdraw hook enforcement |
| 2 | Delegated transfers, freeze administration, SAC passthrough, multi-token binding |
| 3 | Security hardening, invariant tests, fuzzing, testnet integration, CLI |
| 4 | Advanced policy integration, policy versioning, deployment tooling, performance |

See `docs/architecture.md` and `docs/enforcement-model.md` for the design,
and `docs/security.md` / `docs/threat-model.md` for the security posture.

## License

MIT
