# Testing

How the enforcement layer is verified, and how to run the suites.

## Test matrix

| Area | Where | How |
| ---- | ----- | --- |
| Hook unit tests | `contracts/compliance-hooks` unit tests | every `before_*` gate path, exact error codes |
| Crate unit tests | each crate's `#[cfg(test)]` modules | decisions, storage, events, reason codes, gate ordering |
| Authorization | `contracts/compliance-hooks` + `crates/authorization` | admin gate, double-init, freeze/bind scope gates |
| Policy integration | mock deny-list/allow-all policies across suites | `is_authorized` consumption, `PolicyDenied`, `PolicyUnavailable` |
| SAC passthrough | `crates/compliance` + contract tests | authorized/denied/unreachable SAC |
| Freeze enforcement | frozen sender / recipient / spender cases | `AccountFrozen` on every op |
| Delegated transfers | `before_transfer_from` tests | spender policy-only, blocked spender, frozen owner |
| Multi-token isolation | contract tests + invariants | same policy across tokens; per-token freeze |
| Failure atomicity | invariant suite | rejected op = no state change |
| Security suite | `tests/security.rs` | token spoofing, bypass, cross-token contamination, config attacks |
| Invariant suite | `tests/invariants.rs` | read-only evaluation, frozen-until-unfrozen, oracle parity, out-of-scope never allows |
| Property suite | `tests/fuzz.rs` | seeded random admin/hook sequences vs an enforcement oracle |
| Live-ledger integration | `scripts/integration-local.sh` (CI: `.github/workflows/integration.yml`) | deploy + full lifecycle + revert codes on a real Soroban ledger |
| Schema/fixture validation | `scripts/check-schema.sh` (CI) | every fixture/example/deployment record against `schemas/` |

## Running everything

```bash
cargo test --workspace        # all unit + contract suites
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
python3 scripts/check_schemas.py            # or: bash scripts/check-schema.sh
```

Contract wasm (needed for the live-ledger flow):

```bash
cargo build --target wasm32v1-none --release -p compliance-hooks -p sample-policy
```

Live-ledger rehearsal (Docker + stellar CLI ≥ 28):

```bash
scripts/integration-local.sh
```

## Determinism

* The property suite is seeded and deterministic — three seeds, 600 steps
  each — and asserts oracle parity after *every* step, so a regression in
  gate order or state drift fails loudly rather than probabilistically.
* Tests assert exact error codes and exact events (`to_xdr`), never prose,
  so the mapping between reasons, contract errors, and event payloads is
  pinned by the suite itself.

## Coverage conventions

Every rejection reason has at least one test asserting its exact code; every
event has an exact-payload test; every operation × party combination appears
in the exhaustive matrix inside the invariant suite. When you add a gate or
a state write, the suites that will catch a mistake are the invariant and
property suites (state drift) and the security suite (bypass).
