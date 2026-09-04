# Contributing

Thanks for contributing to Safeguard Hooks, the ENFORCE layer of the
Safeguard compliance stack. The guidance here keeps contributions small,
reviewable, and aligned with the architecture.

## Architecture first

Read `docs/architecture.md` before writing code. The hard boundary:

* **`safeguard-policy` decides what is allowed** (rules, registries,
  jurisdictions). This repository must never grow a second policy engine.
* **`safeguard-hooks` makes the operation obey the decision** (this repo).
* **`safeguard-audit` records what happened** (the VERIFY polyrepo). This
  repository emits events for it and never stores its history.

## What belongs where

| You want to… | Work in |
| ------------ | ------- |
| Add a gate or change gate order | `crates/compliance` + `docs/compliance-engine.md` + `docs/performance.md` (the short-circuit cost table) |
| Add a rejection reason | `crates/hook-core/src/reason.rs`, the contract error enum, `schemas/rejection.schema.json`, `docs/errors.md` — together (they mirror each other) |
| Add an event | `crates/events`, `schemas/compliance-event.schema.json`, `interfaces/events/events.md` — together |
| Change the policy seam | `interfaces/policy/policy.md` and both sides' code; this is a cross-repo protocol change |
| Add a hook operation | `crates/hook-core` (Operation), the evaluator, the contract entry point, `interfaces/hooks/hooks.md`, `schemas/policy-request.schema.json` — together |

A protocol-level change (new operation, new reason, new event) must update
the code, the schema, and the interface reference in the same change.

## Definition of done

Every contribution must pass, locally and in CI:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
bash scripts/check-schema.sh
```

Suites that protect against the mistakes most worth catching:
`tests/invariants.rs` (state drift, read-only enforcement),
`tests/fuzz.rs` (randomized gate-order regressions), and
`tests/security.rs` (bypasses). If your change touches enforcement
behavior, extend the relevant suite rather than only the happy-path unit
test.

## Commit conventions

* One logical improvement per commit; no filler commits.
* Write commit messages explaining the *what* and the *why*, not just the
  change.
* Keep the working tree clean before pushing.

## Reporting issues

* **Bugs and security issues:** `SECURITY.md` (private report for
  vulnerabilities).
* **Features and questions:** open an issue; the templates in
  `.github/ISSUE_TEMPLATE/` cover hook work, policy integration, security,
  testing, and documentation.
