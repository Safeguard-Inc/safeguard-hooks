## What and why

<!-- One or two sentences: the behavior change and the reason for it. -->

## Protocol surface touched?

<!-- If this adds or changes a hook operation, rejection reason, event, or the
policy wire contract, the following must move together in this PR:
interfaces/, schemas/, and the code. Mark which apply. -->

- [ ] Hook entry point / operation
- [ ] Rejection reason (`crates/hook-core`, contract error enum, `schemas/rejection.schema.json`, `docs/errors.md`)
- [ ] Event (`crates/events`, `schemas/compliance-event.schema.json`, `interfaces/events/events.md`)
- [ ] Policy wire contract (`interfaces/policy/policy.md`)

## Definition of done

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] `bash scripts/check-schema.sh`
- [ ] Enforcement behavior change covered by the relevant suite (unit /
  security / invariant / property) rather than only the happy path

## Notes

<!-- Anything reviewers should know: trust-model impact, docs updated,
security considerations. -->
