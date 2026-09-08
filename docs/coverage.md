# Coverage

## Guarantee

Overall line coverage of the Rust workspace is **≥ 80%**, enforced by the
`coverage` CI job (`.github/workflows/ci.yml`) via
[`scripts/coverage.sh`](../scripts/coverage.sh). The gate fails the build if
the TOTAL line-cover of `cargo llvm-cov --workspace --summary-only` drops
below 80%.

Measured on `main` (error-code audit, September 2026): **92.9%** line
coverage overall — the contract (`compliance-hooks`), every workspace crate,
and the CLI are all individually above the threshold. The completeness audit
removed dead error codes and pinned the live ones, so every contract denial
path is exercised.

## How to run

```bash
rustup component add llvm-tools-preview   # one-time
bash scripts/coverage.sh                  # prints the table and enforces 80%
bash scripts/coverage.sh 90               # raise the bar locally
```

The script installs `cargo-llvm-cov` on first use. CI uses a prebuilt binary
(`taiki-e/install-action`) so the gate stays fast.

## Reading the numbers

Line coverage is the primary metric; the gate keys off the TOTAL row's
line-cover column. Region and branch numbers are informational. Coverage is
measured on the full workspace including the contract's test suite and the
CLI's end-to-end tests, so a regression in any crate — including a gate that
stops being exercised — fails CI before it reaches review.

To see per-module gaps:

```bash
cargo llvm-cov --workspace --summary-only | sort -t'%' -k1
```