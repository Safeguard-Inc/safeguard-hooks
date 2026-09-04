#!/usr/bin/env bash
#
# End-to-end integration of `compliance-hooks` against a real Soroban ledger.
#
# Brings up the containerized local network (`stellar container start local`),
# deploys `compliance-hooks` and `sample-policy`, walks the full admin
# lifecycle (initialize → set_config → bind_token → freeze/unfreeze), and
# exercises every enforcement gate through real, signed transactions —
# asserting the exact revert codes the unit and integration suites assert
# in the simulator (`Error(Contract, #2)` UnboundToken, `#3` PolicyDenied,
# `#4` AccountFrozen).
#
# This is the local form of the testnet flow in docs/testnet.md: the same
# `stellar contract` commands run against `--network testnet` once accounts
# are funded there.
#
# Requirements: stellar CLI (>= 28) on PATH (override with STELLAR), Docker,
# and the Rust workspace (target/wasm32v1-none installed via
# rust-toolchain.toml). The network image is pulled on first run.
#
# Usage: scripts/integration-local.sh [--no-build] [--keep-network]
#
#   --no-build        skip the wasm build (use existing artifacts)
#   --keep-network    leave the local container running on exit

set -euo pipefail

STELLAR="${STELLAR:-stellar}"
NETWORK="${NETWORK:-local}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOOKS_WASM="$ROOT/target/wasm32v1-none/release/compliance_hooks.wasm"
POLICY_WASM="$ROOT/target/wasm32v1-none/release/sample_policy.wasm"

RPC_URL="${RPC_URL:-http://localhost:8000/rpc}"
FRIENDBOT_URL="${FRIENDBOT_URL:-http://localhost:8000/friendbot}"
PASSPHRASE="${PASSPHRASE:-Standalone Network ; February 2017}"
CONTAINER="${CONTAINER:-stellar-local}"

NO_BUILD=0
KEEP_NETWORK=0
for arg in "$@"; do
  case "$arg" in
    --no-build) NO_BUILD=1 ;;
    --keep-network) KEEP_NETWORK=1 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

say() { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
die() { printf '\033[1;31mfatal:\033[0m %s\n' "$*" >&2; exit 1; }

command -v "$STELLAR" >/dev/null 2>&1 || die "'$STELLAR' not found on PATH (install stellar-cli >= 28)"
command -v docker >/dev/null 2>&1 || die "docker not found on PATH"

# ---------------------------------------------------------------------------
# 1. Build the contracts (unless skipped).
# ---------------------------------------------------------------------------
if [ "$NO_BUILD" -eq 0 ]; then
  say "Building contract wasm"
  cargo build --target wasm32v1-none --release -p compliance-hooks -p sample-policy
fi
[ -f "$HOOKS_WASM" ] || die "missing $HOOKS_WASM (build first)"
[ -f "$POLICY_WASM" ] || die "missing $POLICY_WASM (build first)"

# ---------------------------------------------------------------------------
# 2. Local network: start the container and wait for RPC health.
# ---------------------------------------------------------------------------
say "Starting local network container ($CONTAINER)"
if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
  "$STELLAR" container start local
fi
health=""
for _ in $(seq 1 60); do
  health="$(curl -s -X POST -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"getHealth","params":{}}' \
    "$RPC_URL" 2>/dev/null | grep -o '"status":"healthy"' || true)"
  [ -n "$health" ] && break
  sleep 5
done
[ -n "$health" ] || die "RPC at $RPC_URL did not become healthy"
say "RPC healthy"

if [ "$KEEP_NETWORK" -eq 0 ]; then
  trap '"$STELLAR" container stop local >/dev/null 2>&1 || true' EXIT
fi

# ---------------------------------------------------------------------------
# 3. Register the network and create identities (idempotent).
# ---------------------------------------------------------------------------
if ! "$STELLAR" network ls | grep -qx "$NETWORK"; then
  "$STELLAR" network add "$NETWORK" --rpc-url "$RPC_URL" --network-passphrase "$PASSPHRASE"
fi
for name in admin alice bob token; do
  "$STELLAR" keys generate "$name" >/dev/null 2>&1 || true # exists already → ok
done

fund() { # $1 identity name
  local addr
  addr="$("$STELLAR" keys address "$1")"
  # The friendbot is part of the local container stack. Ignore failure: an
  # already-funded account returns an error and needs no funding.
  curl -s "$FRIENDBOT_URL?addr=$addr" >/dev/null 2>&1 || true
}
for name in admin alice bob token; do fund "$name"; done

ADMIN="$("$STELLAR" keys address admin)"
ALICE="$("$STELLAR" keys address alice)"
BOB="$("$STELLAR" keys address bob)"
TOKEN="$("$STELLAR" keys address token)"

# ---------------------------------------------------------------------------
# 4. Deploy the contracts and capture their ids.
# ---------------------------------------------------------------------------
say "Deploying compliance-hooks"
HOOKS_ID="$("$STELLAR" contract deploy --wasm "$HOOKS_WASM" --source admin --network "$NETWORK" | grep -E '^C[0-9A-Z]{55}$' | head -1)"
[ -n "$HOOKS_ID" ] || die "could not parse deployed hooks contract id"
echo "hooks = $HOOKS_ID"

say "Deploying sample-policy (allow-all)"
POLICY_ID="$("$STELLAR" contract deploy --wasm "$POLICY_WASM" --source admin --network "$NETWORK" | grep -E '^C[0-9A-Z]{55}$' | head -1)"
echo "policy(allow-all) = $POLICY_ID"

# The hooks contract is admin-gated: the admin identity signs every call.
invoke() { # $1 contract id, then fn + --param value pairs
  local id="$1"; shift
  "$STELLAR" contract invoke --id "$id" --source admin --network "$NETWORK" -- "$@"
}
hooks() { invoke "$HOOKS_ID" "$@"; }

# Option<Address> parameters take JSON values ("C..." for Some, null for None).
expect_revert() { # $1 expected contract code, then fn + args
  local want="$1"; shift
  local out
  out="$(hooks "$@" 2>&1 || true)"
  if ! printf '%s' "$out" | grep -q "Error(Contract, #$want)"; then
    printf '%s\n' "$out" >&2
    die "expected revert Error(Contract, #$want) from: $*"
  fi
  echo "reverted Error(Contract, #$want) as expected: $*"
}

# ---------------------------------------------------------------------------
# 5. Lifecycle + enforcement gates.
# ---------------------------------------------------------------------------
say "initialize"
hooks initialize --admin "$ADMIN" >/dev/null
hooks initialized | grep -q true || die "contract did not initialize"

say "set_config(policy = allow-all, sac passthrough off)"
hooks set_config --policy "\"$POLICY_ID\"" --sac_passthrough false >/dev/null

say "bind_token (no SAC)"
hooks bind_token --token "$TOKEN" --sac null >/dev/null
hooks token_is_bound --token "$TOKEN" | grep -q true || die "token not bound"

say "compliant deposit is allowed"
hooks before_deposit --token "$TOKEN" --from "$ALICE" --to "$BOB" >/dev/null \
  || die "compliant deposit was unexpectedly rejected"

say "freeze Bob → his operations revert with AccountFrozen (#4)"
hooks freeze --token "$TOKEN" --account "$BOB" >/dev/null
hooks is_frozen --token "$TOKEN" --account "$BOB" | grep -q true || die "Bob not frozen"
expect_revert 4 before_deposit --token "$TOKEN" --from "$ALICE" --to "$BOB"
expect_revert 4 before_transfer --token "$TOKEN" --from "$BOB" --to "$ALICE"
expect_revert 4 before_withdraw --token "$TOKEN" --account "$BOB"

say "unfreeze restores access"
hooks unfreeze --token "$TOKEN" --account "$BOB" >/dev/null
hooks before_deposit --token "$TOKEN" --from "$ALICE" --to "$BOB" >/dev/null \
  || die "deposit still rejected after unfreeze"

say "policy rotation to a deny-list blocks Bob with PolicyDenied (#3)"
DENY_ID="$("$STELLAR" contract deploy --wasm "$POLICY_WASM" --source admin --network "$NETWORK" -- --blocked "\"$BOB\"" | grep -E '^C[0-9A-Z]{55}$' | head -1)"
hooks set_config --policy "\"$DENY_ID\"" --sac_passthrough false >/dev/null
expect_revert 3 before_deposit --token "$TOKEN" --from "$ALICE" --to "$BOB"
hooks set_config --policy "\"$POLICY_ID\"" --sac_passthrough false >/dev/null
hooks before_deposit --token "$TOKEN" --from "$ALICE" --to "$BOB" >/dev/null \
  || die "deposit still rejected after rotating back to allow-all"

say "an unbound token reverts before any gate with UnboundToken (#2)"
# A bound-address-shaped string that was never admitted by bind_token.
STRANGER="$ADMIN"
expect_revert 2 before_transfer --token "$STRANGER" --from "$ALICE" --to "$BOB"

printf '\n\033[1;32mAll local integration checks passed.\033[0m\n'
echo "compliance-hooks: $HOOKS_ID"
echo "sample-policy (allow-all): $POLICY_ID"
echo "run the same flow against public testnet with docs/testnet.md (same commands, --network testnet)"
