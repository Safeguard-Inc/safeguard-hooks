#!/usr/bin/env bash
# Benchmark per-transaction gas (fee charged, in stroops) for the
# compliance-hooks contract's public functions against a live network.
#
# Usage:
#   bash scripts/bench-gas.sh [network]        # default: testnet
#
# Requires:
#   - stellar CLI (>= 28) on PATH
#   - a deployment record at deployments/<network>/configuration.json
#     (the committed testnet record lists the live ids)
#   - identities in the CLI keychain: admin (funded), alice, bob (their
#     addresses are the screened parties; they need not be funded — admin
#     signs every call). Generate missing ones with:
#       stellar keys generate admin && stellar keys fund admin --network testnet
#       stellar keys generate alice && stellar keys generate bob
#
# Output: one line per function with the fee actually charged for a real
# transaction, in stroops (1 stroop = 1e-7 XLM). Nothing here asserts
# pass/fail — only the cost of executing the function is measured. The
# enforcement gates (before_*) run on the allowed path, so the numbers are
# the worst-case per-operation cost a token holder pays (denied paths are
# cheaper; see docs/performance.md).
#
# Methodology note: the fee charged is the authoritative on-chain cost
# (CPU instructions + ledger footprint + storage rent + tx size). It is the
# number a token holder actually pays per operation. docs/performance.md
# records the measured table and how to read it.

set -euo pipefail

cd "$(dirname "$0")/.."

NETWORK="${1:-testnet}"
RECORD="deployments/$NETWORK/configuration.json"
ADMIN="${STELLAR_ADMIN:-admin}"

[ -f "$RECORD" ] || {
    echo "error: no deployment record at $RECORD" >&2
    exit 1
}

CONTRACT=$(python3 -c "import json; print(json.load(open('$RECORD'))['hooks_contract_id'])")
TOKEN=$(python3 -c "
import json
rec = json.load(open('$RECORD'))
print(next(t['contract_id'] for t in rec['tokens']))
")
ALICE="$(stellar keys address alice 2>/dev/null || true)"
BOB="$(stellar keys address bob 2>/dev/null || true)"
[ -n "$ALICE" ] && [ -n "$BOB" ] || {
    echo "error: identities 'alice' and 'bob' are required (see the header)" >&2
    exit 1
}

invoke() { # fn args... -> prints the fee charged in stroops
    local out fee
    out="$(stellar contract invoke --id "$CONTRACT" --source-account "$ADMIN" \
        --network "$NETWORK" --cost --send=yes -- "$@" 2>&1)" || true
    fee="$(printf '%s' "$out" | grep -oE 'Fee Charged: [0-9]+' | tail -1 | grep -oE '[0-9]+')"
    printf '%s' "${fee:-n/a}"
}

echo "== compliance-hooks gas benchmark ($NETWORK) =="
echo "contract: $CONTRACT   token: $TOKEN   admin: $ADMIN"
printf '%-28s %10s\n' "function" "stroops"

# State reads.
printf '%-28s %10s\n' "initialized" "$(invoke initialized)"
printf '%-28s %10s\n' "config" "$(invoke config)"
printf '%-28s %10s\n' "token_is_bound" "$(invoke token_is_bound --token "$TOKEN")"
printf '%-28s %10s\n' "is_frozen(bob)" "$(invoke is_frozen --token "$TOKEN" --account "$BOB")"

# Enforcement gates on the allowed path (the per-operation cost a token
# holder actually pays).
printf '%-28s %10s\n' "before_register" "$(invoke before_register --token "$TOKEN" --account "$ALICE")"
printf '%-28s %10s\n' "before_deposit" "$(invoke before_deposit --token "$TOKEN" --from "$ALICE" --to "$BOB")"
printf '%-28s %10s\n' "before_transfer" "$(invoke before_transfer --token "$TOKEN" --from "$ALICE" --to "$BOB")"
printf '%-28s %10s\n' "before_withdraw" "$(invoke before_withdraw --token "$TOKEN" --account "$ALICE")"

echo
echo "Values are fee charged per real transaction on $NETWORK in stroops"
echo "(1 XLM = 10,000,000 stroops). Repeat runs vary by a few percent;"
echo "docs/performance.md records the measured table and methodology."