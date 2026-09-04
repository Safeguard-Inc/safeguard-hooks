# Deployment and operation

How to deploy and operate the enforcement contract on any Soroban network.
The exact command shapes below were verified end to end against the
containerized local network (see `docs/testnet.md` for the testnet
runbook; `scripts/integration-local.sh` automates the local flow).

## Prerequisites

* **stellar CLI ≥ 28** on `PATH`.
* A funded account whose secret key the operator controls — the contract's
  **admin**. Never check the secret into this repository; the commands below
  sign with a stellar CLI identity (or pass `--source` a secret key from an
  environment variable).
* A built `compliance_hooks.wasm`:

  ```bash
  cargo build --target wasm32v1-none --release -p compliance-hooks -p sample-policy
  ```

## Deployment topology

The enforcement layer is *consulted by* confidential tokens; it holds no
balances. A deployment has three pieces:

```text
safeguard-policy (or sample-policy for demos)   ← decides eligibility
        ▲ policy address in config
compliance-hooks                                 ← enforces (this repo)
        ▲ compliance hook address on the token(s)
confidential token(s)                            ← hold balances, call before_*
```

One `compliance-hooks` deployment can serve many tokens; each token is bound
separately (`bind_token`) and one policy can serve all of them.

## CLI conventions (verified on stellar-cli 28)

* Function arguments are flags after the function name:
  `stellar contract invoke --id <id> --source <src> --network <net> -- <fn> --<param> <value>`.
* **Plain `Address`** parameters take a bare address string (`G…`/`C…`).
* **`Option<Address>`** parameters take **JSON**: `"C…"` for `Some`, `null`
  for `None`. (Addresses are complex XDR values when wrapped.)
* **`bool`** parameters take `true`/`false`.
* Contract constructors take their arguments after `--` on `contract deploy`.
* A denial reverts the call; the CLI reports `Error(Contract, #N)` where `N`
  is the code mapped in `docs/errors.md` (`#2` UnboundToken, `#3`
  PolicyDenied, `#4` AccountFrozen, …).

## Deploy

```bash
# Upload + instantiate the hooks contract (admin signs).
stellar contract deploy --wasm target/wasm32v1-none/release/compliance_hooks.wasm \
  --source admin --network testnet
# → C… (the hooks contract id — record it as HOOKS)

# Optional demo/allowlist policy standing in for safeguard-policy.
stellar contract deploy --wasm target/wasm32v1-none/release/sample_policy.wasm \
  --source admin --network testnet                 # allow-all
# or with a deny-list target:
stellar contract deploy --wasm target/wasm32v1-none/release/sample_policy.wasm \
  --source admin --network testnet -- --blocked '"G…BLOCKED_ACCOUNT…"'
# → C… (record as POLICY)
```

## Operate

The lifecycle is one-way: **initialize → set_config → bind_token**, then
per-account freeze administration. Enforcement cannot be switched off once
configured (see `docs/enforcement-model.md`).

```bash
HOOKS=C…
POLICY=C…
ADMIN=$(stellar keys address admin)     # the stored admin public key

# 1. One-shot initialization (fails if called twice — no admin rotation via re-init).
stellar contract invoke --id "$HOOKS" --source admin --network testnet \
  -- initialize --admin "$ADMIN"

# 2. Turn enforcement on. policy: "C…" or null; sac_passthrough: true/false.
stellar contract invoke --id "$HOOKS" --source admin --network testnet \
  -- set_config --policy "\"$POLICY\"" --sac_passthrough false

# 3. Admit a token into enforcement scope. sac: the token's underlying SAC
#    contract id, or null when the token has none / passthrough is off.
stellar contract invoke --id "$HOOKS" --source admin --network testnet \
  -- bind_token --token "C…TOKEN…" --sac null
stellar contract invoke --id "$HOOKS" --source admin --network testnet \
  -- token_is_bound --token "C…TOKEN…"   # → true

# 4. Freeze / unfreeze (admin). A frozen account cannot send, receive,
#    deposit, or withdraw on that token — its operations revert with #4.
stellar contract invoke --id "$HOOKS" --source admin --network testnet \
  -- freeze --token "C…TOKEN…" --account "G…ACCOUNT…"
stellar contract invoke --id "$HOOKS" --source admin --network testnet \
  -- is_frozen --token "C…TOKEN…" --account "G…ACCOUNT…"   # → true
stellar contract invoke --id "$HOOKS" --source admin --network testnet \
  -- unfreeze --token "C…TOKEN…" --account "G…ACCOUNT…"
```

## Reading state

```bash
stellar contract invoke --id "$HOOKS" --source admin --network testnet \
  -- initialized                      # true once initialize ran
stellar contract invoke --id "$HOOKS" --source admin --network testnet \
  -- config                           # {"policy": "C…", "sac_passthrough": false}
```

`config` returns `null` until `set_config` runs — hooks fail closed with
`#9` (InvalidConfiguration) until then.

## What the admin can and cannot do

The admin key operates this contract's *own* state only: configuration,
bindings, and freeze flags. It cannot move funds, mint, or bypass the policy
— and a frozen or policy-blocked account cannot be helped by any
configuration the admin writes (see the invariants in `docs/security.md`).

## Automating

* **One-command bring-up (CLI).** Once the wasm artifacts are built,
  `safeguard-hooks deploy --hooks-wasm <path> [--sample-policy-wasm <path>] [--save]`
  (from `deployments/<env>/configuration.json`) deploys the hooks contract,
  optionally deploys/reuses a policy, and runs `initialize` → `set_config` →
  `bind_token` for every configured token; `--save` records the freshly
  minted ids back into the config (`docs/cli.md`).
* **Live-ledger rehearsal (script).** `scripts/integration-local.sh` runs
  the entire lifecycle against the containerized local network with
  assertions on every revert code — a zero-credential rehearsal of the
  testnet flow, and the same commands with `--network testnet` once
  accounts are funded there.
