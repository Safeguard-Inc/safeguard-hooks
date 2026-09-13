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

> `initialize` requires the prospective admin's authorization — the call is
> signed by (or sponsored for) the admin key itself. An unsigned `initialize`
> reverts at the host, so a fresh deployment cannot be admin-hijacked by a
> front-runner who observes the deploy transaction. The CLI's `deploy` flow
> transacts with the admin key and satisfies this automatically.

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

## Verify a deployment

`docs/deployment.md` and `deployments/<env>/` describe what *should* be
running; `verify` reports what *is*. It is read-only, needs **no secret
key**, and exits non-zero when any check fails, so it works from a
reviewer's machine, a CI job, or an incident-response shell that holds no
key material:

```bash
safeguard-hooks --config deployments/testnet/configuration.json verify
```

```text
safeguard-hooks verify — read-only, no secret key
network: testnet
hooks contract: C…
source account: G… (simulated, never signs)

  PASS  contract reachable
  PASS  initialized
  PASS  admin matches the config
  PASS  compliance configuration present
        policy gate → C…
  PASS  recorded policy matches the contract
  PASS  config_version
        config_version = 1
  PASS  state_version
        state_version = 1
  PASS  token sandbox-token bound
  PASS  fail-closed probe
        before_transfer on unbound token G… refused with #2 unbound_token
  SKIP  gate sample
        pass --account G… to observe a real enforcement decision

9 passed, 0 failed, 1 skipped
```

What each check is protecting:

* **contract reachable** — the recorded contract id resolves on the recorded
  network. The first read is the probe; if it fails the report stops there
  rather than cascading.
* **initialized** — `initialize` ran, so the admin seat is claimed. An
  uninitialized contract fails closed on every hook (`#9`).
* **admin matches the config** — the on-chain admin equals
  `admin.public_key`. A mismatch means the record is stale.
* **compliance configuration present** — `set_config` ran. Until it has, the
  contract is inert and every hook reverts `#9`.
* **recorded policy matches the contract** — the live `policy` equals the
  config's recorded policy, catching a reconfiguration that never made it
  back into the deployment record.
* **config_version / state_version** — both are ≥ 1, the on-chain anchors
  `safeguard-audit` pairs with events.
* **token <alias> bound** — every configured token really is in enforcement
  scope.
* **fail-closed probe** — the contract refuses an operation on an unbound
  token with `#2 unbound_token`. This is the central safety promise, so it
  is probed directly: the admin address is used as the known-out-of-scope
  target, and the check fails loudly if that address is somehow bound.
* **gate sample** (needs `--account G…`) — simulates a real
  `before_transfer` on every bound token and reports the decision. Being
  *refused* is a healthy result (the gate is live and refusing); being
  *unable to decide* (`#9` invalid configuration, `#10` policy unavailable)
  is a failure, because it means a fail-closed outage.

Nothing here signs or sends: every call goes out as
`--source-account <G…> --send=no`, so the command is safe to run against a
production deployment during an incident.

## Automating

* **One-command bring-up (CLI).** Once the wasm artifacts are built,
  `safeguard-hooks deploy --hooks-wasm <path> [--sample-policy-wasm <path>] [--save]`
  (from `deployments/<env>/configuration.json`) deploys the hooks contract,
  optionally deploys/reuses a policy, and runs `initialize` → `set_config` →
  `bind_token` for every configured token; `--save` records the freshly
  minted ids back into the config (`docs/cli.md`).
* **Post-deployment smoke test (CLI).** `safeguard-hooks verify` answers
  "is the thing I just deployed actually enforcing?" read-only and without a
  key, and exits non-zero when it is not — wire it into your release
  checklist right after `deploy`.
* **Live-ledger rehearsal (script).** `scripts/integration-local.sh` runs
  the entire lifecycle against the containerized local network with
  assertions on every revert code — a zero-credential rehearsal of the
  testnet flow, and the same commands with `--network testnet` once
  accounts are funded there.
