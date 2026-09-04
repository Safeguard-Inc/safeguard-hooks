# Operator CLI (`safeguard-hooks`)

A thin, checked operator surface over the on-chain compliance-hooks
contract. It inspects and configures the enforcement layer — it never
duplicates it: every ledger operation is executed by the stellar CLI (≥ 28)
through the same verified commands documented in `docs/deployment.md`, and
all policy, freeze, and binding state stays on the contract.

```bash
cargo build -p safeguard-hooks
```

## Configuration

Every command (except the offline `errors` reference) reads the deployment
configuration described in `deployments/README.md`:

```bash
safeguard-hooks --config deployments/local/configuration.json show
# or: export SAFEGUARD_CONFIG=deployments/testnet/configuration.json
```

The network is registered in the stellar CLI config automatically when the
file's `rpc_url`/`network_passphrase` describe a network the CLI does not
know yet.

Admin operations sign with a stellar CLI **source** — an identity name, a
secret key, or a seed phrase — resolved in this order: `--source`, the
config's `admin.stellar_identity`, or the secret in the env var named by
`admin.secret_key_env`. Secrets never live in the config file or in this
tool's state.

## Commands

| Command | What it does | Signs |
| ------- | ------------ | ----- |
| `deploy --hooks-wasm <path> [--sample-policy-wasm <path>] [--policy-blocked <G…>] [--policy-id <id>] [--no-policy] [--save]` | One-command bring-up: deploy the hooks contract (and optionally a sample policy), then `initialize` → `set_config` → bind every configured token. `--save` records the fresh ids in the config | admin |
| `init` | Runs the one-shot `initialize(admin)`; reverts `#12` if already done | admin |
| `configure --policy <id>\|--no-policy [--sac-passthrough <bool>]` | Writes the compliance configuration (policy gate + SAC flag) | admin |
| `bind --token <alias\|id> [--sac <id>]` | Admits a token into enforcement scope | admin |
| `unbind --token <alias\|id>` | Removes a token from scope | admin |
| `freeze --token <alias\|id> --account <G…>` | Freezes the account on the token | admin |
| `unfreeze --token <alias\|id> --account <G…>` | Unfreezes the account on the token | admin |
| `show [--token <alias\|id>] [--account <G…>]` | Reads initialization, config, bindings, and freeze flags (simulated reads) | — |
| `errors [code]` | Lists or decodes the rejection codes (`docs/errors.md`) — offline | — |

`--token` accepts an alias from the config's `tokens` list or a bare
`C…`/`G…` address.

## Behavior worth knowing

* **Rejections are decoded, not echoed.** A denied operation reverts the
  transaction; the CLI turns `Error(Contract, #N)` into the stable reason
  name from `safeguard-hook-core` (e.g. `#4 account_frozen`), pointing at
  `docs/errors.md` for remediation.
* **Reads are simulations.** `show` never sends a transaction; stellar CLI
  simulates read-only calls and the CLI prints the value.
* **Token resolution is local.** An unknown alias fails before any ledger
  round-trip, so typos are caught instantly.
* **Double-initialization is impossible to paper over.** Running `init`
  twice reports `#12 already_initialized`, the contract's own guard.

## Examples

```bash
# Bring a fresh deployment up from the deployments config (deployment
# tooling) and record the minted ids back into it:
safeguard-hooks deploy \
  --hooks-wasm target/wasm32v1-none/release/compliance_hooks.wasm \
  --sample-policy-wasm target/wasm32v1-none/release/sample_policy.wasm \
  --policy-blocked "$G_BLOCKED" --save

# Then operate it:
safeguard-hooks show                              # what is configured?
safeguard-hooks configure --policy "$POLICY"      # point at a new policy
safeguard-hooks bind --token usd                  # admit the usd token
safeguard-hooks freeze --token usd --account "$G" # freeze an account
safeguard-hooks show --token usd --account "$G"   # bound? frozen?
safeguard-hooks unfreeze --token usd --account "$G"
```

`deploy` policy resolution: `--policy-id` reuses a deployed policy,
`--sample-policy-wasm` deploys a fresh one (denying `--policy-blocked` when
given), `--no-policy` disables the gate, and with none of those the config's
recorded policy is reused.

## Boundary

This CLI performs no policy evaluation, keeps no balances, and holds no
compliance state of its own — it issues the same contract calls a token or
an operator would, with checked argument shapes, clear error decoding, and
token aliases from the deployment record. See `docs/authorization.md` for
the authority model behind the admin-gated entry points it drives.
