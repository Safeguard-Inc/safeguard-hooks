# Deployments

Per-environment reference for the enforcement deployment. The actual
contract ids are minted by `stellar contract deploy` per run and must never
be hard-coded into code; keep them in this directory (or in the CI
workflow's environment) so a deployment is reproducible from a record.

Layout:

```text
deployments/
  local/     → produced by scripts/integration-local.sh on a containerized network
  testnet/   → from the docs/testnet.md runbook
```

Each environment holds a `configuration.example.json` template (copy it to
`configuration.json` once ids exist); the actual `configuration.json` is a
per-environment record, never committed with real admin secrets.

> The spec structure once imagined `contracts.json`/`policy.json` beside
> `configuration.json`. The enforcement deployment is a single wiring record
> — the CLI's `Config` parses exactly one file per environment — so all ids
> and flags live in `configuration.json`; splitting them across three files
> would only let them drift.

## Shape

`configuration.json` records the on-chain wiring that the admin commands in
`docs/deployment.md` produce:

```json
{
  "network": "testnet",
  "rpc_url": "https://soroban-testnet.stellar.org",
  "network_passphrase": "Test SDF Network ; September 2015",
  "hooks_contract_id": "C…",
  "policy": {
    "contract_id": "C…",
    "note": "sample-policy demo, or the safeguard-policy deployment for production"
  },
  "sac_passthrough": false,
  "admin": {
    "public_key": "G…",
    "secret_key_env": "SAFEGUARD_ADMIN_SK"
  },
  "tokens": [
    {
      "contract_id": "C…",
      "sac_contract_id": null,
      "frozen_accounts": []
    }
  ]
}
```

* `admin.secret_key_env` names the environment variable holding the admin
  secret key. The operator (or CI) exports it when running the commands;
  the file itself never contains a secret.
* `tokens[].sac_contract_id` is `null` when the token wraps no SAC or SAC
  passthrough is off for the deployment.
* `tokens[].frozen_accounts` is the freeze ledger; freezing happens through
  the admin commands, and the entries here should mirror on-chain state.

## Local

`scripts/integration-local.sh` prints the fresh `local` contract ids at the
end of each run; record them under `local/` if you want to keep the
instance's state across container restarts. The container network is
ephemeral — every `stellar container start local` starts a fresh ledger, so
local ids are for rehearsal only.

## Testnet

Follow `docs/testnet.md` to produce a real `testnet/configuration.json`.
Keep that file out of public CI output if it ever carries real addresses
under embargo; the ids themselves are public ledger data once deployed.
