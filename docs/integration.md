# Integration

How a confidential token (or any token contract) opts into enforcement, and
how a deployment wires the pieces together.

## For a token: invoke before you change state

1. **Deploy or reference the hooks contract** and record its id.
2. **Before every state-changing operation**, call the matching hook with
   your own address as `token`:
   `before_register` / `before_deposit` / `before_merge` /
   `before_transfer` / `before_transfer_from` / `before_withdraw`
   (`interfaces/hooks/hooks.md`).
3. **Treat a failed call as a failed operation.** Use a plain (non-`try`)
   nested call so the hook's revert reverts your transaction. Never catch
   and continue: that would bypass enforcement.
4. Keep your own model where it belongs — party signatures, balances,
   allowances, commitments, proofs stay at the token. The hook screens
   parties; it never sees amounts (`docs/hook-lifecycle.md`,
   `docs/privacy.md`).

## For a deployment: the admin lifecycle

Order matters — the contract is fail-closed until configured and bound:

```text
initialize(admin)
   └─ set_config(policy, sac_passthrough)   # enforcement turns on
         └─ bind_token(token, sac)          # per token, admin-gated
               └─ freeze/unfreeze           # optional circuit breakers
```

The operator CLI (`docs/cli.md`) and `safeguard-hooks deploy --save`
(`docs/deployment.md`) drive this lifecycle; `scripts/integration-local.sh`
runs the whole flow against a containerized local ledger and asserts every
revert code.

## Reference wiring

* **Policy:** implement `is_authorized(account, token) -> bool`
  (`interfaces/policy/policy.md`), deploy it, and pass its id to
  `set_config`. `contracts/sample-policy` is a working demo.
* **SAC passthrough:** optional; bind the token with its SAC address and
  enable the flag (`docs/sac-passthrough.md`).
* **Configs:** one `configuration.json` per environment
  (`deployments/README.md`); nine scenarios to adapt under `examples/`.
* **Testnet:** follow `docs/testnet.md` (developer preview — Confidential
  Tokens on Stellar are testnet-only today, not production infrastructure).

## Compatibility notes

* A token that never invokes hooks simply runs unenforced; enforcement
  applies only to operations routed through the hook surface.
* The contract exposes read-only queries (`token_is_bound`,
  `is_frozen`, `config`, `config_version`) so integrators and tooling can
  check scope and state without transacting (`interfaces/hooks/hooks.md`).
