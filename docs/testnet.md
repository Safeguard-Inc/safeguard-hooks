# Testnet

This repository sits at the **ENFORCE** layer of the Safeguard stack for
Stellar Confidential Tokens. Confidential Tokens are a Stellar **developer
preview available on Testnet** — treat every deployment here as
experimental, not production financial infrastructure.

Testnet integration has two halves:

1. **This repo's half** — deploy and operate `compliance-hooks` on Testnet
   (this page). The full lifecycle is now proven against a *real* Soroban
   ledger via the containerized local network, so the Testnet run is the
   same verified command set against a different network.
2. **The token half** — deploy a confidential token whose compliance-hook
   address points at the hooks contract. That lives in the confidential
   token repository (the OpenZeppelin `stellar-contracts` confidential-token
   stack); this repo never holds balances or proofs.

## Rehearse locally first

`scripts/integration-local.sh` deploys the hooks contract, walks the whole
admin lifecycle, and asserts every enforcement revert code against the
containerized local network — with real transactions and real signatures,
but no credentials. Run it once before touching Testnet:

```bash
scripts/integration-local.sh          # needs Docker + stellar CLI ≥ 28
```

## Testnet runbook

Follow `docs/deployment.md` for the full command reference; the Testnet
specifics are:

1. **Register the network** (once per machine):

   ```bash
   stellar network add testnet \
     --rpc-url https://soroban-testnet.stellar.org \
     --network-passphrase "Test SDF Network ; September 2015"
   ```

2. **Create and fund the admin identity** (friendbot funds it):

   ```bash
   stellar keys generate admin
   stellar keys fund admin --network testnet
   ```

3. **Build and deploy**, replacing `--network local` with `--network testnet`
   in every command of `docs/deployment.md`. Record the returned contract id
   (`C…`); a token later points its compliance-hook address at it.

4. **Verify the wiring on-ledger**, mirroring the local assertions:

   ```bash
   stellar contract invoke --id "$HOOKS" --source admin --network testnet \
     -- initialized                                # true
   stellar contract invoke --id "$HOOKS" --source admin --network testnet \
     -- token_is_bound --token "C…TOKEN…"          # true after bind
   # A compliant flow returns null (allowed); a frozen/blocked party reverts:
   #   Error(Contract, #4)  AccountFrozen
   #   Error(Contract, #3)  PolicyDenied
   #   Error(Contract, #2)  UnboundToken
   ```

## What the local rehearsal already proves

The containerized run (CI: `.github/workflows/integration.yml`) proves the
deployment surface end to end on a real ledger: deploy → initialize →
`set_config` → `bind_token`; compliant operations allowed; freeze reverts
every frozen-party operation with `#4`; unfreeze emits the decoded
`AccountUnfrozen` event and restores access; policy rotation to a deny-list
reverts with `#3`; unbound tokens revert with `#2` before any gate. The only
differences on Testnet are the RPC endpoint, passphrase, and having funded
accounts.

## Developer-preview caveats

* Confidential Tokens are in developer preview; protocol behavior and the
  token-side integration can change.
* The hooks contract makes cross-contract calls to the configured policy
  and (optionally) SAC. On Testnet, deploy and pin those addresses as part
  of the same release; a moved policy is a fail-closed outage, not a
  compliance hole.
* Never store admin secret keys in this repository or in CI logs.
