# Fixtures

Reference data for the enforcement layer and its integration with the
`safeguard-policy` (DEFINE) polyrepo. Every JSON file here is validated by
`scripts/check-schema.sh`: files under `tokens/`, `accounts/`, and
`operations/` are instances of the wire schemas in `schemas/`, while
`policies/` are reference rule-sets for the DEFINE polyrepo and parse as JSON
only.

## Conventions

* **Addresses are placeholders.** The `G…`/`C…` strings below are readable
  stand-ins for real Stellar strkeys (`G` = account, `C` = contract). They
  satisfy the schema address pattern but are not decodable addresses — never
  use them on a ledger.
* **No amounts anywhere.** Hooks and policy requests carry addresses and
  operation names only; that is the privacy boundary (`docs/privacy.md`).
* **`operations/<op>/`** pairs the *request* the enforcement layer sends to a
  policy for that operation's first-named party with the *expected decision*
  the hooks contract would enforce. Denials for accounts (policy-blocked,
  registration-required) live under `accounts/`.

## Directory map

| Directory | Files are instances of |
| --------- | ---------------------- |
| `tokens/` | `token-binding.schema.json` |
| `accounts/` | `freeze-state.schema.json`, `authorization-decision.schema.json` |
| `operations/<op>/request.json` | `policy-request.schema.json` |
| `operations/<op>/expected-decision.json` | `authorization-decision.schema.json` |
| `policies/` | reference rule-sets for `safeguard-policy` (parse-only here) |
