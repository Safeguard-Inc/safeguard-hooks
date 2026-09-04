# Policy wire contract (`is_authorized`)

The single seam between the enforcement layer and the `safeguard-policy`
(DEFINE) polyrepo. The enforcement layer never evaluates rules itself; it
invokes the configured policy contract and enforces its answer.

## Wire function

```text
is_authorized(env, account: Address, token: Address) -> bool
```

* `account` — the party being screened for this operation.
* `token` — the token the operation concerns. Always sent, so one policy
  contract can serve many bound tokens with per-token rules
  (`docs/multi-token.md`).
* Return — `true` authorizes the account for the operation; `false` is a
  denial the enforcement layer surfaces as `PolicyDenied`.

There is no richer request object on the wire: the policy is free to read
whatever deployment state it needs (its own registries, jurisdictions,
sanctions data) from its own storage. The enforcement layer only guarantees
what *it* sends — never amounts or private financial data
(`docs/privacy.md`).

## Failure semantics (fail-closed)

A call that cannot produce a boolean — the policy reverts, is missing, or
returns something unexpected — is **never** treated as an allow. The
fail-closed client (`crates/policy-client`) maps:

| Wire outcome | Enforcement decision |
| ------------ | -------------------- |
| `Ok(true)` | allow |
| `Ok(false)` | deny — `PolicyDenied` |
| policy reverted / unavailable | deny — `PolicyUnavailable` |
| unexpected return | deny — `PolicyUnavailable` (invalid configuration if unrecoverable) |

## Reference implementations

* `contracts/sample-policy` — a minimal documented demo (optionally
  deny-listing one account) used by the local-ledger integration and the
  test suites. It is a stand-in for the DEFINE polyrepo, not a registry.
* Policy *rule-sets* in `fixtures/policies/` document the DEFINE-side
  shapes (allowlist, denylist, sanctions, jurisdiction) that real
  `safeguard-policy` deployments evaluate.
