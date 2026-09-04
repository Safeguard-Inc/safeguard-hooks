# Delegated transfers

`transfer_from` lets an authorized `spender` move value from `from` to `to`
on the owner's behalf. Because a third actor joins the operation, delegated
flows are screened through the full party set — with one deliberate
asymmetry.

## Who is screened how

```text
spender ── policy only (it holds no funds)
from    ── full gate: freeze → policy → SAC
to      ── full gate: freeze → policy → SAC
```

The `spender` is the only party that holds no funds — the value stays the
owner's — so freezing and SAC gates (which protect fund ownership) do not
apply to it. The external policy still screens it: a delegation to a
non-compliant spender fails even when `from` and `to` would pass
(`crates/hook-core/src/party.rs` documents the role model).

## Gate consequences

* **Blocked spender** → `PolicyDenied`. Spenders are policy-gated, so a
  deny-listed or sanctions-blocked spender cannot move value on behalf of
  others.
* **Frozen spender** → allowed by the freeze rule, *but* the owner can
  always stop delegations by freezing `from` (or the destination `to`).
* **Frozen or blocked `from` / `to`** → `AccountFrozen` / `PolicyDenied`,
  exactly as for a direct transfer.
* The spender is screened *first* (canonical party order), so a
  non-compliant spender is rejected before any fund-holder gate runs.

## The token still owns the delegation

Signature and allowance checks — "did the owner actually authorize this
spender for this amount?" — happen at the token, where allowances live. The
enforcement layer screens the *parties*; it does not see amounts and never
re-implements the allowance model (`docs/hook-lifecycle.md`).
