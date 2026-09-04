# Privacy

Confidential Tokens keep balances and transfer amounts private while sender and
recipient addresses remain visible. The enforcement layer is built to preserve
that boundary **by construction**, not by discipline.

## What the enforcement layer never sees

* No `before_*` hook accepts an amount. The hook surface is
  `(token, parties…)` only; there is no parameter to leak a balance, a
  transfer size, a commitment, or a ciphertext.
* The compliance evaluation (`safeguard-compliance`) gates *addresses* on
  *tokens*. Its types contain no value or cryptographic material.
* The policy wire contract (`safeguard-policy-client`) is
  `is_authorized(account, token) → bool`. A policy cannot observe amounts even
  if it wanted to — the request carries only the party and the token.
* Events name addresses, tokens, policies, and booleans. Amounts, balances,
  commitments, and openings never appear. See `crates/events/src/lib.rs`.

## What the enforcement layer does see

It observes which parties interact with which token, in which operation, and
whether they pass the configured gates — the compliance *metadata* of the
system. That is inherent to enforcement: a freeze, an allowlist, or a
sanctions screen must name accounts.

## What that means for deployments

The policy contract is the only component that can impose address-level
restrictions, and it operates on addresses alone. A deployment that genuinely
needs amount context (rate limits keyed on size, for example) must provide its
own mechanism; it cannot extract amounts through this layer. This is a feature:
the enforcement layer's honest answer to "how much did Alice send?" is "it
never asked."
