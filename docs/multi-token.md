# Multi-token

One enforcement contract serving many tokens, with one policy contract able
to serve many of them. Token identity is carried into every decision so a
ruling for one token can never leak into another.

## Bindings

A token enters enforcement scope through an admin-gated `bind_token(token,
sac)` write. Binding state is keyed per token and carries the token's
underlying SAC when it has one (`docs/storage.md`). Unbinding revokes scope
for that token alone.

```text
Token A ── bind ──▶ compliance-hooks ◀── bind ── Token B
                        │
              set_config(policy, …)
                        │
                        ▼
                   policy contract
```

* One policy serves both tokens; the policy receives the token on every
  `is_authorized(account, token)` call, so a single registry can apply
  per-token rules.
* Every binding is admin-authenticated, and unbound tokens are rejected
  before any gate runs (`Error(Contract, #2)`) — the admission control
  behind token-spoofing protection (`docs/security.md`).

## Isolation invariants

* **Freeze state** is keyed by (token, account): freezing Alice on Token A
  never touches Alice on Token B.
* **Policy decisions** carry the token: a policy that blocks Alice on
  Token A can still allow her on Token B.
* **Config and version** are contract-wide (they describe the enforcement
  deployment, not any single token).
* **Unbinding** is per token: revoking scope for Token B leaves Token A
  enforced.

The exhaustive matrix test, the invariant suite, and the randomized
property suite in `contracts/compliance-hooks/tests/` all assert these
isolation properties across the full contract surface; a single-policy,
two-token scenario is in `examples/multi-token-policy/`.
