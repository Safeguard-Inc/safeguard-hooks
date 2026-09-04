# Policy integration

How `safeguard-hooks` (ENFORCE) talks to `safeguard-policy` (DEFINE), and
the boundary that keeps the two polyrepos from re-implementing each other.

## The seam

```text
safeguard-hooks                       safeguard-policy
crates/compliance evaluator
        │
        ▼
crates/policy-client ── is_authorized(account, token) ──▶ policy contract
        ▲                                                     │
        └────────────── Ok(true) / Ok(false) / revert ◀───────┘
```

* **One wire function.** `is_authorized(env, account: Address, token:
  Address) -> bool` is the entire cross-repo protocol
  (`interfaces/policy/policy.md`).
* **One call per screened party.** The evaluator asks once per party per
  operation; allowed paths cost exactly one policy round-trip per party
  (`docs/performance.md`).
* **The token always travels with the account.** One policy contract can
  serve many bound tokens and apply per-token rules by reading the token
  argument (`docs/multi-token.md`).

## Who decides what

| Question | Answered by |
| -------- | ----------- |
| May this caller perform this admin operation? | `safeguard-hooks` (admin authority, `docs/authorization.md`) |
| Is this token in enforcement scope? | `safeguard-hooks` (binding state) |
| Is this account eligible under the rules? | `safeguard-policy` (allowlists, denylists, sanctions, jurisdictions, registries) |
| Is this account frozen here? | `safeguard-hooks` (freeze state) |
| Is this account authorized on the underlying SAC? | the SAC itself, composed when passthrough is on |

The enforcement layer stores none of the policy's rules and holds none of
its registries. It enforces the boolean that comes back.

## Fail-closed translation

An unevaluable policy must not silently pass an operation:

| Wire outcome | Enforcement decision |
| ------------ | -------------------- |
| `Ok(true)` | allow |
| `Ok(false)` | deny — `PolicyDenied` (`Error(Contract, #3)`) |
| policy reverted | deny — `PolicyUnavailable` (`#10`) |
| unexpected return | deny — `PolicyUnavailable` (`#10`) |

## Demo and reference implementations

* `contracts/sample-policy` implements the wire contract for local demos and
  tests (optionally deny-listing one account). It is explicitly a stand-in
  for the DEFINE polyrepo, not a registry.
* `fixtures/policies/` documents the rule-set shapes a real policy
  deployment evaluates (allow-all, allowlist, denylist, sanctions,
  jurisdiction).
* A richer policy surface (rule versions, multi-policy routing, staged
  escalation) belongs in `safeguard-policy`: it may expose any number of
  `is_authorized`-shaped entry points or an internal registry, and the hooks
  contract simply points its `set_config` at the chosen address.
