# Security

## Posture

The enforcement layer is fail-closed. Its security properties follow from a
small set of rules that are enforced in code and asserted in tests:

1. **Rejected operation = no state transition.** Every gate failure returns an
   error that reverts the invoking token's operation. There is no gate path
   that returns "allow" when it cannot decide.
2. **No anonymous administration.** Every state-changing entry point is gated
   by the stored admin's signature; re-initialization (which would rotate the
   admin) fails.
3. **No unbound tokens.** Enforcement runs only for bound tokens; an unbound
   token's invocation is rejected before any gate or state access. Binding is
   the admission control that makes token spoofing impossible as a *state*
   attack (see the caller model in `docs/authorization.md` for the boundary of
   what caller checks are possible on Soroban).
4. **Isolation per token.** Freeze and binding state are keyed by token and
   account; one token's compliance state can never contaminate another's.
5. **No private data on hooks or in events.** The surface takes no amounts;
   events carry addresses and booleans only.
6. **Deterministic gate order.** The first failing gate in canonical order is
   reported, so rejection chains are reproducible and testable.

## Trust surface

* **The admin** can bind/unbind tokens, rotate configuration, and (Phase 2)
  freeze/unfreeze accounts. It cannot move funds or mint.
* **The policy contract** (`safeguard-policy`) decides account eligibility.
  It is reached only through the fail-closed client, but a malicious or
  compromised policy is a denial-of-service for the deployments that use it —
  it is part of the deployment's trust surface.
* **The confidential token** is the gatekeeper of its own compliance address
  and holds balances and allowances. It performs the party signature checks.

## Current coverage

Phase 1 ships the gate-level security tests (unbound token, unconfigured
contract, blocked/frozen parties, SAC failures, re-initialization, unauthorized
admin, per-token isolation) across the compliance and contract crates. The
dedicated security suite — token spoofing, cross-token contamination,
configuration attacks, bypass attempts, and the invariant suite — is part of
the Phase 3 hardening roadmap.
