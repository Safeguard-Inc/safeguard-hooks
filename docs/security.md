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

* **The admin** can bind/unbind tokens, rotate configuration, and
  freeze/unfreeze accounts. It cannot move funds or mint.
* **The policy contract** (`safeguard-policy`) decides account eligibility.
  It is reached only through the fail-closed client, but a malicious or
  compromised policy is a denial-of-service for the deployments that use it —
  it is part of the deployment's trust surface.
* **The confidential token** is the gatekeeper of its own compliance address
  and holds balances and allowances. It performs the party signature checks.

## Current coverage

The gate-level security tests live in the compliance and contract crates
(unbound token, unconfigured contract, blocked/frozen parties including
delegated flows, SAC failures, freeze event integrity, multi-token
isolation). The Phase 3 hardening suites in `contracts/compliance-hooks/tests/`
complete the coverage through the full contract surface:

* `security.rs` — the explicit threat-model attacks with exact denial codes:
  token spoofing, bypass across every operation, cross-token
  contamination, and configuration attacks (including rotation and
  double-initialization).
* `invariants.rs` — the system properties behind this page: hook
  evaluations never write enforcement state; a frozen account stays frozen
  under every policy/configuration transition until an admin unfreezes it;
  every operation outcome matches the enforcement oracle exhaustively;
  out-of-scope (unbound, unconfigured) never allows.
* `fuzz.rs` — deterministic, seeded random sequences of admin transitions
  and hook evaluations, asserting oracle parity after every step. This
  catches gate-order regressions, cross-token/account contamination in
  randomized states, and state drift (for example a freeze that silently
  failed to survive an unbind) that hand-written cases miss.
