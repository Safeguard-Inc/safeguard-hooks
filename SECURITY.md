# Security

## Reporting a vulnerability

Please report suspected vulnerabilities privately — do **not** open a public
issue. Email the maintainers at the address listed on the repository
settings page (or open a private advisory via the GitHub "Security" tab of
this repository) with:

* the affected version / commit;
* a description of the flaw and its impact;
* reproduction steps or a minimal proof of concept.

You will receive an acknowledgment within five business days and a target
timeline for the fix. Please give the maintainers time to release a fix
before disclosing the issue publicly.

## Scope

This repository implements the **ENFORCE** layer of the Safeguard compliance
stack for Stellar Confidential Tokens. It is a **developer-preview** codebase
for a developer-preview protocol; do not deploy it as production financial
infrastructure.

The security posture and trust model are documented in `docs/security.md`
and `docs/threat-model.md`; the explicit attack tests live in
`contracts/compliance-hooks/tests/security.rs`. Anything that defeats the
fail-closed enforcement model (a rejected operation that changes state, an
unbound or spoofed token that runs gates, cross-token contamination, or
unauthorized administration) is in scope. Confidential Token core, ZK proof
generation, wallets, dashboards, and the policy/audit polyrepos are outside
this repository — report issues there to their own maintainers.
