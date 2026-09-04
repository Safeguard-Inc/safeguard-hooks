# Interfaces

The cross-contract and cross-repo protocol surfaces of the enforcement layer,
written as canonical signature references. These files define *what a caller
must send and what it must expect back*; the Rust implementations live in
`contracts/compliance-hooks` (the hook entry points), `crates/policy-client`
(the policy wire client), and `crates/events` (the event structs). A change
to an implementation that drifts from these signatures is a protocol change
and must update the interface here, the code, and the schemas together.

Three surfaces are documented:

| Surface | Consumers | Interface |
| ------- | --------- | --------- |
| Hook entry points (`before_*`) | The confidential token (and any bound token) invoking enforcement before a state change | `hooks/hooks.md` |
| Policy wire (`is_authorized`) | `safeguard-policy` (DEFINE polyrepo) via `crates/policy-client` | `policy/policy.md` |
| Events | `safeguard-audit` (VERIFY polyrepo) via ledger event streams | `events/events.md` |

The one rule that holds across all three surfaces: **no private financial
data crosses any interface** — addresses, operation names, and booleans
only (`docs/privacy.md`).
