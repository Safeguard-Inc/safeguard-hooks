# Examples

Ready-to-adapt deployment configurations for the `safeguard-hooks` CLI and
the `compliance-hooks` contract. Each directory is one deployment scenario
with a `configuration.json` in the shape the CLI loads
(`deployments/README.md` documents the fields). Addresses are placeholders:
replace them with freshly minted ids from your own deployment (the CLI's
`deploy --save` does this for you on a live network).

| Scenario | What it demonstrates |
| -------- | -------------------- |
| `basic-compliance/` | The default deployment: allow-all policy, one confidential token over its SAC, passthrough on. |
| `allowlist/` | Only listed accounts transact; everyone else is denied. |
| `denylist/` | Everyone transacts except the listed accounts. |
| `sanctions-policy/` | Policy-side sanctions screening; denials surface as `sanctions_blocked`. |
| `jurisdiction-policy/` | Policy-side jurisdiction rules; denials surface as `jurisdiction_restricted`. |
| `sac-passthrough/` | Optional SAC `authorized()` composition on top of policy. |
| `frozen-account/` | Admin-freeze workflow against a configured token. |
| `delegated-transfer/` | Spender-screened `transfer_from` flows (spender is policy-gated only). |
| `multi-token-policy/` | One policy contract serving several bound tokens. |

All configurations parse as JSON (checked by `scripts/check-schema.sh`).
They encode *deployment wiring only* — never secrets; the admin secret key
stays in the stellar CLI identity store or the env var named by
`admin.secret_key_env`.
