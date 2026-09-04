//! Deployment configuration loading.
//!
//! The CLI is driven by the per-environment configuration record described
//! in `deployments/README.md`: which network to talk to, where the hooks
//! contract lives, what the policy wiring is, and which tokens are in
//! enforcement scope. The file never holds secrets — the admin secret stays
//! in the stellar CLI identity store or an environment variable.

use serde::{Deserialize, Serialize};

/// The `deployments/<env>/configuration.json` shape.
///
/// Round-trippable: `safeguard-hooks deploy --save` writes freshly minted
/// contract ids back through this struct, so a deployment stays recorded.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    /// Stellar network name (must be registered in the stellar CLI config,
    /// e.g. `local`, `testnet`). The CLI registers it when `rpc_url` and
    /// `network_passphrase` are present and it is missing.
    pub network: String,
    /// RPC endpoint used to (re)register the network when needed.
    pub rpc_url: String,
    /// Network passphrase used to (re)register the network when needed.
    pub network_passphrase: String,
    /// The deployed `compliance-hooks` contract id (`C…`).
    pub hooks_contract_id: String,
    /// The policy the deployment points the hooks contract at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<Policy>,
    /// Informational mirror of the on-chain SAC-passthrough flag.
    #[serde(default)]
    pub sac_passthrough: bool,
    /// The admin authority of the hooks contract.
    pub admin: Admin,
    /// Tokens in enforcement scope, keyed by alias.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tokens: Vec<Token>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Policy {
    pub contract_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Admin {
    /// Public key the hooks contract was initialized with.
    pub public_key: String,
    /// stellar CLI identity name that signs admin operations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stellar_identity: Option<String>,
    /// Env var holding the admin secret key (alternative to an identity).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_key_env: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Token {
    /// Local name for `--token` arguments.
    pub alias: String,
    /// The bound token's address (`C…` for a contract, `G…` for an account).
    pub contract_id: String,
    /// The token's underlying SAC contract id, if it wraps one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sac_contract_id: Option<String>,
}
impl Config {
    /// Loads and parses the configuration file.
    pub fn load(path: &str) -> Result<Config, String> {
        let raw =
            std::fs::read_to_string(path).map_err(|e| format!("cannot read config {path}: {e}"))?;
        serde_json::from_str(&raw).map_err(|e| format!("invalid config {path}: {e}"))
    }

    /// Persists the configuration back to `path` (used by `deploy --save`
    /// to record freshly deployed contract ids).
    pub fn save(&self, path: &str) -> Result<(), String> {
        let raw = serde_json::to_string_pretty(self)
            .map_err(|e| format!("cannot serialize config: {e}"))?;
        std::fs::write(path, format!("{raw}\n"))
            .map_err(|e| format!("cannot write config {path}: {e}"))
    }

    /// Resolves a `--token` argument (an alias or a bare `C…`/`G…` address)
    /// to the token's contract id.
    pub fn resolve_token(&self, arg: &str) -> Result<String, String> {
        if let Some(t) = self.tokens.iter().find(|t| t.alias == arg) {
            return Ok(t.contract_id.clone());
        }
        if arg.starts_with('C') || arg.starts_with('G') {
            return Ok(arg.to_string());
        }
        let aliases: Vec<&str> = self.tokens.iter().map(|t| t.alias.as_str()).collect();
        Err(format!(
            "unknown token {arg:?}: not an alias ({}) and not a C…/G… address",
            if aliases.is_empty() {
                "no tokens configured".into()
            } else {
                aliases.join(", ")
            }
        ))
    }

    /// The SAC contract id bound for `token`, or `None` when the token has
    /// no underlying SAC.
    pub fn sac_for(&self, arg: &str) -> Option<String> {
        self.tokens
            .iter()
            .find(|t| t.alias == arg)
            .and_then(|t| t.sac_contract_id.clone())
    }

    /// Resolves the admin signing source: an explicit identity/secret beats
    /// the config's identity, which beats the secret env var.
    pub fn admin_source(&self, explicit: Option<&str>) -> Result<String, String> {
        if let Some(s) = explicit {
            return Ok(s.to_string());
        }
        if let Some(name) = &self.admin.stellar_identity {
            return Ok(name.clone());
        }
        if let Some(env) = &self.admin.secret_key_env {
            if let Ok(secret) = std::env::var(env) {
                if !secret.is_empty() {
                    return Ok(secret);
                }
            }
            return Err(format!(
                "config names admin secret in ${env}, which is not set"
            ));
        }
        Err("no admin source: pass --source, set admin.stellar_identity, or admin.secret_key_env in the config".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Config {
        serde_json::from_str(
            r#"{
                "network": "local",
                "rpc_url": "http://localhost:8000/rpc",
                "network_passphrase": "Standalone Network ; February 2017",
                "hooks_contract_id": "CA42K3YO7EDNT4PRRK7GBOACOLGJHSQBDGT57KH2W3JTGQSNDAB7USQL",
                "policy": { "contract_id": "CAC3QOZH4VXD4MEZOXI3X7J4OY4BPRYSKMLKICHS7NGTNW2BZIF637EE" },
                "sac_passthrough": false,
                "admin": { "public_key": "GBQZUZ2MKEJJXOMHVQMLTWPRDJIBPP6GB73JOZC2TSY5RT6CXX2YRDZS", "stellar_identity": "admin" },
                "tokens": [
                    { "alias": "usd", "contract_id": "GDHXVAXOEMOBX6SL43YX5OYF2XPLPNJFWRRYPPKGBPJ3P5HHDH7KXSBE", "sac_contract_id": null }
                ]
            }"#,
        )
        .unwrap()
    }

    #[test]
    fn token_resolution_accepts_alias_and_bare_address() {
        let c = sample();
        assert_eq!(
            c.resolve_token("usd").unwrap(),
            "GDHXVAXOEMOBX6SL43YX5OYF2XPLPNJFWRRYPPKGBPJ3P5HHDH7KXSBE"
        );
        assert_eq!(
            c.resolve_token("CA42K3YO7EDNT4PRRK7GBOACOLGJHSQBDGT57KH2W3JTGQSNDAB7USQL")
                .unwrap(),
            "CA42K3YO7EDNT4PRRK7GBOACOLGJHSQBDGT57KH2W3JTGQSNDAB7USQL"
        );
        assert!(c.resolve_token("nope").is_err());
        assert_eq!(c.sac_for("usd"), None);
    }

    #[test]
    fn admin_source_prefers_identity_over_env() {
        let c = sample();
        assert_eq!(c.admin_source(None).unwrap(), "admin");
        assert_eq!(c.admin_source(Some("deployer")).unwrap(), "deployer");
    }

    #[test]
    fn admin_source_falls_back_to_secret_env() {
        let c: Config = serde_json::from_str(
            r#"{
                "network": "testnet",
                "rpc_url": "https://soroban-testnet.stellar.org",
                "network_passphrase": "Test SDF Network ; September 2015",
                "hooks_contract_id": "C…",
                "admin": { "public_key": "G…", "secret_key_env": "SAFEGUARD_ADMIN_SK" },
                "tokens": []
            }"#,
        )
        .unwrap();
        // Missing env var → a clear error naming the variable.
        std::env::remove_var("SAFEGUARD_ADMIN_SK");
        let err = c.admin_source(None).unwrap_err();
        assert!(err.contains("SAFEGUARD_ADMIN_SK"), "{err}");
    }
}
