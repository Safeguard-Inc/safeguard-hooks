//! # safeguard-hooks (operator CLI)
//!
//! Inspects and configures the on-chain compliance-hooks enforcement layer.
//! Every ledger operation is executed by the stellar CLI (>= 28) — this tool
//! is a thin, checked operator surface on top of it, never a second
//! compliance engine: all policy, freeze, and binding state lives on the
//! contract and is reached through the same verified commands documented in
//! `docs/deployment.md`.
//!
//! Configuration: `--config deployments/<env>/configuration.json` (or
//! `SAFEGUARD_CONFIG`), see `deployments/README.md`. Admin signing uses a
//! stellar CLI identity name or a secret key (`--source`, or the source
//! named by the config), kept out of this tool's own state.
//!
//! Reads (`show`, `verify`) run as read-only simulations; admin writes
//! (`init`, `configure`, `bind`, `unbind`, `freeze`, `unfreeze`) send real
//! transactions signed by the admin source. A denial reverts and is
//! decoded into its stable rejection reason (`docs/errors.md`).
//!
//! `verify` is the deployment smoke test: it answers "is the thing just
//! deployed actually enforcing?" by simulating from a bare public key, so
//! it needs — and touches — no secret key material.

mod config;
mod stellar;

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};

use config::Config;
use stellar::{address, boolean, interpret, opt_address, Runner, Stellar};

#[derive(Parser)]
#[command(
    name = "safeguard-hooks",
    version,
    about = "Operator CLI for the Safeguard compliance-hooks contract (ENFORCE)"
)]
struct Cli {
    /// Deployment configuration file (deployments/README.md).
    #[arg(
        long,
        env = "SAFEGUARD_CONFIG",
        default_value = "deployments/local/configuration.json"
    )]
    config: PathBuf,

    /// stellar CLI source signing admin operations: an identity name, a
    /// secret key, or a seed phrase. Defaults to the config's admin source.
    #[arg(long, env = "SAFEGUARD_SOURCE")]
    source: Option<String>,

    /// stellar CLI binary to invoke.
    #[arg(long, env = "STELLAR", default_value = "stellar")]
    stellar_bin: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Runs the one-shot initialize(admin) — fails with #12 if already done.
    Init,
    /// Writes the compliance configuration (admin): policy address and the
    /// SAC-passthrough flag.
    Configure {
        /// Policy contract id to point at; `--no-policy` clears the gate.
        #[arg(long, conflicts_with = "no_policy")]
        policy: Option<String>,
        /// Configure no policy (policy = null) — skip the policy gate.
        #[arg(long)]
        no_policy: bool,
        /// SAC-passthrough flag. Defaults to the config's value.
        #[arg(long)]
        sac_passthrough: Option<bool>,
    },
    /// Admits a token into enforcement scope (admin), with its underlying
    /// SAC when it has one.
    Bind {
        /// Token alias (from the config) or a bare C…/G… address.
        #[arg(long)]
        token: String,
        /// The token's SAC contract id, when it wraps one.
        #[arg(long)]
        sac: Option<String>,
    },
    /// Removes a token from enforcement scope (admin).
    Unbind {
        /// Token alias (from the config) or a bare C…/G… address.
        #[arg(long)]
        token: String,
    },
    /// Freezes an account on a token (admin). Frozen = no send, receive,
    /// deposit, or withdraw on that token until an admin unfreezes it.
    Freeze {
        /// Token alias (from the config) or a bare C…/G… address.
        #[arg(long)]
        token: String,
        /// The account to freeze (G…).
        #[arg(long)]
        account: String,
    },
    /// Unfreezes an account on a token (admin).
    Unfreeze {
        /// Token alias (from the config) or a bare C…/G… address.
        #[arg(long)]
        token: String,
        /// The account to unfreeze (G…).
        #[arg(long)]
        account: String,
    },
    /// Deploys and configures a fresh enforcement deployment from the config:
    /// deploy hooks (and optionally a policy), then initialize → configure →
    /// bind every configured token (deployment tooling).
    Deploy {
        /// `compliance-hooks` wasm to deploy.
        #[arg(long)]
        hooks_wasm: PathBuf,
        /// `sample-policy` wasm to deploy as the policy.
        #[arg(long)]
        sample_policy_wasm: Option<PathBuf>,
        /// Pin the deployed sample policy to deny this account (G…).
        #[arg(long, requires = "sample_policy_wasm")]
        policy_blocked: Option<String>,
        /// Reuse an already-deployed policy contract instead of deploying one.
        #[arg(long, conflicts_with_all = ["sample_policy_wasm", "no_policy"])]
        policy_id: Option<String>,
        /// Configure the hooks contract with no policy gate.
        #[arg(long, conflicts_with_all = ["sample_policy_wasm", "policy_id"])]
        no_policy: bool,
        /// SAC-passthrough flag for the new config (default: config value).
        #[arg(long)]
        sac_passthrough: Option<bool>,
        /// Write the freshly deployed contract ids back into the config file.
        #[arg(long)]
        save: bool,
    },
    /// Reads on-chain enforcement state (read-only simulations).
    Show {
        /// Token alias to scope the reads to (defaults to all configured).
        #[arg(long)]
        token: Option<String>,
        /// Also print the freeze flag for this account on the token.
        #[arg(long, requires = "token")]
        account: Option<String>,
    },
    /// Post-deployment smoke test: read-only, needs no secret key, reports
    /// PASS/FAIL per check, and exits non-zero when any check fails.
    Verify {
        /// The `G…` public key to simulate reads from (defaults to the
        /// config's `admin.public_key`). Never a secret: verification is a
        /// pure simulation and uses no key material.
        #[arg(long, env = "SAFEGUARD_SOURCE_ACCOUNT")]
        source_account: Option<String>,
        /// Sample the enforcement gate for this account on every bound
        /// token — reports what the gate decided (nothing is signed or sent).
        #[arg(long)]
        account: Option<String>,
    },
    /// Lists the rejection codes / decodes one code offline.
    Errors {
        /// Decode a single code (1–12); omit to list all.
        code: Option<u32>,
    },
}

fn main() {
    let cli = Cli::parse();
    let code = match run(&cli) {
        Ok(()) => 0,
        Err(msg) => {
            eprintln!("❌ {msg}");
            1
        }
    };
    std::process::exit(code);
}

/// Executes the command against the config's network.
fn run(cli: &Cli) -> Result<(), String> {
    // Offline: no config, no ledger.
    if let Command::Errors { code } = &cli.command {
        return print_errors(*code);
    }

    let config = Config::load(&cli.config.to_string_lossy())?;

    // `verify` is read-only and secret-free, so it bypasses admin-source
    // resolution entirely: a smoke test must run on a deployment whose
    // secret the operator does not have (a reviewer's machine, CI, or an
    // incident response after key rotation). It also validates its own
    // arguments *before* any ledger call, so a placeholder left in a
    // deployment record is reported as a placeholder rather than as an
    // opaque network failure.
    if let Command::Verify {
        source_account,
        account,
    } = &cli.command
    {
        let source_account = source_account
            .clone()
            .unwrap_or_else(|| config.admin.public_key.clone());
        if !stellar::is_stellar_address(&source_account) {
            return Err(format!(
                "verify simulates from a bare public key, but {source_account:?} is not a \
                 56-character G… address — pass --source-account, or set a real \
                 admin.public_key in the config"
            ));
        }
        if let Some(account) = account {
            if !stellar::is_stellar_address(account) {
                return Err(format!(
                    "--account must be a 56-character G… address, got {account:?}"
                ));
            }
        }
        let runner = Stellar {
            bin: cli.stellar_bin.clone(),
        };
        ensure_network(&runner, &config)?;
        let checks = verify(&runner, &config, &source_account, account.as_deref());
        print_report(&checks, &config, &source_account);
        let failed = checks.iter().filter(|c| c.status == Status::Fail).count();
        if failed > 0 {
            return Err(format!(
                "deployment verification failed: {failed} of {} checks failed",
                checks.len()
            ));
        }
        return Ok(());
    }

    let runner = Stellar {
        bin: cli.stellar_bin.clone(),
    };
    ensure_network(&runner, &config)?;
    let source = config.admin_source(cli.source.as_deref())?;
    let app = App {
        config,
        config_path: cli.config.clone(),
        runner,
        source,
    };

    match &cli.command {
        Command::Init => app.init(),
        Command::Configure {
            policy,
            no_policy,
            sac_passthrough,
        } => {
            let policy = if *no_policy {
                None
            } else {
                match policy {
                    Some(id) => Some(id.clone()),
                    None => app.config.policy.as_ref().map(|p| p.contract_id.clone()),
                }
            };
            let sac = sac_passthrough.unwrap_or(app.config.sac_passthrough);
            app.configure(policy.as_deref(), sac)
        }
        Command::Bind { token, sac } => app.bind(token, sac.as_deref()),
        Command::Unbind { token } => app.unbind(token),
        Command::Freeze { token, account } => app.freeze(token, account),
        Command::Unfreeze { token, account } => app.unfreeze(token, account),
        Command::Deploy {
            hooks_wasm,
            sample_policy_wasm,
            policy_blocked,
            policy_id,
            no_policy,
            sac_passthrough,
            save,
        } => {
            let save_path = if *save {
                Some(app.config_path.as_path())
            } else {
                None
            };
            run_deploy(
                &app.runner,
                &app.config,
                save_path,
                &app.source,
                hooks_wasm,
                sample_policy_wasm.as_deref(),
                policy_blocked.as_deref(),
                policy_id.as_deref(),
                *no_policy,
                *sac_passthrough,
            )
        }
        Command::Show { token, account } => app.show(token.as_deref(), account.as_deref()),
        Command::Verify { .. } => unreachable!("handled before the admin source is resolved"),
        Command::Errors { .. } => unreachable!(),
    }
}

/// The runtime context for one invocation.
struct App {
    config: Config,
    config_path: PathBuf,
    runner: Stellar,
    source: String,
}

impl App {
    fn hooks_id(&self) -> &str {
        &self.config.hooks_contract_id
    }

    fn network(&self) -> &str {
        &self.config.network
    }

    /// Runs one hooks-contract invocation and interprets the outcome.
    fn invoke(&self, func: &str, params: &[(&str, String)]) -> Result<Option<String>, String> {
        let args = stellar::invoke_args(
            Some(&self.source),
            self.hooks_id(),
            self.network(),
            func,
            params,
        );
        let outcome = self.runner.run(&args)?;
        interpret(outcome)
    }

    /// Runs an invocation. Reads are simulated (stellar CLI does not send
    /// when the call is read-only), but the stellar CLI still wants a source
    /// account to build the simulation footprint.
    fn read(&self, func: &str, params: &[(&str, String)]) -> Result<Option<String>, String> {
        self.invoke(func, params)
    }

    fn init(&self) -> Result<(), String> {
        self.invoke(
            "initialize",
            &[("admin", address(&self.config.admin.public_key))],
        )?;
        println!("initialized with admin {}", self.config.admin.public_key);
        Ok(())
    }

    fn configure(&self, policy: Option<&str>, sac: bool) -> Result<(), String> {
        self.invoke(
            "set_config",
            &[
                ("policy", opt_address(policy)),
                ("sac_passthrough", boolean(sac)),
            ],
        )?;
        match policy {
            Some(id) => println!("policy set to {id}; sac_passthrough={sac}"),
            None => println!("policy gate disabled; sac_passthrough={sac}"),
        }
        Ok(())
    }

    fn bind(&self, token: &str, sac: Option<&str>) -> Result<(), String> {
        let id = self.config.resolve_token(token)?.to_string();
        let sac = match sac {
            Some(s) => Some(s.to_string()),
            None => self.config.sac_for(token),
        };
        self.invoke(
            "bind_token",
            &[
                ("token", address(&id)),
                ("sac", opt_address(sac.as_deref())),
            ],
        )?;
        println!("bound {id}");
        Ok(())
    }

    fn unbind(&self, token: &str) -> Result<(), String> {
        let id = self.config.resolve_token(token)?.to_string();
        self.invoke("unbind_token", &[("token", address(&id))])?;
        println!("unbound {id}");
        Ok(())
    }

    fn freeze(&self, token: &str, account: &str) -> Result<(), String> {
        self.freeze_op("freeze", token, account)
    }

    fn unfreeze(&self, token: &str, account: &str) -> Result<(), String> {
        self.freeze_op("unfreeze", token, account)
    }

    fn freeze_op(&self, func: &str, token: &str, account: &str) -> Result<(), String> {
        let id = self.config.resolve_token(token)?.to_string();
        self.invoke(
            func,
            &[("token", address(&id)), ("account", address(account))],
        )?;
        let past = if func == "freeze" { "froze" } else { "unfroze" };
        println!("{past} {account} on {id}");
        Ok(())
    }

    fn show(&self, token: Option<&str>, account: Option<&str>) -> Result<(), String> {
        println!("hooks contract: {}", self.hooks_id());
        println!("network: {}", self.network());

        let initialized = self.read("initialized", &[])?;
        println!("initialized: {}", value_or(initialized.as_deref(), "?"));
        let admin = self.read("admin", &[])?;
        match admin.as_deref() {
            Some("null") | None => println!("admin: (none)"),
            Some(a) => println!("admin: {a}"),
        }
        let config = self.read("config", &[])?;
        match config.as_deref() {
            Some("null") | None => println!("config: null (enforcement off — hooks fail closed)"),
            Some(c) => println!("config: {c}"),
        }
        let version = self.read("config_version", &[])?;
        println!("config_version: {}", value_or(version.as_deref(), "?"));

        // Resolve the requested token set: one alias/address, or all
        // configured tokens.
        let mut targets: Vec<String> = Vec::new();
        match token {
            Some(t) => targets.push(self.config.resolve_token(t)?.to_string()),
            None => {
                for t in &self.config.tokens {
                    targets.push(t.contract_id.clone());
                }
                if targets.is_empty() {
                    println!("tokens: none configured");
                    return Ok(());
                }
            }
        }

        for id in &targets {
            let bound = self.read("token_is_bound", &[("token", address(id))])?;
            println!("token {id}: bound={}", value_or(bound.as_deref(), "?"));
            if let Some(acc) = account {
                let frozen = self.read(
                    "is_frozen",
                    &[("token", address(id)), ("account", address(acc))],
                )?;
                println!("  frozen({acc})={}", value_or(frozen.as_deref(), "?"));
            }
        }
        Ok(())
    }
}

fn value_or<'a>(v: Option<&'a str>, fallback: &'a str) -> &'a str {
    v.filter(|s| !s.is_empty()).unwrap_or(fallback)
}

// ################## DEPLOYMENT VERIFICATION ##################

/// The outcome of one verification check.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum Status {
    Pass,
    Fail,
    /// The check could not run in this configuration (reported, not failed).
    Skip,
}

/// One reported verification check.
#[derive(Debug, Clone)]
struct Check {
    name: String,
    status: Status,
    detail: String,
}

impl Check {
    fn pass(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Check {
            name: name.into(),
            status: Status::Pass,
            detail: detail.into(),
        }
    }

    fn fail(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Check {
            name: name.into(),
            status: Status::Fail,
            detail: detail.into(),
        }
    }

    fn skip(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Check {
            name: name.into(),
            status: Status::Skip,
            detail: detail.into(),
        }
    }
}

/// The verdict of a simulated enforcement gate.
enum GateOutcome {
    /// The contract let the operation through.
    Allowed,
    /// The contract refused, with a decoded reason.
    Denied(stellar::ContractRevert),
}

/// The last non-empty line of a combined CLI output — the CLI's own error
/// tail once no contract revert decodes.
fn last_nonempty(combined: &str) -> Option<String> {
    combined
        .lines()
        .map(str::trim)
        .rev()
        .find(|l| !l.is_empty())
        .map(String::from)
}

/// Runs one read-only view (`--source-account <G…> --send=no`) and returns
/// the contract's value. Never signs, never sends, never needs a secret.
fn view<R: Runner>(
    runner: &R,
    source_account: &str,
    contract_id: &str,
    network: &str,
    func: &str,
    params: &[(&str, String)],
) -> Result<String, String> {
    let args = stellar::view_args(source_account, contract_id, network, func, params);
    let outcome = runner.run(&args)?;
    if outcome.ok {
        return Ok(outcome.value().unwrap_or_default());
    }
    let combined = outcome.combined();
    if let Some(revert) = stellar::decode_contract_error(&combined) {
        return Err(revert.describe());
    }
    Err(last_nonempty(&combined).unwrap_or_else(|| "stellar CLI failed without output".into()))
}

/// Simulates one gate entry point and reports whether it allowed or refused.
///
/// A refusal is a decoded contract revert; anything else (RPC down, bad
/// argument shape, host error) is an `Err` — the distinction matters,
/// because "the gate refused" and "the gate could not run" are different
/// findings.
fn gate<R: Runner>(
    runner: &R,
    source_account: &str,
    contract_id: &str,
    network: &str,
    func: &str,
    params: &[(&str, String)],
) -> Result<GateOutcome, String> {
    let args = stellar::view_args(source_account, contract_id, network, func, params);
    let outcome = runner.run(&args)?;
    if outcome.ok {
        return Ok(GateOutcome::Allowed);
    }
    let combined = outcome.combined();
    match stellar::decode_contract_error(&combined) {
        Some(revert) => Ok(GateOutcome::Denied(revert)),
        None => {
            Err(last_nonempty(&combined)
                .unwrap_or_else(|| "stellar CLI failed without output".into()))
        }
    }
}

/// Normalizes a printed address: the CLI prints addresses bare, but a JSON
/// wrapper (quotes) must not produce a spurious mismatch.
fn unquote(value: &str) -> &str {
    value.trim().trim_matches('"')
}

/// Verifies a live deployment read-only and returns one check per claim.
///
/// The surface is deliberately the *deployment's* claims, not a restatement
/// of the config file: a config that says a token is bound proves nothing
/// until the contract agrees, and a contract that is configured but no
/// longer reaches a decision is the failure mode this exists to catch.
fn verify<R: Runner>(
    runner: &R,
    config: &Config,
    source_account: &str,
    account: Option<&str>,
) -> Vec<Check> {
    use stellar::ContractRevert;

    let hooks = config.hooks_contract_id.as_str();
    let network = config.network.as_str();
    let mut checks = Vec::new();

    // Reachability doubles as the first read: if the contract id is wrong or
    // the network is unreachable, nothing else can be checked and returning
    // early keeps the report honest rather than full of cascading failures.
    let initialized = match view(runner, source_account, hooks, network, "initialized", &[]) {
        Ok(value) => value,
        Err(err) => {
            checks.push(Check::fail("contract reachable", err));
            return checks;
        }
    };
    checks.push(Check::pass(
        "contract reachable",
        format!("{hooks} answered on {network}"),
    ));

    if unquote(&initialized) == "true" {
        checks.push(Check::pass(
            "initialized",
            "initialize has run — the admin seat is claimed",
        ));
    } else {
        checks.push(Check::fail(
            "initialized",
            format!(
                "initialized returned {:?}: initialize never ran, so every hook fails closed",
                unquote(&initialized)
            ),
        ));
    }

    match view(runner, source_account, hooks, network, "admin", &[]) {
        Ok(admin) => {
            let admin = unquote(&admin);
            if admin == config.admin.public_key {
                checks.push(Check::pass(
                    "admin matches the config",
                    format!("on-chain admin {admin}"),
                ));
            } else {
                checks.push(Check::fail(
                    "admin matches the config",
                    format!(
                        "config records {} but the contract reports {} — one of the two is stale",
                        config.admin.public_key, admin
                    ),
                ));
            }
        }
        Err(err) => checks.push(Check::fail("admin matches the config", err)),
    }

    let mut configured = false;
    match view(runner, source_account, hooks, network, "config", &[]) {
        Ok(raw) => {
            if unquote(&raw) == "null" || raw.trim().is_empty() {
                checks.push(Check::fail(
                    "compliance configuration present",
                    "set_config has never run: the contract is inert and every hook reverts #9 \
                     (invalid_configuration)",
                ));
            } else {
                configured = true;
                let policy = serde_json::from_str::<serde_json::Value>(&raw)
                    .ok()
                    .and_then(|v| v.get("policy").cloned())
                    .and_then(|p| p.as_str().map(String::from));
                let described = match &policy {
                    Some(id) => format!("policy gate → {id}"),
                    None => "no policy gate (fail-closed on bindings and freeze only)".to_string(),
                };
                checks.push(Check::pass("compliance configuration present", described));
                // The config's recorded policy is the deployment's own claim;
                // a mismatch means the live contract was reconfigured without
                // the record being updated.
                match (&policy, &config.policy) {
                    (Some(live), Some(recorded)) if live != &recorded.contract_id => {
                        checks.push(Check::fail(
                            "recorded policy matches the contract",
                            format!(
                                "config records {} but the contract uses {live} — update the \
                                 deployment record",
                                recorded.contract_id
                            ),
                        ));
                    }
                    (Some(live), Some(recorded)) if live == &recorded.contract_id => {
                        checks.push(Check::pass(
                            "recorded policy matches the contract",
                            format!("both name {live}"),
                        ));
                    }
                    _ => {}
                }
            }
        }
        Err(err) => checks.push(Check::fail("compliance configuration present", err)),
    }

    for (func, label, floor) in [
        ("config_version", "config_version", 1u32),
        ("state_version", "state_version", 1u32),
    ] {
        match view(runner, source_account, hooks, network, func, &[]) {
            Ok(raw) => match raw.trim().parse::<u32>() {
                Ok(version) if version >= floor => {
                    checks.push(Check::pass(label, format!("{func} = {version}")))
                }
                Ok(version) => checks.push(Check::fail(
                    label,
                    format!("{func} = {version}, expected ≥ {floor}"),
                )),
                Err(_) => checks.push(Check::fail(
                    label,
                    format!("{func} returned {:?}, which is not a u32", raw.trim()),
                )),
            },
            Err(err) => checks.push(Check::fail(label, err)),
        }
    }

    if config.tokens.is_empty() {
        checks.push(Check::skip(
            "token bindings",
            "no tokens listed in the config",
        ));
    }
    for token in &config.tokens {
        let name = format!("token {} bound", token.alias);
        let params = [("token", address(&token.contract_id))];
        match view(
            runner,
            source_account,
            hooks,
            network,
            "token_is_bound",
            &params,
        ) {
            Ok(value) if unquote(&value) == "true" => checks.push(Check::pass(
                name,
                format!("{} is in enforcement scope", token.contract_id),
            )),
            Ok(value) => checks.push(Check::fail(
                name,
                format!(
                    "token_is_bound returned {:?} for {} — the token is not gated, so its \
                     operations are not screened",
                    unquote(&value),
                    token.contract_id
                ),
            )),
            Err(err) => checks.push(Check::fail(name, err)),
        }
    }

    // ################## FAIL-CLOSED PROBE ##################
    //
    // The contract's central promise (docs/security.md) is that an unbound
    // token is rejected before any gate runs. The admin address is the one
    // address guaranteed to be out of scope, so it is the probe: first read
    // its binding, then require the contract to refuse an operation on it.
    let probe = config.admin.public_key.as_str();
    let probe_params = [("token", address(probe))];
    match view(
        runner,
        source_account,
        hooks,
        network,
        "token_is_bound",
        &probe_params,
    ) {
        Ok(value) if unquote(&value) == "true" => checks.push(Check::fail(
            "fail-closed probe",
            format!(
                "the admin address {probe} is bound as a token, so it cannot serve as the \
                 unbound probe — investigate why an admin key entered enforcement scope"
            ),
        )),
        Ok(_) => {
            let transfer = [
                ("token", address(probe)),
                ("from", address(probe)),
                ("to", address(probe)),
            ];
            match gate(
                runner,
                source_account,
                hooks,
                network,
                "before_transfer",
                &transfer,
            ) {
                Ok(GateOutcome::Allowed) => checks.push(Check::fail(
                    "fail-closed probe",
                    format!(
                        "the contract allowed before_transfer on unbound token {probe} — \
                         fail-closed is broken (docs/security.md)"
                    ),
                )),
                Ok(GateOutcome::Denied(ContractRevert::Rejection(reason))) => {
                    let expected = reason.name() == "unbound_token";
                    let detail = format!(
                        "before_transfer on unbound token {probe} refused with #{} {}",
                        reason.code(),
                        reason.name()
                    );
                    checks.push(if expected {
                        Check::pass("fail-closed probe", detail)
                    } else {
                        Check::fail(
                            "fail-closed probe",
                            format!("{detail} — expected #2 unbound_token"),
                        )
                    });
                }
                Ok(GateOutcome::Denied(revert)) => checks.push(Check::fail(
                    "fail-closed probe",
                    format!("unexpected refusal: {}", revert.describe()),
                )),
                Err(err) => checks.push(Check::fail("fail-closed probe", err)),
            }
        }
        Err(err) => checks.push(Check::fail("fail-closed probe", err)),
    }

    // ################## SAMPLE GATE ##################
    //
    // What a deployment must be able to do is *reach a decision*. Being
    // refused is a healthy outcome for an account the policy blocks; being
    // unable to evaluate (#9/#10) is not, because it means a fail-closed
    // outage (or, worse, that enforcement is off).
    let Some(account) = account else {
        checks.push(Check::skip(
            "gate sample",
            "pass --account G… to observe a real enforcement decision",
        ));
        return checks;
    };
    if !configured {
        checks.push(Check::skip(
            "gate sample",
            "no compliance configuration to sample",
        ));
        return checks;
    }
    for token in &config.tokens {
        let name = format!("gate sample on {}", token.alias);
        let params = [
            ("token", address(&token.contract_id)),
            ("from", address(account)),
            ("to", address(account)),
        ];
        match gate(
            runner,
            source_account,
            hooks,
            network,
            "before_transfer",
            &params,
        ) {
            Ok(GateOutcome::Allowed) => checks.push(Check::pass(
                name,
                format!("before_transfer({account}) allowed"),
            )),
            Ok(GateOutcome::Denied(ContractRevert::Rejection(reason))) => {
                let undecidable = matches!(
                    reason,
                    safeguard_hook_core::RejectionReason::InvalidConfiguration
                        | safeguard_hook_core::RejectionReason::PolicyUnavailable
                );
                let detail = format!("the gate refused #{} {}", reason.code(), reason.name());
                checks.push(if undecidable {
                    Check::fail(
                        name,
                        format!("{detail} — enforcement cannot reach a decision"),
                    )
                } else {
                    Check::pass(name, format!("{detail} — the gate is live and refusing"))
                });
            }
            Ok(GateOutcome::Denied(revert)) => checks.push(Check::fail(
                name,
                format!("unexpected refusal: {}", revert.describe()),
            )),
            Err(err) => checks.push(Check::fail(name, err)),
        }
    }
    checks
}

/// Prints the verification report, one line per check.
fn print_report(checks: &[Check], config: &Config, source_account: &str) {
    println!("safeguard-hooks verify — read-only, no secret key");
    println!("network: {}", config.network);
    println!("hooks contract: {}", config.hooks_contract_id);
    println!("source account: {source_account} (simulated, never signs)");
    println!();
    for check in checks {
        let tag = match check.status {
            Status::Pass => "PASS",
            Status::Fail => "FAIL",
            Status::Skip => "SKIP",
        };
        println!("  {tag}  {}", check.name);
        if !check.detail.is_empty() {
            println!("        {}", check.detail);
        }
    }
    let count = |status: Status| checks.iter().filter(|c| c.status == status).count();
    println!();
    println!(
        "{} passed, {} failed, {} skipped",
        count(Status::Pass),
        count(Status::Fail),
        count(Status::Skip)
    );
}

/// Runs a raw stellar CLI command against `runner`, decoding any revert on
/// failure.
fn send_raw<R: Runner>(runner: &R, args: &[String]) -> Result<stellar::RunOutcome, String> {
    let outcome = runner.run(args)?;
    if outcome.ok {
        Ok(outcome)
    } else {
        Err(interpret(outcome)
            .err()
            .unwrap_or_else(|| "stellar CLI failed".into()))
    }
}

/// Deploys a fresh enforcement deployment and configures it from the
/// deployment config (one-command bring-up): deploy the hooks contract,
/// optionally deploy or reuse a policy, then run the one-way lifecycle
/// `initialize → set_config → bind_token` for every configured token.
///
/// Generic over the [`Runner`] so tests drive it with a scripted fake.
/// `config_path` records the freshly minted ids back into the config file
/// when present (`--save`); the wasm paths must already be built.
#[allow(clippy::too_many_arguments)]
fn run_deploy<R: Runner>(
    runner: &R,
    config: &Config,
    config_path: Option<&Path>,
    source: &str,
    hooks_wasm: &Path,
    sample_policy_wasm: Option<&Path>,
    policy_blocked: Option<&str>,
    policy_id: Option<&str>,
    no_policy: bool,
    sac_passthrough: Option<bool>,
) -> Result<(), String> {
    let network = &config.network;
    let hooks_wasm = hooks_wasm.to_string_lossy().into_owned();
    if !Path::new(&hooks_wasm).exists() {
        return Err(format!(
            "hooks wasm not found at {hooks_wasm} — build it with \
             `cargo build --target wasm32v1-none --release -p compliance-hooks`"
        ));
    }

    // 1. Deploy the hooks contract.
    println!("deploying compliance-hooks…");
    let out = send_raw(
        runner,
        &stellar::deploy_args(&hooks_wasm, source, network, &[]),
    )?;
    let hooks_id = stellar::parse_deployed_id(&out.stdout)
        .ok_or_else(|| "could not parse the deployed hooks contract id".to_string())?;
    println!("deployed hooks: {hooks_id}");

    // 2. Resolve the policy: an explicit id, a freshly deployed sample
    //    policy, the config's recorded policy, or no policy gate.
    let policy: Option<String> = if no_policy {
        None
    } else if let Some(id) = policy_id {
        Some(id.to_string())
    } else if let Some(wasm) = sample_policy_wasm {
        let wasm = wasm.to_string_lossy().into_owned();
        if !Path::new(&wasm).exists() {
            return Err(format!(
                "sample-policy wasm not found at {wasm} — build it with \
                 `cargo build --target wasm32v1-none --release -p sample-policy`"
            ));
        }
        let mut constructor = Vec::new();
        if let Some(blocked) = policy_blocked {
            constructor.push(("blocked", opt_address(Some(blocked))));
        }
        let out = send_raw(
            runner,
            &stellar::deploy_args(&wasm, source, network, &constructor),
        )?;
        let pid = stellar::parse_deployed_id(&out.stdout)
            .ok_or_else(|| "could not parse the deployed policy contract id".to_string())?;
        println!("deployed policy: {pid}");
        Some(pid)
    } else {
        config.policy.as_ref().map(|p| p.contract_id.clone())
    };

    // 3. Run the one-way lifecycle on the fresh contract.
    let invoke = |func: &str, params: &[(&str, String)]| -> Result<(), String> {
        let args = stellar::invoke_args(Some(source), &hooks_id, network, func, params);
        interpret(runner.run(&args)?).map(|_| ())
    };
    invoke(
        "initialize",
        &[("admin", address(&config.admin.public_key))],
    )?;
    println!("initialized with admin {}", config.admin.public_key);

    let sac = sac_passthrough.unwrap_or(config.sac_passthrough);
    invoke(
        "set_config",
        &[
            ("policy", opt_address(policy.as_deref())),
            ("sac_passthrough", boolean(sac)),
        ],
    )?;
    match &policy {
        Some(id) => println!("policy set to {id}; sac_passthrough={sac}"),
        None => println!("policy gate disabled; sac_passthrough={sac}"),
    }

    for token in &config.tokens {
        invoke(
            "bind_token",
            &[
                ("token", address(&token.contract_id)),
                ("sac", opt_address(token.sac_contract_id.as_deref())),
            ],
        )?;
        println!("bound token {}", token.alias);
    }

    if let Some(path) = config_path {
        let mut updated = config.clone();
        updated.hooks_contract_id = hooks_id.clone();
        updated.policy = policy.map(|id| config::Policy { contract_id: id });
        updated.sac_passthrough = sac;
        updated.save(&path.to_string_lossy())?;
        println!("config updated: {}", path.display());
    } else {
        println!(
            "config not modified — rerun with --save to record {hooks_id} as the hooks contract"
        );
    }
    Ok(())
}

/// Registers the configured network in the stellar CLI config when missing.
fn ensure_network<R: Runner>(runner: &R, config: &Config) -> Result<(), String> {
    let listed = runner.run(&stellar::network_list_args())?;
    if !listed.ok {
        return Err("cannot list stellar networks — is the stellar CLI configured?".into());
    }
    let registered = listed
        .stdout
        .lines()
        .map(str::trim)
        .any(|line| line == config.network);
    if registered {
        return Ok(());
    }
    let added = runner.run(&stellar::network_add_args(
        &config.network,
        &config.rpc_url,
        &config.network_passphrase,
    ))?;
    if !added.ok {
        return Err(format!(
            "network {} is not registered and could not be added: {}",
            config.network,
            added.stderr.trim()
        ));
    }
    Ok(())
}

/// Offline error reference (no config, no ledger required).
fn print_errors(code: Option<u32>) -> Result<(), String> {
    use safeguard_hook_core::RejectionReason;
    match code {
        Some(c) => {
            let revert = stellar::ContractRevert::from_code(c);
            println!("{}", revert.describe());
        }
        None => {
            println!("Rejection codes (docs/errors.md):");
            for reason in RejectionReason::ALL {
                println!("  {:>2}  {}", reason.code(), reason.name());
            }
            println!("  12  already_initialized (contract-only)");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    /// A scripted runner: each queued outcome answers one invocation.
    #[derive(Default)]
    struct Scripted {
        queue: RefCell<VecDeque<stellar::RunOutcome>>,
        calls: RefCell<Vec<Vec<String>>>,
    }

    impl Runner for Scripted {
        fn run(&self, args: &[String]) -> Result<stellar::RunOutcome, String> {
            self.calls.borrow_mut().push(args.to_vec());
            Ok(self
                .queue
                .borrow_mut()
                .pop_front()
                .expect("scripted runner exhausted"))
        }
    }

    fn ok_out(stdout: &str) -> stellar::RunOutcome {
        stellar::RunOutcome {
            ok: true,
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    fn err_out(stderr: &str) -> stellar::RunOutcome {
        stellar::RunOutcome {
            ok: false,
            stdout: String::new(),
            stderr: stderr.into(),
        }
    }

    fn config_path() -> String {
        // A minimal config used only for loading in these tests.
        let raw = r#"{
            "network": "local",
            "rpc_url": "http://localhost:8000/rpc",
            "network_passphrase": "Standalone Network ; February 2017",
            "hooks_contract_id": "CA…HOOKS",
            "policy": { "contract_id": "CA…POLICY" },
            "sac_passthrough": false,
            "admin": { "public_key": "GBQZ…ADMIN", "stellar_identity": "admin" },
            "tokens": [
                { "alias": "usd", "contract_id": "G…USD", "sac_contract_id": null }
            ]
        }"#;
        // Tests run in parallel in one process, so the scratch dir must be
        // unique per call: a shared `shcfg-<pid>` path raced (one test's
        // truncate-then-write was observed as an empty file by another's
        // read, surfacing as "EOF while parsing a value").
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "shcfg-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("configuration.json");
        std::fs::write(&path, raw).unwrap();
        path.to_string_lossy().into_owned()
    }

    /// The scripted answers for a healthy `deployments/local` deployment:
    /// initialized, the config's admin, the config's own policy, versions at
    /// 1, the one configured token bound, and an out-of-scope admin probe.
    fn healthy_deployment() -> Vec<stellar::RunOutcome> {
        vec![
            ok_out("true\n"),
            ok_out("GBQZ…ADMIN\n"),
            ok_out("{\"policy\":\"CA…POLICY\",\"sac_passthrough\":false}\n"),
            ok_out("1\n"),
            ok_out("1\n"),
            ok_out("true\n"),
            ok_out("false\n"),
            err_out("❌ error: transaction simulation failed: HostError: Error(Contract, #2)\n"),
        ]
    }

    fn run_verify(
        outcomes: Vec<stellar::RunOutcome>,
        account: Option<&str>,
    ) -> (Vec<Check>, Scripted) {
        let scripted = Scripted {
            queue: RefCell::new(VecDeque::from(outcomes)),
            ..Default::default()
        };
        let config = Config::load(&config_path()).unwrap();
        let checks = verify(&scripted, &config, "GBQZ…ADMIN", account);
        (checks, scripted)
    }

    fn fails(checks: &[Check]) -> Vec<&str> {
        checks
            .iter()
            .filter(|c| c.status == Status::Fail)
            .map(|c| c.name.as_str())
            .collect()
    }

    #[test]
    fn verify_passes_a_healthy_deployment_without_any_secret() {
        let (checks, scripted) = run_verify(healthy_deployment(), None);
        assert_eq!(fails(&checks), Vec::<&str>::new());
        assert_eq!(
            checks.iter().filter(|c| c.status == Status::Pass).count(),
            9,
            "{checks:#?}"
        );
        assert_eq!(
            checks.iter().filter(|c| c.status == Status::Skip).count(),
            1
        );
        // Every read went out as a simulation from a bare public key: no
        // `--source` (which would demand an identity or secret) appears.
        for call in scripted.calls.borrow().iter() {
            assert!(call.contains(&"--send=no".to_string()), "{call:?}");
            assert!(call.contains(&"--source-account".to_string()), "{call:?}");
            assert!(!call.contains(&"--source".to_string()), "{call:?}");
        }
    }

    #[test]
    fn verify_fails_when_the_gate_allows_an_unbound_token() {
        let mut outcomes = healthy_deployment();
        *outcomes.last_mut().unwrap() = ok_out("null\n");
        let (checks, _) = run_verify(outcomes, None);
        assert_eq!(fails(&checks), ["fail-closed probe"]);
    }

    #[test]
    fn verify_reports_an_unconfigured_contract() {
        let mut outcomes = healthy_deployment();
        outcomes[2] = ok_out("null\n");
        outcomes[3] = ok_out("0\n"); // config_version, still zero
        outcomes[5] = ok_out("false\n"); // the token was never bound
        let (checks, _) = run_verify(outcomes, None);
        assert_eq!(
            fails(&checks),
            [
                "compliance configuration present",
                "config_version",
                "token usd bound"
            ]
        );
    }

    #[test]
    fn verify_flags_a_policy_that_no_longer_matches_the_record() {
        let mut outcomes = healthy_deployment();
        outcomes[2] = ok_out("{\"policy\":\"CB…ROTATED\",\"sac_passthrough\":false}\n");
        let (checks, _) = run_verify(outcomes, None);
        assert_eq!(fails(&checks), ["recorded policy matches the contract"]);
    }

    #[test]
    fn verify_stops_early_when_the_contract_is_unreachable() {
        let (checks, _) = run_verify(vec![err_out("❌ error: account not found\n")], None);
        assert_eq!(checks.len(), 1);
        assert_eq!(fails(&checks), ["contract reachable"]);
    }

    #[test]
    fn verify_samples_a_real_gate_decision_when_an_account_is_given() {
        let mut outcomes = healthy_deployment();
        outcomes.push(err_out("HostError: Error(Contract, #4)\n"));
        let (checks, _) = run_verify(outcomes, Some("GBQZ…ACCOUNT"));
        assert_eq!(fails(&checks), Vec::<&str>::new(), "{checks:#?}");
        assert_eq!(
            checks.iter().filter(|c| c.status == Status::Skip).count(),
            0
        );
        let sample = checks
            .iter()
            .find(|c| c.name == "gate sample on usd")
            .expect("the gate sample must be reported");
        assert!(sample.detail.contains("account_frozen"), "{sample:?}");
    }

    #[test]
    fn verify_fails_a_gate_sample_that_cannot_reach_a_decision() {
        let mut outcomes = healthy_deployment();
        outcomes.push(err_out("HostError: Error(Contract, #10)\n"));
        let (checks, _) = run_verify(outcomes, Some("GBQZ…ACCOUNT"));
        assert_eq!(fails(&checks), ["gate sample on usd"]);
    }

    #[test]
    fn placeholder_source_accounts_are_rejected_before_any_ledger_call() {
        assert!(!stellar::is_stellar_address("GBQZ…ADMIN"));
        assert!(stellar::is_stellar_address(&format!("G{}", "A".repeat(55))));
        assert!(!stellar::is_stellar_address(&format!(
            "S{}",
            "A".repeat(55)
        )));
    }

    #[test]
    fn ensure_network_registers_a_missing_network() {
        let scripted = Scripted {
            queue: RefCell::new(VecDeque::from([
                ok_out("futurenet\ntestnet\n"), // network ls → local missing
                ok_out("added\n"),              // network add
            ])),
            ..Default::default()
        };
        let config = Config::load(&config_path()).unwrap();
        ensure_network(&scripted, &config).unwrap();
        let calls = scripted.calls.borrow();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0][0], "network");
        assert!(calls[1].contains(&"--rpc-url".to_string()));
    }

    #[test]
    fn ensure_network_skips_when_already_registered() {
        let scripted = Scripted {
            queue: RefCell::new(VecDeque::from([ok_out("local\nfuturenet\n")])),
            ..Default::default()
        };
        let config = Config::load(&config_path()).unwrap();
        ensure_network(&scripted, &config).unwrap();
        assert_eq!(scripted.calls.borrow().len(), 1);
    }

    #[test]
    fn decode_references_are_offline() {
        // The offline `errors` reference needs no config or ledger.
        assert!(print_errors(None).is_ok());
    }

    fn fake_id(letter: char) -> String {
        format!("C{}", letter.to_string().repeat(55))
    }

    #[test]
    fn deploy_runs_the_full_lifecycle_in_order() {
        // Script the whole bring-up: deploy hooks, deploy a deny-list sample
        // policy, then initialize → set_config → bind each token.
        let hooks_id = fake_id('A');
        let policy_id = fake_id('B');
        let scripted = Scripted {
            queue: RefCell::new(VecDeque::from([
                ok_out(&format!("✅ Deployed!\n{hooks_id}\n")),
                ok_out(&format!("✅ Deployed!\n{policy_id}\n")),
                ok_out("null\n"), // initialize
                ok_out("null\n"), // set_config
                ok_out("null\n"), // bind_token (one configured token)
            ])),
            ..Default::default()
        };

        // The config's own policy is ignored: the wasm path deploys a fresh
        // deny-list policy pinned to a blocked account.
        let config = Config::load(&config_path()).unwrap();
        let dir = std::env::temp_dir().join(format!("shwasm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let hooks_wasm = dir.join("hooks.wasm");
        let policy_wasm = dir.join("policy.wasm");
        std::fs::write(&hooks_wasm, b"wasm").unwrap();
        std::fs::write(&policy_wasm, b"wasm").unwrap();

        run_deploy(
            &scripted,
            &config,
            None,
            "admin",
            &hooks_wasm,
            Some(&policy_wasm),
            Some("GBQZ…BOB"),
            None,
            false,
            None,
        )
        .unwrap();

        let calls = scripted.calls.borrow();
        assert_eq!(calls.len(), 5);

        // [0] hooks deploy; [1] policy deploy with the JSON-quoted deny target.
        assert!(calls[0]
            .windows(2)
            .any(|w| w == ["--wasm", &hooks_wasm.to_string_lossy()]));
        assert!(calls[1]
            .windows(2)
            .any(|w| w == ["--wasm", &policy_wasm.to_string_lossy()]));
        let dash = calls[1].iter().position(|a| a == "--").unwrap();
        assert_eq!(calls[1][dash + 1..], ["--blocked", "\"GBQZ…BOB\""]);

        // [2..4] the lifecycle targets the freshly deployed hooks id.
        assert!(calls[2].contains(&hooks_id));
        assert_eq!(
            calls[2][calls[2].iter().position(|a| a == "--").unwrap() + 1],
            "initialize"
        );
        assert_eq!(
            calls[3][calls[3].iter().position(|a| a == "--").unwrap() + 1],
            "set_config"
        );
        let set_cfg = &calls[3];
        assert!(set_cfg
            .windows(2)
            .any(|w| w == ["--policy", &format!("\"{policy_id}\"")]));
        assert!(set_cfg
            .windows(2)
            .any(|w| w == ["--sac_passthrough", "false"]));
        assert_eq!(
            calls[4][calls[4].iter().position(|a| a == "--").unwrap() + 1],
            "bind_token"
        );
    }

    #[test]
    fn deploy_save_records_fresh_ids_into_the_config() {
        let hooks_id = fake_id('C');
        let scripted = Scripted {
            queue: RefCell::new(VecDeque::from([
                ok_out(&format!("✅ Deployed!\n{hooks_id}\n")),
                ok_out("null\n"), // initialize
                ok_out("null\n"), // set_config
                ok_out("null\n"), // bind_token
            ])),
            ..Default::default()
        };

        let dir = std::env::temp_dir().join(format!("shsave-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let hooks_wasm = dir.join("hooks.wasm");
        std::fs::write(&hooks_wasm, b"wasm").unwrap();
        let target = dir.join("configuration.json");
        std::fs::copy(config_path(), &target).unwrap();

        // No policy wasm and no --policy-id: the config's recorded policy is
        // reused, and its (stale) hooks id is overwritten by the deploy.
        run_deploy(
            &scripted,
            &Config::load(&target.to_string_lossy()).unwrap(),
            Some(&target),
            "admin",
            &hooks_wasm,
            None,
            None,
            None,
            false,
            None,
        )
        .unwrap();

        let saved = Config::load(&target.to_string_lossy()).unwrap();
        assert_eq!(saved.hooks_contract_id, hooks_id);
        assert_eq!(
            saved.policy.as_ref().map(|p| p.contract_id.as_str()),
            Some("CA…POLICY")
        );
        // The config round-tripped losslessly enough to load again.
        assert_eq!(saved.tokens.len(), 1);
        assert_eq!(saved.tokens[0].alias, "usd");
    }
}
