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
//! Reads (`show`) run as read-only simulations; admin writes (`init`,
//! `configure`, `bind`, `unbind`, `freeze`, `unfreeze`) send real
//! transactions signed by the admin source. A denial reverts and is
//! decoded into its stable rejection reason (`docs/errors.md`).

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
        let dir = std::env::temp_dir().join(format!("shcfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("configuration.json");
        std::fs::write(&path, raw).unwrap();
        path.to_string_lossy().into_owned()
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
