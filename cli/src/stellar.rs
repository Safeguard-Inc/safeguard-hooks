//! The stellar-CLI bridge.
//!
//! Every ledger operation goes through the stellar CLI (`stellar contract
//! invoke …`), the same tool `docs/deployment.md` verifies. This module owns
//! the argument shapes that are easy to get wrong — per-parameter flags,
//! JSON quoting for `Option<Address>` values, the read-only simulation
//! behavior — and decodes `Error(Contract, #N)` revers into the stable
//! rejection names from `safeguard-hook-core`.
//!
//! The [`Runner`] trait lets unit tests drive the whole command surface
//! with a fake that records invocations and returns canned output — no
//! network, no stellar CLI binary required.

use std::process::Command;

use safeguard_hook_core::RejectionReason;

/// A process that can execute a stellar CLI invocation.
pub trait Runner {
    /// Runs one stellar CLI command and returns its combined result.
    fn run(&self, args: &[String]) -> Result<RunOutcome, String>;
}

/// The captured result of a stellar CLI invocation.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RunOutcome {
    pub ok: bool,
    pub stdout: String,
    pub stderr: String,
}

impl RunOutcome {
    fn combined(&self) -> String {
        format!("{}\n{}", self.stdout, self.stderr)
    }

    /// The invocation's value: the last non-empty stdout line. stellar CLI
    /// prints informational lines (e.g. read-only simulation notices) and
    /// then the returned value; reads and sends alike end on the value.
    pub fn value(&self) -> Option<String> {
        self.stdout
            .lines()
            .map(str::trim)
            .rev()
            .find(|l| !l.is_empty())
            .map(String::from)
    }
}

/// The real runner: executes the `stellar` binary.
pub struct Stellar {
    pub bin: String,
}

impl Runner for Stellar {
    fn run(&self, args: &[String]) -> Result<RunOutcome, String> {
        let out = Command::new(&self.bin)
            .args(args)
            .output()
            .map_err(|e| format!("failed to run {}: {e}", self.bin))?;
        Ok(RunOutcome {
            ok: out.status.success(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }
}

// ################## ARGUMENT VALUE FORMATTING ##################
//
// stellar-cli 28 conventions (verified in docs/deployment.md):
// * plain `Address` parameters take a bare `G…`/`C…` string;
// * `Option<Address>` parameters take JSON — `"C…"` for Some, `null` for
//   None — because a wrapped address parses as a JSON value;
// * `bool` parameters take `true`/`false`.

/// A plain `Address` parameter value.
pub fn address(addr: &str) -> String {
    addr.to_string()
}

/// An `Option<Address>` parameter value (JSON).
pub fn opt_address(addr: Option<&str>) -> String {
    match addr {
        Some(a) => format!("\"{a}\""),
        None => "null".into(),
    }
}

/// A `bool` parameter value.
pub fn boolean(value: bool) -> String {
    value.to_string()
}

/// Builds `stellar contract invoke` argv for a hooks-contract function.
///
/// `params` are `(parameter name, formatted value)` pairs; every function
/// takes `--<name> <value>` flags after the function name.
pub fn invoke_args(
    source: Option<&str>,
    hooks_id: &str,
    network: &str,
    func: &str,
    params: &[(&str, String)],
) -> Vec<String> {
    let mut args = vec![
        "contract".into(),
        "invoke".into(),
        "--id".into(),
        hooks_id.to_string(),
    ];
    if let Some(source) = source {
        args.push("--source".into());
        args.push(source.to_string());
    }
    args.push("--network".into());
    args.push(network.to_string());
    args.push("--".into());
    args.push(func.to_string());
    for (name, value) in params {
        args.push(format!("--{name}"));
        args.push(value.clone());
    }
    args
}

/// Builds the argv that registers `network` in the stellar CLI config.
pub fn network_add_args(network: &str, rpc_url: &str, passphrase: &str) -> Vec<String> {
    vec![
        "network".into(),
        "add".into(),
        network.to_string(),
        "--rpc-url".into(),
        rpc_url.to_string(),
        "--network-passphrase".into(),
        passphrase.to_string(),
    ]
}

/// Whether `network` is registered in the stellar CLI config.
pub fn network_list_args() -> Vec<String> {
    vec!["network".into(), "ls".into()]
}

/// Decodes a `Error(Contract, #N)` line into the stable reason.
///
/// Returns the reason for codes 1–11, the contract's own `already_initialized`
/// for code 12, and `None` for anything else (host/auth failures and codes
/// this tool does not know are surfaced verbatim).
pub fn decode_contract_error(combined: &str) -> Option<ContractRevert> {
    for line in combined.lines() {
        let Some(idx) = line.find("Error(Contract, #") else {
            continue;
        };
        let rest = &line[idx + "Error(Contract, #".len()..];
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() {
            continue;
        }
        let code: u32 = digits.parse().ok()?;
        return Some(ContractRevert::from_code(code));
    }
    None
}

/// A decoded contract revert.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ContractRevert {
    /// Codes 1–11 map to a stable rejection reason.
    Rejection(RejectionReason),
    /// Code 12 is the contract's own double-initialization guard.
    AlreadyInitialized,
    /// A code outside the documented range.
    Unknown(u32),
}

impl ContractRevert {
    pub fn from_code(code: u32) -> Self {
        match RejectionReason::from_code(code) {
            Some(reason) => ContractRevert::Rejection(reason),
            None if code == 12 => ContractRevert::AlreadyInitialized,
            None => ContractRevert::Unknown(code),
        }
    }

    /// A one-line operator-facing description (`docs/errors.md` has the
    /// remediation detail).
    pub fn describe(self) -> String {
        match self {
            ContractRevert::Rejection(r) => {
                format!("contract error #{}: {} — see docs/errors.md", r.code(), r.name())
            }
            ContractRevert::AlreadyInitialized => {
                "contract error #12: already_initialized — initialize runs once; re-init is an admin-rotation attempt".into()
            }
            ContractRevert::Unknown(code) => format!("contract error #{code}: undocumented code"),
        }
    }
}

/// Interprets an invocation outcome into a CLI result.
///
/// A successful run yields the returned value (if any). A failed run whose
/// output contains a decoded contract revert becomes `Err` with that
/// description; other failures keep the raw stellar error tail.
pub fn interpret(outcome: RunOutcome) -> Result<Option<String>, String> {
    if outcome.ok {
        return Ok(outcome.value());
    }
    let combined = outcome.combined();
    if let Some(revert) = decode_contract_error(&combined) {
        return Err(revert.describe());
    }
    // Not a decoded contract revert (auth failure, RPC down, CLI misuse):
    // surface the stellar CLI's own error line (the last non-empty one).
    match combined
        .lines()
        .map(str::trim)
        .rev()
        .find(|l| !l.is_empty())
    {
        Some(tail) => Err(tail.to_string()),
        None => Err("stellar CLI failed without output".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake runner returning one canned outcome.
    #[derive(Default)]
    struct Fake {
        outcome: std::cell::RefCell<Option<RunOutcome>>,
    }

    impl Fake {
        fn returns(outcome: RunOutcome) -> Self {
            Fake {
                outcome: std::cell::RefCell::new(Some(outcome)),
            }
        }
    }

    impl Runner for Fake {
        fn run(&self, _args: &[String]) -> Result<RunOutcome, String> {
            Ok(self.outcome.borrow_mut().take().expect("fake primed once"))
        }
    }

    fn run_ok(stdout: &str) -> RunOutcome {
        RunOutcome {
            ok: true,
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    fn run_err(stdout: &str) -> RunOutcome {
        RunOutcome {
            ok: false,
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    #[test]
    fn invoke_argv_is_shaped_like_docs_deployment_md() {
        let args = invoke_args(
            Some("admin"),
            "CA…HOOKS",
            "local",
            "set_config",
            &[
                ("policy", opt_address(Some("CA…POLICY"))),
                ("sac_passthrough", boolean(false)),
            ],
        );
        assert_eq!(
            args,
            [
                "contract",
                "invoke",
                "--id",
                "CA…HOOKS",
                "--source",
                "admin",
                "--network",
                "local",
                "--",
                "set_config",
                "--policy",
                "\"CA…POLICY\"",
                "--sac_passthrough",
                "false"
            ]
        );
    }

    #[test]
    fn option_addresses_take_json_values() {
        assert_eq!(opt_address(Some("CABC")), "\"CABC\"");
        assert_eq!(opt_address(None), "null");
        assert_eq!(address("GABC"), "GABC");
        assert_eq!(boolean(true), "true");
    }

    #[test]
    fn bind_with_null_sac_omits_nothing_important() {
        // The null SAC is explicit: an unset passthrough target stays null.
        let args = invoke_args(
            None,
            "CA…HOOKS",
            "local",
            "bind_token",
            &[("token", address("G…TOKEN")), ("sac", opt_address(None))],
        );
        assert_eq!(args[args.len() - 1], "null");
    }

    #[test]
    fn successful_read_yields_the_value_line() {
        let fake = Fake::returns(run_ok("\nfalse\n"));
        let out = fake.run(&[]).unwrap();
        assert_eq!(interpret(out).unwrap(), Some("false".into()));
    }

    #[test]
    fn successful_send_yields_null_value() {
        let fake = Fake::returns(run_ok("✅ Transaction submitted successfully!\nnull\n"));
        let out = fake.run(&[]).unwrap();
        assert_eq!(interpret(out).unwrap(), Some("null".into()));
    }

    #[test]
    fn contract_reverts_decode_to_stable_reasons() {
        let cases = [
            ("Error(Contract, #2)", "unbound_token"),
            ("Error(Contract, #3)", "policy_denied"),
            ("Error(Contract, #4)", "account_frozen"),
        ];
        for (raw, name) in cases {
            let revert = decode_contract_error(raw).unwrap();
            match revert {
                ContractRevert::Rejection(r) => assert_eq!(r.name(), name),
                other => panic!("unexpected decode: {other:?}"),
            }
            assert!(revert.describe().contains(name));
        }
    }

    #[test]
    fn failed_run_with_contract_error_describes_the_reason() {
        let fake = Fake::returns(run_err(
            "❌ error: transaction simulation failed: HostError: Error(Contract, #4)\n",
        ));
        let out = fake.run(&[]).unwrap();
        let err = interpret(out).unwrap_err();
        assert!(err.contains("account_frozen"), "{err}");
    }

    #[test]
    fn double_initialization_maps_to_the_contract_code() {
        let revert = decode_contract_error("HostError: Error(Contract, #12)").unwrap();
        assert_eq!(revert, ContractRevert::AlreadyInitialized);
        assert!(revert.describe().contains("already_initialized"));
    }

    #[test]
    fn non_contract_failures_surface_the_raw_tail() {
        let fake = Fake::returns(run_err("some log line\n❌ error: account not found\n"));
        let out = fake.run(&[]).unwrap();
        let err = interpret(out).unwrap_err();
        assert!(err.contains("account not found"), "{err}");
    }
}
