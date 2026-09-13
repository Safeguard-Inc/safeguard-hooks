//! Offline integration tests for the built `safeguard-hooks` binary.
//!
//! These exercise the real executable (argument parsing, dispatch, output)
//! without a ledger: `--help`, the offline `errors` reference, and clean
//! failures when a command needs a config that does not exist. Network-touching
//! behavior is covered by unit tests (scripted runner) and by the live-ledger
//! integration in `scripts/integration-local.sh` / the CLI's own validation.

use std::path::PathBuf;
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_safeguard-hooks"))
}

/// A 56-character address, the exact shape the operator surface accepts.
fn address(prefix: char, fill: char) -> String {
    format!("{prefix}{}", fill.to_string().repeat(55))
}

/// A scratch directory unique to this invocation.
///
/// Integration tests run concurrently in one process, so a shared path lets
/// one test's `truncate`-then-`write` be observed as an empty file by
/// another's read. Keying on the pid alone is not enough — every test here
/// shares that pid.
fn scratch(name: &str) -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "safeguard-cli-it-{}-{}-{}",
        std::process::id(),
        name,
        COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Makes `path` executable on unix (a no-op elsewhere).
fn make_executable(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

/// Writes a fake `stellar` binary that answers the read-only surface
/// `verify` uses, plus `network ls`.
///
/// The fake is keyed on the function name after `--`, exactly as the real
/// CLI is. `FAKE_PROBE_ALLOWS=1` makes the unbound-token probe succeed
/// instead of reverting, which is the fail-closed regression under test.
fn fake_stellar(dir: &std::path::Path, admin: &str, policy: &str) -> PathBuf {
    let path = dir.join("fake-stellar");
    let script = format!(
        r#"#!/bin/sh
if [ "$1" = network ] && [ "$2" = ls ]; then echo testnet; exit 0; fi
# The function name is the first argument after the `--` separator; the
# `--token` value must be read positionally, because the simulation source
# (`--source-account` {admin}) is present on *every* invocation and would
# otherwise be mistaken for the token argument.
fn=""; tok=""; seen=0; prev=""
for a in "$@"; do
  if [ "$a" = "--" ]; then seen=1; continue; fi
  if [ "$seen" = "1" ] && [ -z "$fn" ]; then fn="$a"; fi
  if [ "$prev" = "--token" ]; then tok="$a"; fi
  prev="$a"
done
case "$fn" in
  initialized) echo true ;;
  admin) echo {admin} ;;
  config) echo '{{"policy":"{policy}","sac_passthrough":false}}' ;;
  config_version|state_version) echo 1 ;;
  token_is_bound)
    if [ "$tok" = "{admin}" ]; then echo false; else echo true; fi ;;
  before_transfer)
    if [ -n "$FAKE_PROBE_ALLOWS" ]; then echo null; exit 0; fi
    echo 'error: transaction simulation failed: HostError: Error(Contract, #2)' >&2
    exit 1 ;;
  *) echo "unexpected function: $fn" >&2; exit 2 ;;
esac
"#
    );
    std::fs::write(&path, script).unwrap();
    make_executable(&path);
    path
}

/// A deployment config whose admin secret is named by an env var that is
/// deliberately unset — `verify` must not need it.
fn verify_config(dir: &std::path::Path, admin: &str, policy: &str, token: &str) -> PathBuf {
    let path = dir.join("configuration.json");
    std::fs::write(
        &path,
        format!(
            r#"{{
  "network": "testnet",
  "rpc_url": "https://soroban-testnet.stellar.org",
  "network_passphrase": "Test SDF Network ; September 2015",
  "hooks_contract_id": "{}",
  "policy": {{ "contract_id": "{policy}" }},
  "sac_passthrough": false,
  "admin": {{ "public_key": "{admin}", "secret_key_env": "SAFEGUARD_ADMIN_SK_UNSET" }},
  "tokens": [
    {{ "alias": "usd", "contract_id": "{token}", "sac_contract_id": null }}
  ]
}}"#,
            address('C', 'B'),
        ),
    )
    .unwrap();
    path
}

#[test]
fn verify_runs_a_read_only_smoke_test_with_no_secret_key() {
    let dir = scratch("verify-ok");
    let admin = address('G', 'A');
    let policy = address('C', 'D');
    let token = address('C', 'E');
    let config = verify_config(&dir, &admin, &policy, &token);
    let fake = fake_stellar(&dir, &admin, &policy);

    let out = bin()
        .arg("--config")
        .arg(&config)
        .arg("--stellar-bin")
        .arg(&fake)
        .env_remove("SAFEGUARD_ADMIN_SK_UNSET")
        .arg("verify")
        .output()
        .unwrap();

    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "verify failed:\n{text}");
    assert!(text.contains("no secret key"), "{text}");
    for check in [
        "PASS  contract reachable",
        "PASS  initialized",
        "PASS  admin matches the config",
        "PASS  compliance configuration present",
        "PASS  recorded policy matches the contract",
        "PASS  token usd bound",
        "PASS  fail-closed probe",
    ] {
        assert!(text.contains(check), "missing {check}\n{text}");
    }
    assert!(text.contains("9 passed, 0 failed, 1 skipped"), "{text}");
}

#[test]
fn verify_exits_non_zero_when_the_gate_stops_failing_closed() {
    let dir = scratch("verify-broken");
    let admin = address('G', 'A');
    let policy = address('C', 'D');
    let token = address('C', 'E');
    let config = verify_config(&dir, &admin, &policy, &token);
    let fake = fake_stellar(&dir, &admin, &policy);

    let out = bin()
        .arg("--config")
        .arg(&config)
        .arg("--stellar-bin")
        .arg(&fake)
        .env("FAKE_PROBE_ALLOWS", "1")
        .arg("verify")
        .output()
        .unwrap();

    let text = String::from_utf8_lossy(&out.stdout);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "verify should fail:\n{text}");
    assert!(text.contains("FAIL  fail-closed probe"), "{text}");
    assert!(text.contains("8 passed, 1 failed"), "{text}");
    assert!(err.contains("deployment verification failed"), "{err}");
}

#[test]
fn verify_rejects_a_placeholder_source_account_before_any_ledger_call() {
    let dir = scratch("verify-placeholder");
    let path = dir.join("configuration.json");
    std::fs::write(
        &path,
        r#"{
            "network": "local",
            "rpc_url": "http://localhost:8000/rpc",
            "network_passphrase": "Standalone Network ; February 2017",
            "hooks_contract_id": "CA…HOOKS",
            "admin": { "public_key": "G…ADMIN" },
            "tokens": []
        }"#,
    )
    .unwrap();

    // The stellar binary is deliberately absent: a placeholder must be
    // reported before any ledger call, so this proves the validation happens
    // first. Pointing at a missing binary rather than relying on the runner
    // not having one keeps the test independent of the machine it runs on —
    // the previous version passed locally (where stellar was installed) and
    // failed in CI with "failed to run stellar" instead.
    let out = bin()
        .arg("--config")
        .arg(&path)
        .arg("--stellar-bin")
        .arg(dir.join("no-such-stellar-binary"))
        .arg("verify")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--source-account"), "{err}");
    assert!(
        !err.contains("failed to run"),
        "a placeholder must be rejected before any ledger call: {err}"
    );
}

#[test]
fn help_lists_the_operator_surface() {
    let out = bin().arg("--help").output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    for command in [
        "init",
        "configure",
        "bind",
        "unbind",
        "freeze",
        "unfreeze",
        "deploy",
        "show",
        "verify",
        "errors",
    ] {
        assert!(text.contains(command), "--help missing {command}:\n{text}");
    }
    assert!(text.contains("compliance-hooks"));
}

#[test]
fn errors_reference_is_offline_and_complete() {
    let out = bin().arg("errors").output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    for (code, name) in [
        (" 2", "unbound_token"),
        (" 3", "policy_denied"),
        (" 4", "account_frozen"),
        (" 5", "spender_not_authorized"),
        (" 8", "sac_authorization_failed"),
        (" 9", "invalid_configuration"),
        ("10", "policy_unavailable"),
        ("12", "already_initialized"),
    ] {
        assert!(text.contains(name), "errors output missing {name}:\n{text}");
        assert!(text.contains(code), "errors output missing code {code}");
    }
}

#[test]
fn errors_decodes_a_single_code() {
    let out = bin().arg("errors").arg("4").output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("account_frozen"));
}

#[test]
fn missing_config_fails_with_a_clear_message() {
    let out = bin()
        .arg("--config")
        .arg("/nonexistent/configuration.json")
        .arg("show")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("cannot read config"),
        "unexpected error:\n{err}"
    );
}

#[test]
fn unknown_token_is_rejected_with_a_precise_error() {
    // A fake stellar that only answers `network ls` keeps the test hermetic;
    // the unknown-token error must surface before any ledger round-trip.
    let dir = std::env::temp_dir().join("safeguard-cli-it");
    std::fs::create_dir_all(&dir).unwrap();

    let cfg = dir.join("minimal.json");
    std::fs::write(
        &cfg,
        r#"{
            "network": "local",
            "rpc_url": "http://localhost:8000/rpc",
            "network_passphrase": "Standalone Network ; February 2017",
            "hooks_contract_id": "CA…HOOKS",
            "admin": { "public_key": "G…ADMIN", "stellar_identity": "admin" },
            "tokens": []
        }"#,
    )
    .unwrap();

    let fake = dir.join("fake-stellar");
    std::fs::write(
        &fake,
        "#!/bin/sh\nif [ \"$1\" = network ] && [ \"$2\" = ls ]; then echo local; fi\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let out = bin()
        .arg("--config")
        .arg(&cfg)
        .arg("--stellar-bin")
        .arg(&fake)
        .arg("freeze")
        .args(["--token", "nope", "--account", "G…"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("unknown token"), "unexpected error:\n{err}");
}
