//! Offline integration tests for the built `safeguard-hooks` binary.
//!
//! These exercise the real executable (argument parsing, dispatch, output)
//! without a ledger: `--help`, the offline `errors` reference, and clean
//! failures when a command needs a config that does not exist. Network-touching
//! behavior is covered by unit tests (scripted runner) and by the live-ledger
//! integration in `scripts/integration-local.sh` / the CLI's own validation.

use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_safeguard-hooks"))
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
        (" 1", "unauthorized_caller"),
        (" 2", "unbound_token"),
        (" 3", "policy_denied"),
        (" 4", "account_frozen"),
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
