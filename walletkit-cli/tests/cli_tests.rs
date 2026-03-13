#![allow(missing_docs, clippy::missing_panics_doc, clippy::missing_errors_doc)]

//! Integration tests for the `walletkit` CLI binary.
//!
//! These tests invoke the binary via `cargo run` or the built binary
//! to verify argument parsing, storage bootstrapping, and output formats.

use std::path::PathBuf;
use std::process::Command;

fn walletkit_bin() -> PathBuf {
    let path = PathBuf::from(env!("CARGO_BIN_EXE_walletkit"));
    assert!(path.exists(), "binary not found at {}", path.display());
    path
}

fn temp_root() -> tempfile::TempDir {
    tempfile::tempdir().expect("failed to create temp dir")
}

#[test]
fn help_exits_zero() {
    let output = Command::new(walletkit_bin())
        .arg("--help")
        .output()
        .expect("failed to run walletkit");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("wallet"));
    assert!(stdout.contains("auth"));
    assert!(stdout.contains("credential"));
    assert!(stdout.contains("proof"));
}

#[test]
fn wallet_paths_prints_json() {
    let root = temp_root();
    let output = Command::new(walletkit_bin())
        .args([
            "--root",
            root.path().to_str().unwrap(),
            "--json",
            "wallet",
            "paths",
        ])
        .output()
        .expect("failed to run");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("invalid json");
    assert_eq!(parsed["ok"], true);
    assert!(parsed["data"]["root"].as_str().unwrap().len() > 0);
}

#[test]
fn wallet_paths_json_has_all_keys() {
    let root = temp_root();
    let output = Command::new(walletkit_bin())
        .args([
            "--root",
            root.path().to_str().unwrap(),
            "--json",
            "wallet",
            "paths",
        ])
        .output()
        .expect("failed to run");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("invalid json");
    let data = &parsed["data"];
    for key in &[
        "root",
        "worldid_dir",
        "vault_db",
        "cache_db",
        "lock",
        "groth16_dir",
        "query_zkey",
        "nullifier_zkey",
        "query_graph",
        "nullifier_graph",
    ] {
        assert!(
            data[key].as_str().is_some(),
            "missing key '{key}' in wallet paths JSON output"
        );
    }
}

#[test]
fn wallet_init_creates_groth16_material() {
    let root = temp_root();
    let output = Command::new(walletkit_bin())
        .args(["--root", root.path().to_str().unwrap(), "wallet", "init"])
        .output()
        .expect("failed to run");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Wallet initialized"));

    let groth16_dir = root.path().join("worldid").join("groth16");
    assert!(groth16_dir.join("OPRFQuery.arks.zkey").exists());
    assert!(groth16_dir.join("OPRFNullifier.arks.zkey").exists());
    assert!(groth16_dir.join("OPRFQueryGraph.bin").exists());
    assert!(groth16_dir.join("OPRFNullifierGraph.bin").exists());

    assert!(root.path().join(".device_key").exists());
}

#[test]
fn wallet_init_json_output() {
    let root = temp_root();
    let output = Command::new(walletkit_bin())
        .args([
            "--root",
            root.path().to_str().unwrap(),
            "--json",
            "wallet",
            "init",
        ])
        .output()
        .expect("failed to run");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("invalid json");
    assert_eq!(parsed["ok"], true);
    assert!(parsed["data"]["groth16_dir"].as_str().is_some());
}

#[test]
fn wallet_doctor_reports_healthy_after_init() {
    let root = temp_root();

    Command::new(walletkit_bin())
        .args(["--root", root.path().to_str().unwrap(), "wallet", "init"])
        .output()
        .expect("failed to run init");

    let output = Command::new(walletkit_bin())
        .args([
            "--root",
            root.path().to_str().unwrap(),
            "--json",
            "wallet",
            "doctor",
        ])
        .output()
        .expect("failed to run doctor");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("invalid json");
    assert_eq!(parsed["ok"], true);
    assert_eq!(parsed["data"]["healthy"], true);
    assert_eq!(parsed["data"]["groth16_cached"], true);
}

#[test]
fn wallet_doctor_reports_issues_without_init() {
    let root = temp_root();

    let output = Command::new(walletkit_bin())
        .args([
            "--root",
            root.path().to_str().unwrap(),
            "--json",
            "wallet",
            "doctor",
        ])
        .output()
        .expect("failed to run doctor");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("invalid json");
    assert_eq!(parsed["data"]["groth16_cached"], false);
}

#[test]
fn auth_without_seed_fails() {
    let root = temp_root();

    let output = Command::new(walletkit_bin())
        .args(["--root", root.path().to_str().unwrap(), "auth", "info"])
        .output()
        .expect("failed to run");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--seed") || stderr.contains("random-seed"),
        "expected seed error, got: {stderr}"
    );
}

#[test]
fn seed_invalid_hex_fails() {
    let root = temp_root();

    let output = Command::new(walletkit_bin())
        .args([
            "--root",
            root.path().to_str().unwrap(),
            "--seed",
            "zzzzzz",
            "auth",
            "info",
        ])
        .output()
        .expect("failed to run");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid hex seed"),
        "expected hex parse error, got: {stderr}"
    );
}

#[test]
fn seed_wrong_length_fails() {
    let root = temp_root();

    let output = Command::new(walletkit_bin())
        .args([
            "--root",
            root.path().to_str().unwrap(),
            "--seed",
            "0102",
            "auth",
            "info",
        ])
        .output()
        .expect("failed to run");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("32 bytes"),
        "expected length error, got: {stderr}"
    );
}

#[test]
fn random_seed_prints_seed() {
    let root = temp_root();

    Command::new(walletkit_bin())
        .args(["--root", root.path().to_str().unwrap(), "wallet", "init"])
        .output()
        .expect("failed to run init");

    let output = Command::new(walletkit_bin())
        .args([
            "--root",
            root.path().to_str().unwrap(),
            "--random-seed",
            "auth",
            "init",
        ])
        .output()
        .expect("failed to run");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Generated random seed: 0x") || !output.status.success(),
        "expected seed in stderr or network error, got: {stderr}"
    );
}

#[test]
fn seed_and_random_seed_conflict() {
    let output = Command::new(walletkit_bin())
        .args([
            "--seed",
            "0101010101010101010101010101010101010101010101010101010101010101",
            "--random-seed",
            "wallet",
            "paths",
        ])
        .output()
        .expect("failed to run");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot be used with"),
        "expected conflict error, got: {stderr}"
    );
}

#[test]
fn credential_list_on_empty_wallet() {
    let root = temp_root();

    Command::new(walletkit_bin())
        .args(["--root", root.path().to_str().unwrap(), "wallet", "init"])
        .output()
        .expect("failed init");

    let output = Command::new(walletkit_bin())
        .args([
            "--root",
            root.path().to_str().unwrap(),
            "credential",
            "list",
        ])
        .output()
        .expect("failed to run");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains("No credentials stored") || stderr.contains("not initialized"),
        "expected empty list or not-initialized error, stdout: {stdout}, stderr: {stderr}"
    );
}

#[test]
fn credential_list_json_on_empty_wallet() {
    let root = temp_root();

    Command::new(walletkit_bin())
        .args(["--root", root.path().to_str().unwrap(), "wallet", "init"])
        .output()
        .expect("failed init");

    let output = Command::new(walletkit_bin())
        .args([
            "--root",
            root.path().to_str().unwrap(),
            "--json",
            "credential",
            "list",
        ])
        .output()
        .expect("failed to run");

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let parsed: serde_json::Value =
            serde_json::from_str(&stdout).expect("invalid json");
        assert_eq!(parsed["ok"], true);
        assert!(parsed["data"].is_array(), "expected data to be an array");
        assert_eq!(parsed["data"].as_array().unwrap().len(), 0);
    }
}

#[test]
fn credential_delete_nonexistent_id() {
    let root = temp_root();

    Command::new(walletkit_bin())
        .args(["--root", root.path().to_str().unwrap(), "wallet", "init"])
        .output()
        .expect("failed init");

    let output = Command::new(walletkit_bin())
        .args([
            "--root",
            root.path().to_str().unwrap(),
            "credential",
            "delete",
            "--credential-id",
            "99999",
        ])
        .output()
        .expect("failed to run");

    // Should either succeed (idempotent delete) or fail with a clear error — not panic.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("panicked"),
        "unexpected panic on nonexistent credential delete: {stderr}"
    );
}
