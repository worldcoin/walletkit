//! `walletkit wallet` subcommands — local setup and inspection.

use clap::Subcommand;
use walletkit_core::storage::{cache_embedded_groth16_material, StoragePaths};

use crate::output;
use crate::provider::create_fs_credential_store;

use super::{resolve_root, Cli};

#[derive(Subcommand)]
pub enum WalletCommand {
    /// Initialize the wallet: create storage directories and cache Groth16 material.
    Init,
    /// Print resolved storage paths.
    Paths,
    /// Check wallet health: root exists, Groth16 cached, databases openable.
    Doctor,
    /// Export the vault to a plaintext backup file.
    Export {
        /// Destination directory for the backup file.
        #[arg(long)]
        dest: String,
    },
    /// Import credentials from a vault backup file.
    Import {
        /// Path to the backup file.
        #[arg(long)]
        backup: String,
    },
    /// Permanently delete ALL credentials. Requires --confirm.
    DangerClear {
        /// Confirm the destructive operation.
        #[arg(long)]
        confirm: bool,
    },
}

fn run_init(cli: &Cli) -> eyre::Result<()> {
    let root = resolve_root(cli)?;
    std::fs::create_dir_all(&root)?;
    let store = create_fs_credential_store(&root)?;
    let paths = store.storage_paths()?;
    cache_embedded_groth16_material(paths.clone())?;

    let data = serde_json::json!({
        "root": root.display().to_string(),
        "worldid_dir": paths.worldid_dir_path_string(),
        "vault_db": paths.vault_db_path_string(),
        "cache_db": paths.cache_db_path_string(),
        "groth16_dir": paths.groth16_dir_path_string(),
    });

    if cli.json {
        output::print_json_data(&data, true);
    } else {
        println!("Wallet initialized at {}", root.display());
        println!("  worldid dir:  {}", paths.worldid_dir_path_string());
        println!("  vault db:     {}", paths.vault_db_path_string());
        println!("  cache db:     {}", paths.cache_db_path_string());
        println!("  groth16 dir:  {}", paths.groth16_dir_path_string());
    }
    Ok(())
}

fn run_paths(cli: &Cli) -> eyre::Result<()> {
    let root = resolve_root(cli)?;
    let paths = StoragePaths::new(&root);
    let data = serde_json::json!({
        "root": paths.root().display().to_string(),
        "worldid_dir": paths.worldid_dir().display().to_string(),
        "vault_db": paths.vault_db_path().display().to_string(),
        "cache_db": paths.cache_db_path().display().to_string(),
        "lock": paths.lock_path().display().to_string(),
        "groth16_dir": paths.groth16_dir().display().to_string(),
        "query_zkey": paths.query_zkey_path().display().to_string(),
        "nullifier_zkey": paths.nullifier_zkey_path().display().to_string(),
        "query_graph": paths.query_graph_path().display().to_string(),
        "nullifier_graph": paths.nullifier_graph_path().display().to_string(),
    });

    output::print_json_data(&data, cli.json);
    Ok(())
}

fn run_doctor(cli: &Cli) -> eyre::Result<()> {
    let root = resolve_root(cli)?;
    let paths = StoragePaths::new(&root);
    let mut issues: Vec<String> = Vec::new();

    let root_exists = root.exists();
    if !root_exists {
        issues.push(format!("root directory missing: {}", root.display()));
    }

    let groth16_ok = paths.query_zkey_path().exists()
        && paths.nullifier_zkey_path().exists()
        && paths.query_graph_path().exists()
        && paths.nullifier_graph_path().exists();
    if !groth16_ok {
        issues.push(
            "Groth16 material not cached (run `walletkit wallet init`)".to_string(),
        );
    }

    let vault_ok = paths.vault_db_path().exists();
    let cache_ok = paths.cache_db_path().exists();
    let healthy = issues.is_empty();

    if cli.json {
        let data = serde_json::json!({
            "healthy": healthy,
            "root_exists": root_exists,
            "groth16_cached": groth16_ok,
            "vault_db_exists": vault_ok,
            "cache_db_exists": cache_ok,
            "issues": issues,
        });
        output::print_json_data(&data, true);
    } else if healthy {
        println!("Wallet is healthy at {}", root.display());
        println!("  groth16 cached: yes");
        println!(
            "  vault db:       {}",
            if vault_ok { "present" } else { "missing" }
        );
        println!(
            "  cache db:       {}",
            if cache_ok { "present" } else { "missing" }
        );
    } else {
        println!("Wallet issues found:");
        for issue in &issues {
            println!("  - {issue}");
        }
        if vault_ok {
            println!("  vault db: present");
        }
        if cache_ok {
            println!("  cache db: present");
        }
    }
    Ok(())
}

fn run_export(cli: &Cli, dest: &str) -> eyre::Result<()> {
    let root = resolve_root(cli)?;
    let store = create_fs_credential_store(&root)?;
    let backup_path = store
        .export_vault_for_backup(dest.to_string())
        .map_err(|e| eyre::eyre!("export failed: {e}"))?;

    if cli.json {
        output::print_json_data(
            &serde_json::json!({ "backup_path": backup_path }),
            true,
        );
    } else {
        println!("Vault exported to {backup_path}");
    }
    Ok(())
}

fn run_import(cli: &Cli, backup: &str) -> eyre::Result<()> {
    let root = resolve_root(cli)?;
    let store = create_fs_credential_store(&root)?;
    store
        .import_vault_from_backup(backup.to_string())
        .map_err(|e| eyre::eyre!("import failed: {e}"))?;

    output::print_success("Vault imported successfully.", cli.json);
    Ok(())
}

fn run_danger_clear(cli: &Cli, confirm: bool) -> eyre::Result<()> {
    if !confirm {
        return Err(eyre::eyre!(
            "this will permanently delete ALL credentials; pass --confirm to proceed"
        ));
    }

    let root = resolve_root(cli)?;
    let store = create_fs_credential_store(&root)?;
    let deleted = store
        .danger_delete_all_credentials()
        .map_err(|e| eyre::eyre!("danger clear failed: {e}"))?;

    if cli.json {
        output::print_json_data(&serde_json::json!({ "deleted": deleted }), true);
    } else {
        println!("Deleted {deleted} credential(s).");
    }
    Ok(())
}

pub fn run(cli: &Cli, action: &WalletCommand) -> eyre::Result<()> {
    match action {
        WalletCommand::Init => run_init(cli),
        WalletCommand::Paths => run_paths(cli),
        WalletCommand::Doctor => run_doctor(cli),
        WalletCommand::Export { dest } => run_export(cli, dest),
        WalletCommand::Import { backup } => run_import(cli, backup),
        WalletCommand::DangerClear { confirm } => run_danger_clear(cli, *confirm),
    }
}
