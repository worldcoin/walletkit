//! `walletkit wallet` subcommands — local setup and inspection.

use clap::Subcommand;
use eyre::WrapErr as _;
use walletkit_core::storage::{cache_embedded_groth16_material, StoragePaths};

use crate::output;
use crate::provider::create_fs_credential_store;

use super::{init_authenticator, resolve_root, Cli};

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
    cache_embedded_groth16_material(&paths)?;

    // Generate and persist a 32-byte seed if one doesn't exist yet.
    let seed_path = root.join("seed");
    let seed_hex = if seed_path.exists() {
        std::fs::read_to_string(&seed_path)?.trim().to_string()
    } else {
        use rand::RngCore;
        let mut seed = vec![0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        let hex = hex::encode(&seed);
        std::fs::write(&seed_path, &hex)?;
        hex
    };

    let data = serde_json::json!({
        "root": root.display().to_string(),
        "worldid_dir": paths.worldid_dir_path_string(),
        "groth16_dir": paths.groth16_dir_path_string(),
        "seed": seed_hex,
    });

    if cli.json {
        output::print_json_data(&data, true);
    } else {
        println!("Wallet initialized at {}", root.display());
        println!("  worldid dir:  {}", paths.worldid_dir_path_string());
        println!("  groth16 dir:  {}", paths.groth16_dir_path_string());
        println!("  seed:         {seed_hex}");
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
            if vault_ok {
                "present"
            } else {
                "not yet created (run auth register-wait)"
            }
        );
        println!(
            "  cache db:       {}",
            if cache_ok {
                "present"
            } else {
                "not yet created (run auth register-wait)"
            }
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

async fn run_export(cli: &Cli, dest: &str) -> eyre::Result<()> {
    let (_authenticator, store) = init_authenticator(cli).await?;
    let backup_bytes = store.export_vault_for_backup().wrap_err("export failed")?;

    let backup_path = std::path::Path::new(dest).join("vault_backup.bin");
    std::fs::write(&backup_path, &backup_bytes)
        .wrap_err("failed to write backup file")?;

    let backup_path = backup_path.display().to_string();
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

async fn run_import(cli: &Cli, backup: &str) -> eyre::Result<()> {
    let (_authenticator, store) = init_authenticator(cli).await?;
    let backup_bytes = std::fs::read(backup).wrap_err("failed to read backup file")?;
    store
        .import_vault_from_backup(&backup_bytes)
        .wrap_err("import failed")?;

    output::print_success("Vault imported successfully.", cli.json);
    Ok(())
}

async fn run_danger_clear(cli: &Cli, confirm: bool) -> eyre::Result<()> {
    eyre::ensure!(
        confirm,
        "this will permanently delete ALL credentials; pass --confirm to proceed"
    );

    let (_authenticator, store) = init_authenticator(cli).await?;
    let deleted = store
        .danger_delete_all_credentials()
        .wrap_err("danger clear failed")?;

    if cli.json {
        output::print_json_data(&serde_json::json!({ "deleted": deleted }), true);
    } else {
        println!("Deleted {deleted} credential(s).");
    }
    Ok(())
}

pub async fn run(cli: &Cli, action: &WalletCommand) -> eyre::Result<()> {
    match action {
        WalletCommand::Init => run_init(cli),
        WalletCommand::Paths => run_paths(cli),
        WalletCommand::Doctor => run_doctor(cli),
        WalletCommand::Export { dest } => run_export(cli, dest).await,
        WalletCommand::Import { backup } => run_import(cli, backup).await,
        WalletCommand::DangerClear { confirm } => run_danger_clear(cli, *confirm).await,
    }
}
