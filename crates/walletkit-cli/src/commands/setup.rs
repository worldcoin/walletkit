//! `walletkit setup` — one-shot wallet initialization and account registration.

use walletkit_core::storage::cache_embedded_groth16_material;

use crate::output;
use crate::provider::create_fs_credential_store;

use super::auth::{register_and_poll, RegisterOutcome};
use super::{resolve_root, Cli};

pub async fn run(cli: &Cli, poll_interval: u64) -> eyre::Result<()> {
    let root = resolve_root(cli)?;
    let seed_path = root.join("seed");

    // Fail if wallet already exists.
    eyre::ensure!(
        !seed_path.exists(),
        "wallet already exists at {}; use `walletkit auth register-wait` to register an existing wallet",
        root.display()
    );

    // --- wallet init ---
    std::fs::create_dir_all(&root)?;
    let store = create_fs_credential_store(&root)?;
    let paths = store.storage_paths()?;
    cache_embedded_groth16_material(&paths)?;

    // Generate and persist a 32-byte seed.
    let mut seed = vec![0u8; 32];
    {
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut seed);
    }
    let seed_hex = hex::encode(&seed);
    std::fs::write(&seed_path, &seed_hex)?;

    if !cli.json {
        eprintln!("Wallet initialized at {}", root.display());
        eprintln!("  seed: {seed_hex}");
    }

    // --- auth register-wait ---
    if !cli.json {
        eprintln!("Registration submitted, waiting for finalization...");
    }

    let outcome = register_and_poll(cli, &seed, None, poll_interval).await?;

    let status = match outcome {
        RegisterOutcome::Finalized => "Finalized",
        RegisterOutcome::AlreadyRegistered => "AlreadyRegistered",
    };

    let data = serde_json::json!({
        "seed": seed_hex,
        "root": root.display().to_string(),
        "status": status,
    });

    if cli.json {
        output::print_json_data(&data, true);
    } else {
        println!("Setup complete. Account registered and finalized.");
        println!("  root: {}", root.display());
        println!("  seed: {seed_hex}");
    }
    Ok(())
}
