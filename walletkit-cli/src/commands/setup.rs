//! `walletkit setup` — one-shot wallet initialization and account registration.

use eyre::WrapErr as _;
use walletkit_core::error::WalletKitError;
use walletkit_core::storage::cache_embedded_groth16_material;
use walletkit_core::{InitializingAuthenticator, RegistrationStatus};

use crate::output;
use crate::provider::create_fs_credential_store;

use super::{resolve_config, resolve_environment, resolve_region, resolve_root, Cli};

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
    let config_json = resolve_config(cli)?;

    let result = if let Some(ref config) = config_json {
        InitializingAuthenticator::register(
            &seed, config, None, // no recovery address
        )
        .await
    } else {
        let env = resolve_environment(cli)?;
        let region = resolve_region(cli)?;
        InitializingAuthenticator::register_with_defaults(
            &seed,
            cli.rpc_url.clone(),
            &env,
            region,
            None, // no recovery address
        )
        .await
    };

    let init_auth = match result {
        Ok(auth) => auth,
        Err(WalletKitError::NetworkError { ref error, .. })
            if error.contains("authenticator_already_exists") =>
        {
            let data = serde_json::json!({
                "seed": seed_hex,
                "root": root.display().to_string(),
                "status": "AlreadyRegistered",
            });
            if cli.json {
                output::print_json_data(&data, true);
            } else {
                println!("Account already registered.");
            }
            return Ok(());
        }
        Err(e) => return Err(e).wrap_err("registration failed"),
    };

    if !cli.json {
        eprintln!("Registration submitted, waiting for finalization...");
    }

    loop {
        let status = init_auth.poll_status().await.wrap_err("poll failed")?;

        match &status {
            RegistrationStatus::Finalized => {
                let data = serde_json::json!({
                    "seed": seed_hex,
                    "root": root.display().to_string(),
                    "status": "Finalized",
                });
                if cli.json {
                    output::print_json_data(&data, true);
                } else {
                    println!("Setup complete. Account registered and finalized.");
                    println!("  root: {}", root.display());
                    println!("  seed: {seed_hex}");
                }
                return Ok(());
            }
            RegistrationStatus::Failed { error, error_code } => {
                eyre::bail!("registration failed: {error} (code: {error_code:?})");
            }
            _ => {
                let status_str = format!("{status:?}");
                if !cli.json {
                    eprintln!(
                        "Status: {status_str} — polling again in {poll_interval}s..."
                    );
                }
                tokio::time::sleep(std::time::Duration::from_secs(poll_interval)).await;
            }
        }
    }
}
