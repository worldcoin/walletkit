//! `walletkit auth` subcommands — authenticator lifecycle and registration.

use clap::Subcommand;
use walletkit_core::{InitializingAuthenticator, RegistrationStatus};

use crate::output;

use super::{
    init_authenticator, resolve_environment, resolve_region, resolve_seed, Cli,
};

#[derive(Subcommand)]
pub enum AuthCommand {
    /// Register a new World ID (returns immediately).
    Register {
        /// Recovery address (hex).
        #[arg(long)]
        recovery_address: Option<String>,
    },
    /// Register a new World ID and poll until finalized.
    RegisterWait {
        /// Recovery address (hex).
        #[arg(long)]
        recovery_address: Option<String>,
        /// Poll interval in seconds.
        #[arg(long, default_value = "5")]
        poll_interval: u64,
    },
    /// Initialize an authenticator for an already-registered World ID.
    Init,
    /// Print authenticator info (leaf index, onchain address, packed account data).
    Info,
    /// Fetch packed account data from on-chain and compare with local.
    RemoteAccountData,
    /// Generate a credential blinding factor via OPRF nodes.
    BlindingFactor {
        /// Issuer schema ID.
        #[arg(long)]
        issuer_schema_id: u64,
    },
    /// Compute a credential sub from a blinding factor.
    ComputeSub {
        /// Blinding factor as hex.
        #[arg(long)]
        blinding_factor: String,
    },
}

async fn run_register(cli: &Cli, recovery_address: Option<&str>) -> eyre::Result<()> {
    let seed = resolve_seed(cli)?;
    let env = resolve_environment(cli)?;
    let region = resolve_region(cli)?;

    let init_auth = InitializingAuthenticator::register_with_defaults(
        &seed,
        cli.rpc_url.clone(),
        &env,
        region,
        recovery_address.map(String::from),
    )
    .await
    .map_err(|e| eyre::eyre!("registration failed: {e}"))?;

    let status = init_auth
        .poll_status()
        .await
        .map_err(|e| eyre::eyre!("poll failed: {e}"))?;
    let status_str = format!("{status:?}");

    if cli.json {
        output::print_json_data(&serde_json::json!({ "status": status_str }), true);
    } else {
        println!("Registration submitted. Status: {status_str}");
    }
    Ok(())
}

async fn run_register_wait(
    cli: &Cli,
    recovery_address: Option<&str>,
    poll_interval: u64,
) -> eyre::Result<()> {
    let seed = resolve_seed(cli)?;
    let env = resolve_environment(cli)?;
    let region = resolve_region(cli)?;

    let init_auth = InitializingAuthenticator::register_with_defaults(
        &seed,
        cli.rpc_url.clone(),
        &env,
        region,
        recovery_address.map(String::from),
    )
    .await
    .map_err(|e| eyre::eyre!("registration failed: {e}"))?;

    loop {
        let status = init_auth
            .poll_status()
            .await
            .map_err(|e| eyre::eyre!("poll failed: {e}"))?;

        match &status {
            RegistrationStatus::Finalized => {
                if cli.json {
                    output::print_json_data(
                        &serde_json::json!({ "status": "Finalized" }),
                        true,
                    );
                } else {
                    println!("Registration finalized.");
                }
                return Ok(());
            }
            RegistrationStatus::Failed { error, error_code } => {
                return Err(eyre::eyre!(
                    "registration failed: {error} (code: {error_code:?})"
                ));
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

async fn run_info(cli: &Cli) -> eyre::Result<()> {
    let (authenticator, _store) = init_authenticator(cli).await?;

    let data = serde_json::json!({
        "leaf_index": authenticator.leaf_index(),
        "onchain_address": authenticator.onchain_address(),
        "packed_account_data": authenticator.packed_account_data().to_string(),
    });

    output::print_json_data(&data, cli.json);
    Ok(())
}

pub async fn run(cli: &Cli, action: &AuthCommand) -> eyre::Result<()> {
    match action {
        AuthCommand::Register { recovery_address } => {
            run_register(cli, recovery_address.as_deref()).await
        }
        AuthCommand::RegisterWait {
            recovery_address,
            poll_interval,
        } => run_register_wait(cli, recovery_address.as_deref(), *poll_interval).await,
        AuthCommand::Init => {
            let (authenticator, _store) = init_authenticator(cli).await?;
            if cli.json {
                let data = serde_json::json!({
                    "leaf_index": authenticator.leaf_index(),
                    "onchain_address": authenticator.onchain_address(),
                    "packed_account_data": authenticator.packed_account_data().to_string(),
                });
                output::print_json_data(&data, true);
            } else {
                println!("Authenticator initialized.");
                println!("  leaf index:          {}", authenticator.leaf_index());
                println!("  onchain address:     {}", authenticator.onchain_address());
                println!(
                    "  packed account data: {}",
                    authenticator.packed_account_data()
                );
            }
            Ok(())
        }
        AuthCommand::Info => run_info(cli).await,
        AuthCommand::RemoteAccountData => {
            let (authenticator, _store) = init_authenticator(cli).await?;
            let remote = authenticator
                .get_packed_account_data_remote()
                .await
                .map_err(|e| eyre::eyre!("remote fetch failed: {e}"))?;
            let local = authenticator.packed_account_data();
            let matches = remote.to_string() == local.to_string();

            let data = serde_json::json!({
                "local": local.to_string(),
                "remote": remote.to_string(),
                "matches": matches,
            });

            if cli.json {
                output::print_json_data(&data, true);
            } else {
                println!("Local packed account data:  {local}");
                println!("Remote packed account data: {remote}");
                println!("Match: {}", if matches { "yes" } else { "NO" });
            }
            Ok(())
        }
        AuthCommand::BlindingFactor { issuer_schema_id } => {
            let (authenticator, _store) = init_authenticator(cli).await?;
            let bf = authenticator
                .generate_credential_blinding_factor_remote(*issuer_schema_id)
                .await
                .map_err(|e| eyre::eyre!("blinding factor generation failed: {e}"))?;
            let hex = bf.to_hex_string();

            if cli.json {
                output::print_json_data(
                    &serde_json::json!({ "blinding_factor": hex }),
                    true,
                );
            } else {
                println!("{hex}");
            }
            Ok(())
        }
        AuthCommand::ComputeSub { blinding_factor } => {
            let (authenticator, _store) = init_authenticator(cli).await?;
            let bf = walletkit_core::FieldElement::try_from_hex_string(blinding_factor)
                .map_err(|e| eyre::eyre!("invalid blinding factor: {e}"))?;
            let sub = authenticator.compute_credential_sub(&bf);
            let hex = sub.to_hex_string();

            if cli.json {
                output::print_json_data(&serde_json::json!({ "sub": hex }), true);
            } else {
                println!("{hex}");
            }
            Ok(())
        }
    }
}
