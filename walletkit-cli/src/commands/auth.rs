//! `walletkit auth` subcommands — authenticator lifecycle and registration.

use clap::Subcommand;
use eyre::WrapErr as _;
use walletkit_core::error::WalletKitError;
use walletkit_core::{InitializingAuthenticator, RegistrationStatus};

use crate::output;

use super::{
    init_authenticator, resolve_config, resolve_environment, resolve_region,
    resolve_seed, Cli,
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
}

async fn run_register(cli: &Cli, recovery_address: Option<&str>) -> eyre::Result<()> {
    let seed = resolve_seed(cli)?;
    let config_json = resolve_config(cli)?;

    let result = if let Some(ref config) = config_json {
        InitializingAuthenticator::register(
            &seed,
            config,
            recovery_address.map(String::from),
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
            recovery_address.map(String::from),
        )
        .await
    };

    let init_auth = match result {
        Ok(auth) => auth,
        Err(WalletKitError::NetworkError { ref error, .. })
            if error.contains("authenticator_already_exists") =>
        {
            output::print_success("Already registered.", cli.json);
            return Ok(());
        }
        Err(e) => return Err(e).wrap_err("registration failed"),
    };

    let status = init_auth
        .poll_status()
        .await
        .wrap_err("poll failed")?;
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
    let config_json = resolve_config(cli)?;

    let result = if let Some(ref config) = config_json {
        InitializingAuthenticator::register(
            &seed,
            config,
            recovery_address.map(String::from),
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
            recovery_address.map(String::from),
        )
        .await
    };

    let init_auth = match result {
        Ok(auth) => auth,
        Err(WalletKitError::NetworkError { ref error, .. })
            if error.contains("authenticator_already_exists") =>
        {
            output::print_success("Already registered.", cli.json);
            return Ok(());
        }
        Err(e) => return Err(e).wrap_err("registration failed"),
    };

    loop {
        let status = init_auth
            .poll_status()
            .await
            .wrap_err("poll failed")?;

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
                .wrap_err("remote fetch failed")?;
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
    }
}
