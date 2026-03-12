//! CLI command definitions and dispatch.

mod auth;
mod credential;
mod proof;
mod wallet;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// `WalletKit` CLI — developer tool for World ID wallet operations.
#[derive(Parser)]
#[command(name = "walletkit", version, about)]
pub struct Cli {
    /// Wallet data directory.
    #[arg(long, env = "WALLETKIT_ROOT", global = true)]
    pub root: Option<PathBuf>,

    /// 32-byte authenticator seed as hex (required for auth commands).
    #[arg(long, env = "WALLETKIT_SEED", global = true, conflicts_with = "random_seed")]
    pub seed: Option<String>,

    /// Generate a fresh random seed for quick testing.
    #[arg(long, global = true, conflicts_with = "seed")]
    pub random_seed: bool,

    /// Environment (staging or production).
    #[arg(long, default_value = "staging", global = true)]
    pub environment: String,

    /// Region for OPRF/indexer node selection (eu, us, ap).
    #[arg(long, global = true)]
    pub region: Option<String>,

    /// RPC URL for World Chain.
    #[arg(long, env = "WORLDCHAIN_RPC_URL", global = true)]
    pub rpc_url: Option<String>,

    /// Emit machine-readable JSON output.
    #[arg(long, global = true)]
    pub json: bool,

    /// Enable debug logging.
    #[arg(long, global = true)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Local wallet setup and inspection.
    Wallet {
        #[command(subcommand)]
        action: wallet::WalletCommand,
    },
    /// Authenticator lifecycle and registration.
    Auth {
        #[command(subcommand)]
        action: auth::AuthCommand,
    },
    /// Credential management.
    Credential {
        #[command(subcommand)]
        action: credential::CredentialCommand,
    },
    /// Proof generation and inspection.
    Proof {
        #[command(subcommand)]
        action: proof::ProofCommand,
    },
}

/// Resolves the wallet root directory, defaulting to `~/.walletkit`.
fn resolve_root(cli: &Cli) -> eyre::Result<PathBuf> {
    if let Some(ref root) = cli.root {
        Ok(root.clone())
    } else {
        let home = dirs::home_dir().ok_or_else(|| eyre::eyre!("cannot determine home directory"))?;
        Ok(home.join(".walletkit"))
    }
}

/// Resolves the authenticator seed from `--seed` or `--random-seed`.
fn resolve_seed(cli: &Cli) -> eyre::Result<Vec<u8>> {
    if let Some(ref hex_seed) = cli.seed {
        let bytes = hex::decode(hex_seed.trim_start_matches("0x"))
            .map_err(|e| eyre::eyre!("invalid hex seed: {e}"))?;
        if bytes.len() != 32 {
            return Err(eyre::eyre!("seed must be exactly 32 bytes, got {}", bytes.len()));
        }
        Ok(bytes)
    } else if cli.random_seed {
        use rand::RngCore;
        let mut seed = vec![0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        if !cli.json {
            eprintln!("Generated random seed: 0x{}", hex::encode(&seed));
            eprintln!("Save this seed to reuse this wallet later.");
        }
        Ok(seed)
    } else {
        Err(eyre::eyre!("provide --seed <hex> or --random-seed"))
    }
}

/// Resolves the `Environment` enum from the CLI string.
fn resolve_environment(cli: &Cli) -> eyre::Result<walletkit_core::Environment> {
    match cli.environment.to_lowercase().as_str() {
        "staging" => Ok(walletkit_core::Environment::Staging),
        "production" => Ok(walletkit_core::Environment::Production),
        other => Err(eyre::eyre!("unknown environment: {other}")),
    }
}

/// Resolves the optional `Region` from the CLI string.
fn resolve_region(cli: &Cli) -> eyre::Result<Option<walletkit_core::Region>> {
    match cli.region.as_deref() {
        None => Ok(None),
        Some("eu") => Ok(Some(walletkit_core::Region::Eu)),
        Some("us") => Ok(Some(walletkit_core::Region::Us)),
        Some("ap") => Ok(Some(walletkit_core::Region::Ap)),
        Some(other) => Err(eyre::eyre!("unknown region: {other}")),
    }
}

/// Top-level command dispatch.
pub async fn run(cli: Cli) -> eyre::Result<()> {
    match &cli.command {
        Command::Wallet { action } => wallet::run(&cli, action),
        Command::Auth { action } => auth::run(&cli, action).await,
        Command::Credential { action } => credential::run(&cli, action).await,
        Command::Proof { action } => proof::run(&cli, action).await,
    }
}
