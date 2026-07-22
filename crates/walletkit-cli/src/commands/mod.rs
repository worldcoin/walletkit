//! CLI command definitions and dispatch.

mod auth;
mod credential;
mod proof;
mod recovery_agent;
mod recovery_binding;
mod setup;
mod wallet;
use std::path::PathBuf;
use std::sync::Arc;

use alloy_core::primitives::Address;
use clap::{Parser, Subcommand};
use eyre::WrapErr as _;
use world_id_core::primitives::Config;

use walletkit_core::storage::{cache_embedded_groth16_material, CredentialStore};
use walletkit_core::{Authenticator, Groth16Materials};

use walletkit_testkit::env::DEFAULT_WORLDCHAIN_RPC_URL;
use walletkit_testkit::storage::create_fs_credential_store;
use walletkit_testkit::utils::now_secs;

/// `WalletKit` CLI — developer tool for World ID wallet operations.
#[derive(Parser)]
#[command(name = "walletkit", version, about)]
#[allow(clippy::struct_excessive_bools)]
pub struct Cli {
    /// Wallet data directory.
    #[arg(long, env = "WALLETKIT_ROOT", global = true)]
    pub root: Option<PathBuf>,

    /// 32-byte authenticator seed as hex (required for auth commands).
    #[arg(
        long,
        env = "WALLETKIT_SEED",
        global = true,
        conflicts_with = "random_seed"
    )]
    pub seed: Option<String>,

    /// Generate a fresh random seed for quick testing.
    #[arg(long, global = true, conflicts_with = "seed")]
    pub random_seed: bool,

    /// Environment (staging or production).
    #[arg(
        long,
        env = "WALLETKIT_ENVIRONMENT",
        default_value = "staging",
        global = true
    )]
    pub environment: String,

    /// Region for OPRF/indexer node selection (eu, us, ap).
    #[arg(long, env = "WALLETKIT_REGION", global = true)]
    pub region: Option<String>,

    /// Path to a World ID authenticator network config JSON file
    /// (overrides `--environment` and `--region`).
    #[arg(
        long = "authenticator-config",
        env = "WALLETKIT_AUTHENTICATOR_CONFIG",
        global = true,
        conflicts_with_all = ["environment", "region"]
    )]
    pub authenticator_config: Option<PathBuf>,

    /// Route default-config init/register through OHTTP (opt-in).
    #[arg(
        long,
        env = "WALLETKIT_OHTTP_DEFAULTS",
        global = true,
        conflicts_with = "authenticator_config"
    )]
    pub ohttp_defaults: bool,

    /// RPC URL for World Chain.
    #[arg(long, env = "WORLDCHAIN_RPC_URL", global = true)]
    pub rpc_url: Option<String>,

    /// Emit machine-readable JSON output.
    #[arg(long, global = true)]
    pub json: bool,

    /// Enable debug logging.
    #[arg(long, global = true)]
    pub verbose: bool,

    /// Print per-network-call latency summary after the command.
    #[arg(long, global = true)]
    pub latency: bool,

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
    /// Recovery agent management (initiate, execute, cancel updates).
    #[command(name = "recovery-agent-update")]
    RecoveryAgent {
        #[command(subcommand)]
        action: recovery_agent::RecoveryAgentCommand,
    },
    /// Recovery binding management.
    #[command(name = "recovery-binding")]
    RecoveryBinding {
        #[command(subcommand)]
        action: recovery_binding::RecoveryBindingCommand,
    },
    /// Initialize wallet and register account in one step.
    Setup {
        /// Poll interval in seconds while waiting for registration.
        #[arg(long, default_value = "5")]
        poll_interval: u64,
    },
}

/// Resolves the wallet root directory, defaulting to `~/.walletkit`.
fn resolve_root(cli: &Cli) -> eyre::Result<PathBuf> {
    if let Some(ref root) = cli.root {
        Ok(root.clone())
    } else {
        let home = dirs::home_dir()
            .ok_or_else(|| eyre::eyre!("cannot determine home directory"))?;
        Ok(home.join(".walletkit"))
    }
}

/// Resolves the authenticator seed from `--seed` or `--random-seed`.
fn resolve_seed(cli: &Cli) -> eyre::Result<Vec<u8>> {
    if let Some(ref hex_seed) = cli.seed {
        let bytes = hex::decode(hex_seed.trim_start_matches("0x"))
            .wrap_err("invalid hex seed")?;
        eyre::ensure!(
            bytes.len() == 32,
            "seed must be exactly 32 bytes, got {}",
            bytes.len()
        );
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
        // Fallback: read persisted seed from <root>/seed
        let root = resolve_root(cli)?;
        let seed_path = root.join("seed");
        if seed_path.exists() {
            let hex_str = std::fs::read_to_string(&seed_path)
                .wrap_err("failed to read seed file")?;
            let bytes =
                hex::decode(hex_str.trim()).wrap_err("invalid hex in seed file")?;
            eyre::ensure!(
                bytes.len() == 32,
                "seed file must contain exactly 32 bytes, got {}",
                bytes.len()
            );
            Ok(bytes)
        } else {
            eyre::bail!(
                "no seed found; run `walletkit wallet init` first, or pass --seed"
            )
        }
    }
}

/// Resolves the `Environment` enum from the CLI string.
fn resolve_environment(cli: &Cli) -> eyre::Result<walletkit_core::Environment> {
    match cli.environment.to_lowercase().as_str() {
        "staging" => Ok(walletkit_core::Environment::Staging),
        "production" => Ok(walletkit_core::Environment::Production),
        other => eyre::bail!("unknown environment: {other}"),
    }
}

/// Resolves the optional `Region` from the CLI string.
fn resolve_region(cli: &Cli) -> eyre::Result<Option<walletkit_core::Region>> {
    match cli.region.as_deref() {
        None => Ok(None),
        Some("eu") => Ok(Some(walletkit_core::Region::Eu)),
        Some("us") => Ok(Some(walletkit_core::Region::Us)),
        Some("ap") => Ok(Some(walletkit_core::Region::Ap)),
        Some(other) => eyre::bail!("unknown region: {other}"),
    }
}

/// Reads the authenticator config JSON file, if `--authenticator-config` was provided.
pub fn resolve_config(cli: &Cli) -> eyre::Result<Option<String>> {
    match &cli.authenticator_config {
        Some(path) => {
            let json = std::fs::read_to_string(path).wrap_err_with(|| {
                format!(
                    "failed to read authenticator config file {}",
                    path.display()
                )
            })?;
            Ok(Some(json))
        }
        None => Ok(None),
    }
}

/// Builds a World ID [`Config`] from CLI flags (custom JSON or environment defaults).
///
/// # Errors
///
/// Returns an error if the authenticator config file cannot be read or parsed, if
/// `--environment` / `--region` are invalid, or if default config construction fails.
fn resolve_built_config(cli: &Cli) -> eyre::Result<Config> {
    if let Some(config_json) = resolve_config(cli)? {
        Config::from_json(&config_json).wrap_err("invalid authenticator config JSON")
    } else {
        let environment = resolve_environment(cli)?;
        let region = resolve_region(cli)?;
        if cli.ohttp_defaults {
            walletkit_core::defaults::default_config_with_ohttp(
                &environment,
                cli.rpc_url.clone(),
                region,
            )
        } else {
            walletkit_core::defaults::default_config(
                &environment,
                cli.rpc_url.clone(),
                region,
            )
        }
        .wrap_err("failed to build World ID config")
    }
}

/// Resolves the `WorldIDVerifier` address for on-chain proof verification.
///
/// Prefers an explicit override, otherwise maps known staging/production registry
/// addresses from `config` to the matching verifier. Unknown registries require
/// `--verifier-address`.
///
/// # Errors
///
/// Returns an error if the override is not a valid address, or if the config's
/// registry is not a known staging/production registry and no override was given.
fn resolve_verifier_address(
    verifier_address: Option<&str>,
    config: &Config,
) -> eyre::Result<Address> {
    if let Some(addr) = verifier_address {
        return addr.parse::<Address>().wrap_err("invalid verifier address");
    }

    let registry = *config.registry_address();
    if registry == walletkit_core::defaults::STAGING_WORLD_ID_REGISTRY {
        Ok(walletkit_core::defaults::WORLD_ID_VERIFIER_STAGING)
    } else if registry == walletkit_core::defaults::WORLD_ID_REGISTRY {
        Ok(walletkit_core::defaults::WORLD_ID_VERIFIER_PRODUCTION)
    } else {
        eyre::bail!(
            "cannot infer WorldIDVerifier from registry {registry}; \
             pass --verifier-address"
        )
    }
}

/// Resolves the World Chain RPC URL used for on-chain verification.
///
/// Prefers `--rpc-url`, then the RPC embedded in `config`, then the testkit
/// default Alchemy endpoint.
#[must_use]
fn resolve_test_rpc_url(cli: &Cli, config: &Config) -> String {
    if let Some(rpc_url) = cli.rpc_url.as_deref() {
        return rpc_url.to_string();
    }
    config.rpc_url().map_or_else(
        || DEFAULT_WORLDCHAIN_RPC_URL.to_string(),
        ToString::to_string,
    )
}

/// Initializes an authenticator and credential store from CLI args.
pub async fn init_authenticator(
    cli: &Cli,
) -> eyre::Result<(Arc<Authenticator>, Arc<CredentialStore>)> {
    let root = resolve_root(cli)?;
    let seed = resolve_seed(cli)?;
    let config_json = resolve_config(cli)?;

    let store = create_fs_credential_store(&root)?;
    let paths = store.storage_paths()?;
    cache_embedded_groth16_material(&paths)?;
    let materials = Arc::new(
        Groth16Materials::from_cache(Arc::new(paths.clone()))
            .wrap_err("failed to load cached Groth16 materials")?,
    );

    let authenticator = if let Some(ref config) = config_json {
        Authenticator::init(&seed, config, materials.clone(), store.clone())
            .await
            .wrap_err("authenticator init failed")?
    } else {
        let config = resolve_built_config(cli)?;
        Authenticator::init_with_config(&seed, config, materials.clone(), store.clone())
            .await
            .wrap_err("authenticator init failed")?
    };

    let now = now_secs();
    authenticator
        .init_storage(now)
        .wrap_err("storage init failed")?;

    Ok((Arc::new(authenticator), store))
}

/// Top-level command dispatch.
pub async fn run(cli: Cli) -> eyre::Result<()> {
    match &cli.command {
        Command::Wallet { action } => wallet::run(&cli, action).await,
        Command::Auth { action } => auth::run(&cli, action).await,
        Command::Credential { action } => credential::run(&cli, action).await,
        Command::Proof { action } => proof::run(&cli, action).await,
        Command::RecoveryAgent { action } => recovery_agent::run(&cli, action).await,
        Command::RecoveryBinding { action } => {
            let environment = resolve_environment(&cli)?;
            recovery_binding::run(&cli, action, &environment).await
        }
        Command::Setup { poll_interval } => setup::run(&cli, *poll_interval).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use walletkit_core::Environment;
    use world_id_core::primitives::ServiceEndpoint;

    fn parse_cli(args: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once("walletkit").chain(args.iter().copied()))
            .expect("CLI should parse")
    }

    #[test]
    fn resolve_built_config_honors_region_eu() {
        let cli = parse_cli(&["--region", "eu", "auth", "info"]);
        let config = resolve_built_config(&cli).expect("config");
        let expected = walletkit_core::defaults::default_config(
            &Environment::Staging,
            None,
            Some(walletkit_core::Region::Eu),
        )
        .unwrap();
        assert_eq!(config.indexer_url(), expected.indexer_url());
    }

    #[test]
    fn resolve_built_config_defaults_region_like_authenticator() {
        let cli = parse_cli(&["auth", "info"]);
        let config = resolve_built_config(&cli).expect("config");
        let expected =
            walletkit_core::defaults::default_config(&Environment::Staging, None, None)
                .unwrap();
        assert_eq!(config.indexer_url(), expected.indexer_url());
    }

    #[test]
    fn resolve_built_config_honors_ohttp_defaults() {
        let cli = parse_cli(&["--ohttp-defaults", "auth", "info"]);
        let config = resolve_built_config(&cli).expect("config");
        assert!(matches!(config.indexer(), ServiceEndpoint::Ohttp { .. }));
        assert!(matches!(config.gateway(), ServiceEndpoint::Ohttp { .. }));
    }

    #[test]
    fn resolve_built_config_uses_authenticator_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        let staging = walletkit_core::defaults::default_config(
            &Environment::Staging,
            Some("https://example.invalid/rpc".to_string()),
            Some(walletkit_core::Region::Us),
        )
        .unwrap();
        std::fs::write(&path, serde_json::to_string(&staging).unwrap()).unwrap();

        let cli = parse_cli(&[
            "--authenticator-config",
            path.to_str().unwrap(),
            "auth",
            "info",
        ]);
        let config = resolve_built_config(&cli).expect("config");
        assert_eq!(
            config.rpc_url().map(ToString::to_string).as_deref(),
            Some("https://example.invalid/rpc")
        );
        assert_eq!(config.indexer_url(), staging.indexer_url());
    }

    #[test]
    fn old_config_flag_is_rejected() {
        let result =
            Cli::try_parse_from(["walletkit", "--config", "x.json", "auth", "info"]);
        let Err(err) = result else {
            panic!("expected --config to be rejected");
        };
        let message = err.to_string();
        assert!(
            message.contains("unexpected argument") || message.contains("--config"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn resolve_verifier_address_maps_known_registries() {
        let staging =
            walletkit_core::defaults::default_config(&Environment::Staging, None, None)
                .unwrap();
        assert_eq!(
            resolve_verifier_address(None, &staging).unwrap(),
            walletkit_core::defaults::WORLD_ID_VERIFIER_STAGING
        );

        let production = walletkit_core::defaults::default_config(
            &Environment::Production,
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            resolve_verifier_address(None, &production).unwrap(),
            walletkit_core::defaults::WORLD_ID_VERIFIER_PRODUCTION
        );
    }

    #[test]
    fn resolve_verifier_address_override_wins() {
        let staging =
            walletkit_core::defaults::default_config(&Environment::Staging, None, None)
                .unwrap();
        let override_addr = "0x0000000000000000000000000000000000000001";
        assert_eq!(
            resolve_verifier_address(Some(override_addr), &staging).unwrap(),
            override_addr.parse::<Address>().unwrap()
        );
    }

    #[test]
    fn resolve_verifier_address_errors_for_unknown_registry() {
        let unknown = Config::new(
            None,
            480,
            "0x1111111111111111111111111111111111111111"
                .parse()
                .unwrap(),
            ServiceEndpoint::direct("https://example.invalid/indexer".to_string()),
            ServiceEndpoint::direct("https://example.invalid/gateway".to_string()),
            vec!["https://example.invalid/oprf".to_string()],
            3,
        )
        .unwrap();

        let err = resolve_verifier_address(None, &unknown).unwrap_err();
        assert!(
            err.to_string().contains("--verifier-address"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn resolve_test_rpc_url_prefers_cli_over_config() {
        let config = walletkit_core::defaults::default_config(
            &Environment::Staging,
            Some("https://from-config.invalid/rpc".to_string()),
            None,
        )
        .unwrap();
        let cli =
            parse_cli(&["--rpc-url", "https://from-cli.invalid/rpc", "auth", "info"]);
        assert_eq!(
            resolve_test_rpc_url(&cli, &config),
            "https://from-cli.invalid/rpc"
        );
    }

    #[test]
    fn resolve_test_rpc_url_falls_back_to_config() {
        let config = walletkit_core::defaults::default_config(
            &Environment::Staging,
            Some("https://from-config.invalid/rpc".to_string()),
            None,
        )
        .unwrap();
        let mut cli = parse_cli(&["auth", "info"]);
        // Ignore any ambient WORLDCHAIN_RPC_URL (clap reads it via `env`); this
        // test exercises the no-flag fallback to config.
        cli.rpc_url = None;
        assert_eq!(
            resolve_test_rpc_url(&cli, &config),
            "https://from-config.invalid/rpc"
        );
    }
}
