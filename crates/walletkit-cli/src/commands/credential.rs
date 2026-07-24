//! `walletkit credential` subcommands — credential management.

use std::io::Read;

use clap::{Subcommand, ValueEnum};
use eyre::WrapErr as _;
use walletkit_core::{Credential, FieldElement};
use walletkit_testkit::env::TestEnv;
use walletkit_testkit::issuer::import_credential;
use walletkit_testkit::utils::now_secs;
use walletkit_testkit::{issue_credential, CredentialType};

use crate::output;

use super::{init_authenticator, Cli};

#[derive(Clone, Copy, ValueEnum)]
pub enum TestCredentialIssuer {
    /// Hosted staging faux issuer (schema 128).
    Faux,
    /// Local `EdDSA` issuer registered on staging (schema 47).
    Local,
}

#[derive(Subcommand)]
pub enum CredentialCommand {
    /// Import a credential from a file or stdin and store it locally.
    Import {
        /// Path to credential JSON file, or `-` for stdin.
        #[arg(long)]
        credential: String,
        /// Blinding factor as hex. When omitted, generated via OPRF.
        #[arg(long)]
        blinding_factor: Option<String>,
        /// Optional associated data (base64-encoded).
        #[arg(long)]
        associated_data: Option<String>,
    },
    /// List stored credentials.
    List {
        /// Filter by issuer schema ID.
        #[arg(long)]
        issuer_schema_id: Option<u64>,
    },
    /// Show details of the latest credential for an issuer schema.
    Show {
        /// Issuer schema ID to look up.
        #[arg(long)]
        issuer_schema_id: u64,
    },
    /// Delete a credential by ID.
    Delete {
        /// Credential ID to delete.
        #[arg(long)]
        credential_id: u64,
    },
    /// Issue a credential from a staging test issuer.
    IssueTest {
        /// Test issuer to use.
        #[arg(long, value_enum, default_value = "faux")]
        issuer: TestCredentialIssuer,
        /// Credential lifetime in seconds (local issuer only; defaults to 3600).
        #[arg(long)]
        expires_in: Option<u64>,
    },
    /// Generate or accept a blinding factor and derive its credential subject.
    DeriveSub {
        /// Issuer schema ID.
        #[arg(long)]
        issuer_schema_id: u64,
        /// Existing blinding factor as hex. When omitted, generated via OPRF.
        #[arg(long)]
        blinding_factor: Option<String>,
    },
}

const MAX_INPUT_BYTES: u64 = 10 * 1024 * 1024; // 10 MiB

fn read_file_or_stdin(path: &str) -> eyre::Result<Vec<u8>> {
    if path == "-" {
        let mut buf = Vec::new();
        std::io::stdin()
            .take(MAX_INPUT_BYTES)
            .read_to_end(&mut buf)?;
        Ok(buf)
    } else {
        let meta =
            std::fs::metadata(path).wrap_err_with(|| format!("cannot read {path}"))?;
        eyre::ensure!(
            meta.len() <= MAX_INPUT_BYTES,
            "input file too large (max 10 MiB)"
        );
        Ok(std::fs::read(path)?)
    }
}

async fn run_import(
    cli: &Cli,
    credential: &str,
    blinding_factor: Option<&str>,
    associated_data: Option<&str>,
) -> eyre::Result<()> {
    let (authenticator, store) = init_authenticator(cli).await?;

    let cred_bytes = read_file_or_stdin(credential)?;
    let cred = Credential::from_bytes(cred_bytes).wrap_err("invalid credential")?;

    let bf = blinding_factor
        .map(|hex| {
            FieldElement::try_from_hex_string(hex).wrap_err("invalid blinding factor")
        })
        .transpose()?;

    let ad = associated_data
        .map(|b64| {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(b64)
                .wrap_err("invalid base64 associated_data")
        })
        .transpose()?;

    let imported =
        import_credential(&store, &authenticator, &cred, bf.as_ref(), ad).await?;
    let issuer_schema_id = cred.issuer_schema_id();
    let expires_at = cred.expires_at();
    let blinding_factor_hex = imported.blinding_factor.to_hex_string();

    if cli.json {
        output::print_json_data(
            &serde_json::json!({
                "credential_id": imported.credential_id,
                "issuer_schema_id": issuer_schema_id,
                "expires_at": expires_at,
                "blinding_factor": blinding_factor_hex,
            }),
            true,
        );
    } else {
        println!(
            "Credential stored (id={}, issuer_schema_id={issuer_schema_id})",
            imported.credential_id
        );
        println!("  blinding_factor: {blinding_factor_hex}");
    }
    Ok(())
}

async fn run_list(cli: &Cli, issuer_schema_id: Option<u64>) -> eyre::Result<()> {
    let (_authenticator, store) = init_authenticator(cli).await?;
    let now = now_secs();
    let records = store
        .list_credentials(issuer_schema_id, now)
        .wrap_err("list credentials failed")?;

    if cli.json {
        let items: Vec<serde_json::Value> = records
            .iter()
            .map(|r| {
                serde_json::json!({
                    "credential_id": r.credential_id,
                    "issuer_schema_id": r.issuer_schema_id,
                    "expires_at": r.expires_at,
                    "is_expired": r.is_expired,
                })
            })
            .collect();
        output::print_json_data(&serde_json::json!(items), true);
    } else if records.is_empty() {
        println!("No credentials stored.");
    } else {
        println!(
            "{:<6} {:<20} {:<14} Expired",
            "ID", "Issuer Schema ID", "Expires At"
        );
        for r in &records {
            println!(
                "{:<6} {:<20} {:<14} {}",
                r.credential_id,
                r.issuer_schema_id,
                r.expires_at,
                if r.is_expired { "yes" } else { "no" }
            );
        }
    }
    Ok(())
}

async fn run_show(cli: &Cli, issuer_schema_id: u64) -> eyre::Result<()> {
    let (_authenticator, store) = init_authenticator(cli).await?;
    let now = now_secs();
    let result = store
        .get_credential(issuer_schema_id, now)
        .wrap_err("get credential failed")?;

    match result {
        Some((cred, bf)) => {
            let data = serde_json::json!({
                "issuer_schema_id": cred.issuer_schema_id(),
                "sub": cred.sub().to_hex_string(),
                "expires_at": cred.expires_at(),
                "genesis_issued_at": cred.genesis_issued_at(),
                "blinding_factor": bf.to_hex_string(),
            });
            output::print_json_data(&data, cli.json);
        }
        None => {
            if cli.json {
                output::print_json_data(&serde_json::json!(null), true);
            } else {
                println!("No active credential found for issuer_schema_id={issuer_schema_id}");
            }
        }
    }
    Ok(())
}

async fn run_issue_test(
    cli: &Cli,
    issuer_kind: TestCredentialIssuer,
    expires_in: Option<u64>,
) -> eyre::Result<()> {
    let env = TestEnv::default_staging();
    let (issuer_name, credential_type) = match issuer_kind {
        TestCredentialIssuer::Faux => {
            eyre::ensure!(
                expires_in.is_none(),
                "--expires-in is only valid with --issuer local"
            );
            ("faux", CredentialType::Faux)
        }
        TestCredentialIssuer::Local => {
            let genesis_issued_at = now_secs();
            let expires_at = genesis_issued_at
                .checked_add(expires_in.unwrap_or(3600))
                .ok_or_else(|| eyre::eyre!("credential expiration overflow"))?;
            (
                "local",
                CredentialType::Local {
                    genesis_issued_at,
                    expires_at,
                },
            )
        }
    };
    let (authenticator, store) = init_authenticator(cli).await?;
    let issued =
        issue_credential(&env, credential_type, &authenticator, &store).await?;
    let issuer_schema_id = issued.credential.issuer_schema_id();
    let expires_at = issued.credential.expires_at();

    if cli.json {
        output::print_json_data(
            &serde_json::json!({
                "credential_id": issued.credential_id,
                "issuer": issuer_name,
                "issuer_schema_id": issuer_schema_id,
                "expires_at": expires_at,
                "blinding_factor": issued.blinding_factor.to_hex_string(),
            }),
            true,
        );
    } else {
        println!(
            "Credential issued from {issuer_name} issuer (id={})",
            issued.credential_id
        );
        println!("  issuer_schema_id: {issuer_schema_id}");
        println!("  expires_at: {expires_at}");
        println!(
            "  blinding_factor: {}",
            issued.blinding_factor.to_hex_string()
        );
    }
    Ok(())
}

async fn run_derive_sub(
    cli: &Cli,
    issuer_schema_id: u64,
    blinding_factor: Option<&str>,
) -> eyre::Result<()> {
    let supplied_blinding_factor = blinding_factor
        .map(|value| {
            FieldElement::try_from_hex_string(value).wrap_err("invalid blinding factor")
        })
        .transpose()?;
    let (authenticator, _store) = init_authenticator(cli).await?;
    let blinding_factor = match supplied_blinding_factor {
        Some(blinding_factor) => blinding_factor,
        None => authenticator
            .generate_credential_blinding_factor_remote(issuer_schema_id)
            .await
            .wrap_err("blinding factor generation failed")?,
    };
    let sub = authenticator.compute_credential_sub(&blinding_factor);
    let blinding_factor = blinding_factor.to_hex_string();
    let sub = sub.to_hex_string();

    if cli.json {
        output::print_json_data(
            &serde_json::json!({
                "issuer_schema_id": issuer_schema_id,
                "blinding_factor": blinding_factor,
                "sub": sub,
            }),
            true,
        );
    } else {
        println!("issuer_schema_id: {issuer_schema_id}");
        println!("blinding_factor:  {blinding_factor}");
        println!("sub:              {sub}");
    }
    Ok(())
}

pub async fn run(cli: &Cli, action: &CredentialCommand) -> eyre::Result<()> {
    match action {
        CredentialCommand::Import {
            credential,
            blinding_factor,
            associated_data,
        } => {
            run_import(
                cli,
                credential,
                blinding_factor.as_deref(),
                associated_data.as_deref(),
            )
            .await
        }
        CredentialCommand::List { issuer_schema_id } => {
            run_list(cli, *issuer_schema_id).await
        }
        CredentialCommand::Show { issuer_schema_id } => {
            run_show(cli, *issuer_schema_id).await
        }
        CredentialCommand::IssueTest { issuer, expires_in } => {
            run_issue_test(cli, *issuer, *expires_in).await
        }
        CredentialCommand::DeriveSub {
            issuer_schema_id,
            blinding_factor,
        } => run_derive_sub(cli, *issuer_schema_id, blinding_factor.as_deref()).await,
        CredentialCommand::Delete { credential_id } => {
            let (_authenticator, store) = init_authenticator(cli).await?;
            store
                .delete_credential(*credential_id)
                .wrap_err("delete credential failed")?;
            output::print_success(
                &format!("Credential {credential_id} deleted."),
                cli.json,
            );
            Ok(())
        }
    }
}
