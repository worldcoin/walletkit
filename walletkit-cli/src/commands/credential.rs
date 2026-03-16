//! `walletkit credential` subcommands — credential management.

use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Subcommand;
use walletkit_core::{Credential, FieldElement};

use crate::output;

use super::{init_authenticator, Cli};

#[derive(Subcommand)]
pub enum CredentialCommand {
    /// Import a credential from a file or stdin.
    Import {
        /// Path to credential JSON file, or `-` for stdin.
        #[arg(long)]
        credential: String,
        /// Blinding factor as hex.
        #[arg(long)]
        blinding_factor: String,
        /// Expiration timestamp (unix seconds).
        #[arg(long)]
        expires_at: u64,
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
    /// Issue a credential: generate blinding factor via OPRF, then store.
    Issue {
        /// Issuer schema ID.
        #[arg(long)]
        issuer_schema_id: u64,
        /// Path to credential file, or `-` for stdin.
        #[arg(long)]
        credential: String,
        /// Expiration timestamp (unix seconds).
        #[arg(long)]
        expires_at: u64,
        /// Optional associated data (base64-encoded).
        #[arg(long)]
        associated_data: Option<String>,
    },
    /// Issue a test credential from the staging faux issuer (issuer schema 128).
    IssueTest,
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

fn now_secs() -> eyre::Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
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
        let meta = std::fs::metadata(path)
            .map_err(|e| eyre::eyre!("cannot read {path}: {e}"))?;
        if meta.len() > MAX_INPUT_BYTES {
            return Err(eyre::eyre!("input file too large (max 10 MiB)"));
        }
        Ok(std::fs::read(path)?)
    }
}

async fn run_import(
    cli: &Cli,
    credential: &str,
    blinding_factor: &str,
    expires_at: u64,
    associated_data: Option<&str>,
) -> eyre::Result<()> {
    let (_authenticator, store) = init_authenticator(cli).await?;

    let cred_bytes = read_file_or_stdin(credential)?;
    let cred = Credential::from_bytes(cred_bytes)
        .map_err(|e| eyre::eyre!("invalid credential: {e}"))?;

    let bf = FieldElement::try_from_hex_string(blinding_factor)
        .map_err(|e| eyre::eyre!("invalid blinding factor: {e}"))?;

    let ad = associated_data
        .map(|b64| {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(b64)
                .map_err(|e| eyre::eyre!("invalid base64 associated_data: {e}"))
        })
        .transpose()?;

    let now = now_secs()?;
    let id = store
        .store_credential(&cred, &bf, expires_at, ad, now)
        .map_err(|e| eyre::eyre!("store credential failed: {e}"))?;

    if cli.json {
        output::print_json_data(
            &serde_json::json!({
                "credential_id": id,
                "issuer_schema_id": cred.issuer_schema_id(),
                "expires_at": expires_at,
            }),
            true,
        );
    } else {
        println!(
            "Credential stored (id={id}, issuer_schema_id={})",
            cred.issuer_schema_id()
        );
    }
    Ok(())
}

async fn run_list(cli: &Cli, issuer_schema_id: Option<u64>) -> eyre::Result<()> {
    let (_authenticator, store) = init_authenticator(cli).await?;
    let now = now_secs()?;
    let records = store
        .list_credentials(issuer_schema_id, now)
        .map_err(|e| eyre::eyre!("list credentials failed: {e}"))?;

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
    let now = now_secs()?;
    let result = store
        .get_credential(issuer_schema_id, now)
        .map_err(|e| eyre::eyre!("get credential failed: {e}"))?;

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

async fn run_issue(
    cli: &Cli,
    issuer_schema_id: u64,
    credential: &str,
    expires_at: u64,
    associated_data: Option<&str>,
) -> eyre::Result<()> {
    let (authenticator, store) = init_authenticator(cli).await?;

    let bf = authenticator
        .generate_credential_blinding_factor_remote(issuer_schema_id)
        .await
        .map_err(|e| eyre::eyre!("blinding factor generation failed: {e}"))?;

    let cred_bytes = read_file_or_stdin(credential)?;
    let cred = Credential::from_bytes(cred_bytes)
        .map_err(|e| eyre::eyre!("invalid credential: {e}"))?;

    let ad = associated_data
        .map(|b64| {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(b64)
                .map_err(|e| eyre::eyre!("invalid base64 associated_data: {e}"))
        })
        .transpose()?;

    let now = now_secs()?;
    let id = store
        .store_credential(&cred, &bf, expires_at, ad, now)
        .map_err(|e| eyre::eyre!("store credential failed: {e}"))?;

    if cli.json {
        output::print_json_data(
            &serde_json::json!({
                "credential_id": id,
                "blinding_factor": bf.to_hex_string(),
            }),
            true,
        );
    } else {
        println!("Credential issued (id={id})");
        println!("  blinding_factor: {}", bf.to_hex_string());
    }
    Ok(())
}

const FAUX_ISSUER_URL: &str = "https://faux-issuer.us.id-infra.worldcoin.dev/issue";
const FAUX_ISSUER_SCHEMA_ID: u64 = 128;

async fn run_issue_test(cli: &Cli) -> eyre::Result<()> {
    let (authenticator, store) = init_authenticator(cli).await?;

    // Step 1: OPRF to get blinding factor
    let bf = authenticator
        .generate_credential_blinding_factor_remote(FAUX_ISSUER_SCHEMA_ID)
        .await
        .map_err(|e| eyre::eyre!("blinding factor generation failed: {e}"))?;

    // Step 2: Compute sub from blinding factor
    let sub = authenticator.compute_credential_sub(&bf);
    let sub_hex = sub.to_hex_string();

    if !cli.json {
        println!("Computed sub: {sub_hex}");
        println!("Requesting credential from faux issuer...");
    }

    // Step 3: POST to faux issuer
    let client = reqwest::Client::new();
    let resp = client
        .post(FAUX_ISSUER_URL)
        .json(&serde_json::json!({ "sub": sub_hex }))
        .send()
        .await
        .map_err(|e| eyre::eyre!("faux issuer request failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(eyre::eyre!(
            "faux issuer returned {status}: {body}"
        ));
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| eyre::eyre!("failed to parse faux issuer response: {e}"))?;

    let cred_value = body
        .get("credential")
        .ok_or_else(|| eyre::eyre!("faux issuer response missing 'credential' field"))?;

    let cred_bytes = serde_json::to_vec(cred_value)
        .map_err(|e| eyre::eyre!("failed to serialize credential: {e}"))?;
    let cred = Credential::from_bytes(cred_bytes)
        .map_err(|e| eyre::eyre!("invalid credential from faux issuer: {e}"))?;
    let expires_at = cred.expires_at();

    // Step 4: Store the credential
    let now = now_secs()?;
    let id = store
        .store_credential(&cred, &bf, expires_at, None, now)
        .map_err(|e| eyre::eyre!("store credential failed: {e}"))?;

    if cli.json {
        output::print_json_data(
            &serde_json::json!({
                "credential_id": id,
                "issuer_schema_id": FAUX_ISSUER_SCHEMA_ID,
                "expires_at": expires_at,
                "blinding_factor": bf.to_hex_string(),
            }),
            true,
        );
    } else {
        println!("Credential issued from faux issuer (id={id})");
        println!("  issuer_schema_id: {FAUX_ISSUER_SCHEMA_ID}");
        println!("  expires_at: {expires_at}");
        println!("  blinding_factor: {}", bf.to_hex_string());
    }
    Ok(())
}

pub async fn run(cli: &Cli, action: &CredentialCommand) -> eyre::Result<()> {
    match action {
        CredentialCommand::Import {
            credential,
            blinding_factor,
            expires_at,
            associated_data,
        } => run_import(
            cli,
            credential,
            blinding_factor,
            *expires_at,
            associated_data.as_deref(),
        ).await,
        CredentialCommand::Issue {
            issuer_schema_id,
            credential,
            expires_at,
            associated_data,
        } => {
            run_issue(
                cli,
                *issuer_schema_id,
                credential,
                *expires_at,
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
        CredentialCommand::IssueTest => run_issue_test(cli).await,
        CredentialCommand::BlindingFactor { issuer_schema_id } => {
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
        CredentialCommand::ComputeSub { blinding_factor } => {
            let (authenticator, _store) = init_authenticator(cli).await?;
            let bf = FieldElement::try_from_hex_string(blinding_factor)
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
        CredentialCommand::Delete { credential_id } => {
            let (_authenticator, store) = init_authenticator(cli).await?;
            store
                .delete_credential(*credential_id)
                .map_err(|e| eyre::eyre!("delete credential failed: {e}"))?;
            output::print_success(
                &format!("Credential {credential_id} deleted."),
                cli.json,
            );
            Ok(())
        }
    }
}
