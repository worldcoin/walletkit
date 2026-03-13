//! `walletkit credential` subcommands — credential management.

use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Subcommand;
use walletkit_core::issuers::TfhNfcIssuer;
use walletkit_core::storage::cache_embedded_groth16_material;
use walletkit_core::{Credential, FieldElement};

use crate::output;
use crate::provider::create_fs_credential_store;

use super::init_authenticator;
use super::{resolve_root, Cli};

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
    /// Refresh an NFC credential via the TFH issuer.
    RefreshNfc {
        /// Path to request body JSON, or `-` for stdin.
        #[arg(long)]
        request_body: String,
        /// Additional HTTP headers as key=value pairs.
        #[arg(long)]
        header: Vec<String>,
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

fn run_import(
    cli: &Cli,
    credential: &str,
    blinding_factor: &str,
    expires_at: u64,
    associated_data: Option<&str>,
) -> eyre::Result<()> {
    let root = resolve_root(cli)?;
    let store = create_fs_credential_store(&root)?;
    let paths = store.storage_paths()?;
    cache_embedded_groth16_material(paths)?;

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

fn run_list(cli: &Cli, issuer_schema_id: Option<u64>) -> eyre::Result<()> {
    let root = resolve_root(cli)?;
    let store = create_fs_credential_store(&root)?;
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

fn run_show(cli: &Cli, issuer_schema_id: u64) -> eyre::Result<()> {
    let root = resolve_root(cli)?;
    let store = create_fs_credential_store(&root)?;
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

async fn run_refresh_nfc(
    cli: &Cli,
    request_body: &str,
    headers: &[String],
) -> eyre::Result<()> {
    let env = super::resolve_environment(cli)?;
    let issuer = TfhNfcIssuer::new(&env);

    let body = read_file_or_stdin(request_body)?;
    let body_str = String::from_utf8(body)
        .map_err(|e| eyre::eyre!("request body is not valid UTF-8: {e}"))?;

    let mut header_map = std::collections::HashMap::new();
    for h in headers {
        let (k, v) = h.split_once('=').ok_or_else(|| {
            eyre::eyre!("invalid header format, expected key=value: {h}")
        })?;
        header_map.insert(k.to_string(), v.to_string());
    }

    let credential = issuer
        .refresh_nfc_credential(&body_str, header_map)
        .await
        .map_err(|e| eyre::eyre!("NFC refresh failed: {e}"))?;

    let data = serde_json::json!({
        "issuer_schema_id": credential.issuer_schema_id(),
        "sub": credential.sub().to_hex_string(),
        "expires_at": credential.expires_at(),
    });

    if cli.json {
        output::print_json_data(&data, true);
    } else {
        println!("NFC credential received:");
        println!("  issuer_schema_id: {}", credential.issuer_schema_id());
        println!("  expires_at:       {}", credential.expires_at());
        println!("  sub:              {}", credential.sub().to_hex_string());
        println!("\nUse `walletkit credential import` to store this credential.");
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
        ),
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
            run_list(cli, *issuer_schema_id)
        }
        CredentialCommand::Show { issuer_schema_id } => {
            run_show(cli, *issuer_schema_id)
        }
        CredentialCommand::Delete { credential_id } => {
            let root = resolve_root(cli)?;
            let store = create_fs_credential_store(&root)?;
            store
                .delete_credential(*credential_id)
                .map_err(|e| eyre::eyre!("delete credential failed: {e}"))?;
            output::print_success(
                &format!("Credential {credential_id} deleted."),
                cli.json,
            );
            Ok(())
        }
        CredentialCommand::RefreshNfc {
            request_body,
            header,
        } => run_refresh_nfc(cli, request_body, header).await,
    }
}
