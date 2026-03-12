//! `walletkit proof` subcommands — proof generation and inspection.

use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Subcommand;
use walletkit_core::requests::ProofRequest;

use crate::output;

use super::{init_authenticator, Cli};

#[derive(Subcommand)]
pub enum ProofCommand {
    /// Generate a proof from a request JSON.
    Generate {
        /// Path to proof request JSON, or `-` for stdin.
        #[arg(long)]
        request: String,
        /// Override current time (unix seconds) for deterministic testing.
        #[arg(long)]
        now: Option<u64>,
    },
    /// Inspect a proof request without generating a proof.
    InspectRequest {
        /// Path to proof request JSON, or `-` for stdin.
        #[arg(long)]
        request: String,
    },
}

fn read_file_or_stdin(path: &str) -> eyre::Result<String> {
    if path == "-" {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        Ok(buf)
    } else {
        Ok(std::fs::read_to_string(path)?)
    }
}

async fn run_generate(cli: &Cli, request: &str, now: Option<u64>) -> eyre::Result<()> {
    let (authenticator, _store) = init_authenticator(cli).await?;

    let ts = now.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_secs()
    });

    let json_str = read_file_or_stdin(request)?;
    let proof_request = ProofRequest::from_json(&json_str)
        .map_err(|e| eyre::eyre!("invalid proof request: {e}"))?;

    let response = authenticator
        .generate_proof(&proof_request, Some(ts))
        .await
        .map_err(|e| eyre::eyre!("proof generation failed: {e}"))?;

    let response_json = response
        .to_json()
        .map_err(|e| eyre::eyre!("response serialization failed: {e}"))?;

    if cli.json {
        let parsed: serde_json::Value = serde_json::from_str(&response_json)?;
        output::print_json_data(&parsed, true);
    } else {
        println!("{response_json}");
    }
    Ok(())
}

fn run_inspect_request(cli: &Cli, request: &str) -> eyre::Result<()> {
    let json_str = read_file_or_stdin(request)?;
    let proof_request = ProofRequest::from_json(&json_str)
        .map_err(|e| eyre::eyre!("invalid proof request: {e}"))?;

    if cli.json {
        let normalized: serde_json::Value = serde_json::from_str(&json_str)?;
        let full = serde_json::json!({
            "id": proof_request.id(),
            "version": proof_request.version(),
            "raw": normalized,
        });
        output::print_json_data(&full, true);
    } else {
        println!("Proof Request:");
        println!("  id:      {}", proof_request.id());
        println!("  version: {}", proof_request.version());
    }
    Ok(())
}

pub async fn run(cli: &Cli, action: &ProofCommand) -> eyre::Result<()> {
    match action {
        ProofCommand::Generate { request, now } => {
            run_generate(cli, request, *now).await
        }
        ProofCommand::InspectRequest { request } => run_inspect_request(cli, request),
    }
}
