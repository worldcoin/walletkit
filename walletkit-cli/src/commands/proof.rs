//! `walletkit proof` subcommands — proof generation, inspection, and on-chain verification.

use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine as _};
use clap::Subcommand;
use eyre::WrapErr as _;
use walletkit_core::requests::ProofRequest;
use walletkit_testkit::issuer::issue_faux_credential;
use walletkit_testkit::proof::{build_test_request, verify_proof_onchain, VerifyItemResult};
use walletkit_testkit::TestEnv;
use world_id_core::primitives::{FieldElement, OwnershipProof, SessionId};
use world_id_core::requests::{
    ProofRequest as CoreProofRequest, ProofResponse as CoreProofResponse, ProofType,
};
use world_id_proof::ownership_proof::verify_ownership_proof;

use crate::output;

use super::{init_authenticator, Cli};

const MAX_INPUT_BYTES: u64 = 10 * 1024 * 1024; // 10 MiB

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
    /// Generate a signed test proof request using hardcoded staging RP keys.
    GenerateTestRequest {
        /// Issuer schema ID to request a proof for.
        #[arg(long)]
        issuer_schema_id: u64,
        /// Signal string for the proof request.
        #[arg(long, default_value = "test_signal")]
        signal: String,
        /// Seconds from now until the request expires.
        #[arg(long, default_value = "300")]
        expires_in: u64,
        /// Proof type to generate.
        #[arg(long, value_parser = parse_proof_type_arg, default_value = "uniqueness")]
        proof_type: ProofType,
        /// Existing session ID for `--proof-type session`.
        #[arg(long, value_parser = parse_session_id_arg)]
        session_id: Option<SessionId>,
    },
    /// Verify a previously generated proof on-chain via the `WorldIDVerifier` contract.
    Verify {
        /// Path to the original proof request JSON, or `-` for stdin.
        #[arg(long)]
        request: String,
        /// Path to the proof response JSON, or `-` for stdin.
        #[arg(long)]
        response: String,
        /// Override the `WorldID` verifier contract address (default: mainnet).
        #[arg(long)]
        verifier_address: Option<String>,
    },
    /// End-to-end test: issue a test credential, generate a proof, and verify it on-chain.
    Test {
        /// Signal string for the proof request.
        #[arg(long, default_value = "test_signal")]
        signal: String,
    },
    /// Verify a WIP-103 ownership proof from a base64-encoded file.
    VerifyOwnership {
        /// Path to a file containing the base64url-encoded ownership proof, or `-` for stdin.
        #[arg(long)]
        proof: String,
        /// Nonce used when generating the proof, as a 32-byte hex field element (with optional `0x` prefix).
        #[arg(long)]
        nonce: String,
        /// Credential `sub` (commitment) the proof claims ownership of, as a 32-byte hex field element.
        #[arg(long)]
        sub: String,
    },
}

fn read_file_or_stdin(path: &str) -> eyre::Result<String> {
    if path == "-" {
        let mut buf = String::new();
        std::io::stdin()
            .take(MAX_INPUT_BYTES)
            .read_to_string(&mut buf)?;
        Ok(buf)
    } else {
        let meta =
            std::fs::metadata(path).wrap_err_with(|| format!("cannot read {path}"))?;
        eyre::ensure!(
            meta.len() <= MAX_INPUT_BYTES,
            "input file too large (max 10 MiB)"
        );
        Ok(std::fs::read_to_string(path)?)
    }
}

fn parse_proof_type_arg(value: &str) -> Result<ProofType, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "uniqueness" => Ok(ProofType::Uniqueness),
        "create-session" | "create_session" => Ok(ProofType::CreateSession),
        "session" => Ok(ProofType::Session),
        _ => Err("expected one of: uniqueness, create-session, session".to_string()),
    }
}

fn parse_session_id_arg(session_id: &str) -> Result<SessionId, String> {
    serde_json::from_value(serde_json::Value::String(session_id.to_string()))
        .map_err(|err| format!("invalid session id: {err}"))
}

/// Builds a [`TestEnv`] for on-chain verification, honoring the CLI's
/// `--rpc-url` and an optional verifier-address override.
fn verify_env(cli: &Cli, verifier_address: Option<&str>) -> eyre::Result<TestEnv> {
    let mut env = TestEnv::staging();
    if let Some(rpc) = cli.rpc_url.as_deref() {
        env.worldchain_rpc_url = rpc.to_string();
    }
    if let Some(addr) = verifier_address {
        env.world_id_verifier =
            addr.parse().wrap_err("invalid verifier address")?;
    }
    Ok(env)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs()
}

async fn run_generate(cli: &Cli, request: &str, now: Option<u64>) -> eyre::Result<()> {
    let (authenticator, _store) = init_authenticator(cli).await?;

    let ts = now.unwrap_or_else(now_secs);

    let json_str = read_file_or_stdin(request)?;
    let proof_request =
        ProofRequest::from_json(&json_str).wrap_err("invalid proof request")?;

    let response = authenticator
        .generate_proof(&proof_request, Some(ts))
        .await
        .wrap_err("proof generation failed")?;

    let response_json = response
        .to_json()
        .wrap_err("response serialization failed")?;

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
    let proof_request =
        CoreProofRequest::from_json(&json_str).wrap_err("invalid proof request")?;

    if cli.json {
        let normalized: serde_json::Value = serde_json::from_str(&json_str)?;
        let full = serde_json::json!({
            "id": proof_request.id,
            "version": proof_request.version as u8,
            "proof_type": proof_request.proof_type,
            "has_session_id": proof_request.session_id.is_some(),
            "has_action": proof_request.action.is_some(),
            "raw": normalized,
        });
        output::print_json_data(&full, true);
    } else {
        println!("Proof Request:");
        println!("  id:             {}", proof_request.id);
        println!("  version:        {}", proof_request.version as u8);
        println!("  proof_type:     {:?}", proof_request.proof_type);
        println!("  has_session_id: {}", proof_request.session_id.is_some());
        println!("  has_action:     {}", proof_request.action.is_some());
    }
    Ok(())
}

fn print_verify_items_human(results: &[VerifyItemResult]) {
    for r in results {
        if r.verified {
            println!(
                "  {} {} (issuer_schema_id={})",
                output::pass_label(),
                r.identifier,
                r.issuer_schema_id
            );
        } else {
            println!(
                "  {} {} (issuer_schema_id={}): {}",
                output::fail_label(),
                r.identifier,
                r.issuer_schema_id,
                r.error.as_deref().unwrap_or("unknown")
            );
        }
    }
}

fn verify_items_to_json(results: &[VerifyItemResult]) -> Vec<serde_json::Value> {
    results
        .iter()
        .map(|r| {
            serde_json::json!({
                "issuer_schema_id": r.issuer_schema_id,
                "identifier": r.identifier,
                "verified": r.verified,
                "error": r.error,
            })
        })
        .collect()
}

async fn run_verify(
    cli: &Cli,
    request_path: &str,
    response_path: &str,
    verifier_address: Option<&str>,
) -> eyre::Result<()> {
    let request_json = read_file_or_stdin(request_path)?;
    let response_json = read_file_or_stdin(response_path)?;

    let proof_request: CoreProofRequest =
        CoreProofRequest::from_json(&request_json).wrap_err("invalid proof request")?;
    let proof_response: CoreProofResponse =
        serde_json::from_str(&response_json).wrap_err("invalid proof response")?;

    let env = verify_env(cli, verifier_address)?;
    let results = verify_proof_onchain(&env, &proof_request, &proof_response).await?;
    let all_passed = results.iter().all(|r| r.verified);

    if cli.json {
        output::print_json_data(
            &serde_json::json!({
                "verified": all_passed,
                "results": verify_items_to_json(&results),
            }),
            true,
        );
    } else {
        print_verify_items_human(&results);
        if all_passed {
            println!("All proofs verified on-chain.");
        }
    }

    if !all_passed {
        std::process::exit(1);
    }
    Ok(())
}

fn run_generate_test_request(
    cli: &Cli,
    issuer_schema_id: u64,
    signal: &str,
    expires_in: u64,
    proof_type: ProofType,
    session_id: Option<SessionId>,
) -> eyre::Result<()> {
    let session_id = match (proof_type, session_id) {
        (ProofType::Uniqueness | ProofType::CreateSession, Some(_)) => {
            eyre::bail!("--session-id is only valid with --proof-type session");
        }
        (ProofType::Session, None) => {
            eyre::bail!("--session-id is required with --proof-type session");
        }
        (ProofType::Session, Some(session_id)) => Some(session_id),
        (_, None) => None,
    };
    let env = TestEnv::staging();
    let request = build_test_request(
        &env,
        issuer_schema_id,
        signal,
        now_secs(),
        expires_in,
        proof_type,
        session_id,
    )?;
    let json = serde_json::to_string_pretty(&request)?;

    if cli.json {
        let parsed: serde_json::Value = serde_json::from_str(&json)?;
        output::print_json_data(&parsed, true);
    } else {
        println!("{json}");
    }

    Ok(())
}

/// End-to-end test: issue a test credential, generate a proof, and verify it on-chain.
async fn run_test(cli: &Cli, signal: &str) -> eyre::Result<()> {
    let (authenticator, store) = init_authenticator(cli).await?;
    let env = verify_env(cli, None)?;
    let now = now_secs();

    if !cli.json {
        eprintln!("Issuing test credential from faux issuer...");
    }
    let issued = issue_faux_credential(&env, &authenticator, &store, now).await?;

    if !cli.json {
        eprintln!("Generating test proof request...");
    }
    let proof_request = build_test_request(
        &env,
        env.faux_issuer_schema_id,
        signal,
        now,
        300,
        ProofType::Uniqueness,
        None,
    )?;

    if !cli.json {
        eprintln!("Generating proof...");
    }
    let walletkit_request =
        ProofRequest::from_json(&serde_json::to_string(&proof_request)?)
            .wrap_err("invalid proof request")?;
    let proof_response = authenticator
        .generate_proof(&walletkit_request, Some(now))
        .await
        .wrap_err("proof generation failed")?;

    if !cli.json {
        eprintln!("Verifying proof on-chain...");
    }
    let results =
        verify_proof_onchain(&env, &proof_request, &proof_response.0).await?;
    let all_passed = results.iter().all(|r| r.verified);

    if cli.json {
        output::print_json_data(
            &serde_json::json!({
                "credential_id": issued.credential_id,
                "issuer_schema_id": issued.issuer_schema_id,
                "blinding_factor": issued.blinding_factor.to_hex_string(),
                "verified": all_passed,
                "results": verify_items_to_json(&results),
            }),
            true,
        );
    } else {
        print_verify_items_human(&results);
        if all_passed {
            println!("End-to-end test passed.");
        }
    }

    if !all_passed {
        std::process::exit(1);
    }
    Ok(())
}

fn parse_field_element(value: &str, label: &str) -> eyre::Result<FieldElement> {
    value.trim().parse::<FieldElement>().wrap_err_with(|| {
        format!("invalid {label}: expected 32-byte hex field element")
    })
}

fn run_verify_ownership(
    cli: &Cli,
    proof_path: &str,
    nonce: &str,
    sub: &str,
) -> eyre::Result<()> {
    let b64 = read_file_or_stdin(proof_path)?;
    let bytes = BASE64_URL_SAFE_NO_PAD
        .decode(b64.trim())
        .wrap_err("invalid base64 ownership proof")?;
    let proof: OwnershipProof = ciborium::from_reader(&bytes[..])
        .wrap_err("failed to decode ownership proof CBOR")?;

    let nonce_fe = parse_field_element(nonce, "--nonce")?;
    let sub_fe = parse_field_element(sub, "--sub")?;

    let result = verify_ownership_proof(&proof, nonce_fe, sub_fe);
    let merkle_root = proof.merkle_root.to_string();

    if cli.json {
        output::print_json_data(
            &serde_json::json!({
                "verified": result.is_ok(),
                "merkle_root": merkle_root,
                "error": result.as_ref().err().map(|e| format!("{e:#}")),
            }),
            true,
        );
    } else if let Err(ref err) = result {
        println!(
            "{} ownership proof verification failed: {err:#}",
            output::fail_label()
        );
        println!("  merkle_root: {merkle_root}");
    } else {
        println!("{} ownership proof verified", output::pass_label());
        println!("  merkle_root: {merkle_root}");
    }

    if result.is_err() {
        std::process::exit(1);
    }
    Ok(())
}

pub async fn run(cli: &Cli, action: &ProofCommand) -> eyre::Result<()> {
    match action {
        ProofCommand::Generate { request, now } => {
            run_generate(cli, request, *now).await
        }
        ProofCommand::InspectRequest { request } => run_inspect_request(cli, request),
        ProofCommand::GenerateTestRequest {
            issuer_schema_id,
            signal,
            expires_in,
            proof_type,
            session_id,
        } => run_generate_test_request(
            cli,
            *issuer_schema_id,
            signal,
            *expires_in,
            *proof_type,
            *session_id,
        ),
        ProofCommand::Verify {
            request,
            response,
            verifier_address,
        } => run_verify(cli, request, response, verifier_address.as_deref()).await,
        ProofCommand::Test { signal } => run_test(cli, signal).await,
        ProofCommand::VerifyOwnership { proof, nonce, sub } => {
            run_verify_ownership(cli, proof, nonce, sub)
        }
    }
}
