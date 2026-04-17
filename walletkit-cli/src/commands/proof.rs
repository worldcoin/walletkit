//! `walletkit proof` subcommands — proof generation, inspection, and on-chain verification.

use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::providers::ProviderBuilder;
use alloy::signers::{local::PrivateKeySigner, SignerSync};
use alloy::sol;
use clap::Subcommand;
use eyre::WrapErr as _;
use rand::rngs::OsRng;
use walletkit_core::requests::ProofRequest;
use world_id_core::primitives::{rp::RpId, FieldElement};
use world_id_core::requests::{
    ProofRequest as CoreProofRequest, ProofResponse as CoreProofResponse, RequestItem,
    RequestVersion,
};

use crate::output;

use super::credential::{issue_test_credential, FAUX_ISSUER_SCHEMA_ID};
use super::{init_authenticator, Cli};

const DEFAULT_RPC_URL: &str = "https://worldchain-mainnet.g.alchemy.com/public";

const MAX_INPUT_BYTES: u64 = 10 * 1024 * 1024; // 10 MiB

const WORLD_ID_VERIFIER: alloy::primitives::Address =
    alloy::primitives::address!("0x703a6316c975DEabF30b637c155edD53e24657DB");

sol!(
    #[allow(clippy::too_many_arguments)]
    #[sol(rpc)]
    interface IWorldIDVerifier {
        function verify(
            uint256 nullifier,
            uint256 action,
            uint64 rpId,
            uint256 nonce,
            uint256 signalHash,
            uint64 expiresAtMin,
            uint64 issuerSchemaId,
            uint256 credentialGenesisIssuedAtMin,
            uint256[5] calldata zeroKnowledgeProof
        ) external view;
    }
);

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

async fn run_generate(cli: &Cli, request: &str, now: Option<u64>) -> eyre::Result<()> {
    let (authenticator, _store) = init_authenticator(cli).await?;

    let ts = now.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_secs()
    });

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
        ProofRequest::from_json(&json_str).wrap_err("invalid proof request")?;

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

/// Result of verifying one proof response item against the `WorldIDVerifier` contract.
pub struct VerifyItemResult {
    pub issuer_schema_id: u64,
    pub identifier: String,
    pub verified: bool,
    pub error: Option<String>,
}

/// Verifies a proof request + response pair on-chain. Returns per-item results.
pub async fn verify_proof_onchain(
    cli: &Cli,
    proof_request: &CoreProofRequest,
    proof_response: &CoreProofResponse,
    verifier_address: Option<&str>,
) -> eyre::Result<Vec<VerifyItemResult>> {
    if let Some(ref err) = proof_response.error {
        eyre::bail!("proof response contains error: {err}");
    }

    let rpc_url = cli.rpc_url.as_deref().unwrap_or(DEFAULT_RPC_URL);
    let provider = ProviderBuilder::new().connect_http(rpc_url.parse()?);
    let verifier_addr = match verifier_address {
        Some(addr) => addr
            .parse::<alloy::primitives::Address>()
            .wrap_err("invalid verifier address")?,
        None => WORLD_ID_VERIFIER,
    };
    let verifier_contract = IWorldIDVerifier::new(verifier_addr, &provider);

    let action = proof_request.action.ok_or_else(|| {
        eyre::eyre!("proof request has no action (session proofs not supported)")
    })?;
    let nonce = proof_request.nonce;
    let rp_id = proof_request.rp_id.into_inner();

    let mut results = Vec::new();
    for response_item in &proof_response.responses {
        let request_item = proof_request
            .find_request_by_issuer_schema_id(response_item.issuer_schema_id)
            .ok_or_else(|| {
                eyre::eyre!(
                    "no matching request item for issuer_schema_id={}",
                    response_item.issuer_schema_id
                )
            })?;

        let nullifier = response_item
            .nullifier
            .ok_or_else(|| eyre::eyre!("response item missing nullifier"))?;

        let result = verifier_contract
            .verify(
                nullifier.into(),
                action.into(),
                rp_id,
                nonce.into(),
                request_item.signal_hash().into(),
                response_item.expires_at_min,
                response_item.issuer_schema_id,
                request_item
                    .genesis_issued_at_min
                    .unwrap_or_default()
                    .try_into()?,
                response_item.proof.as_ethereum_representation(),
            )
            .call()
            .await;

        results.push(VerifyItemResult {
            issuer_schema_id: response_item.issuer_schema_id,
            identifier: response_item.identifier.clone(),
            verified: result.is_ok(),
            error: result.err().map(|e| format!("{e:#}")),
        });
    }
    Ok(results)
}

fn print_verify_items_human(results: &[VerifyItemResult]) {
    for r in results {
        if r.verified {
            println!(
                "  [PASS] {} (issuer_schema_id={})",
                r.identifier, r.issuer_schema_id
            );
        } else {
            println!(
                "  [FAIL] {} (issuer_schema_id={}): {}",
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
        serde_json::from_str(&request_json).wrap_err("invalid proof request")?;
    let proof_response: CoreProofResponse =
        serde_json::from_str(&response_json).wrap_err("invalid proof response")?;

    let results =
        verify_proof_onchain(cli, &proof_request, &proof_response, verifier_address)
            .await?;
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

/// Staging RP ID registered on the `RpRegistry` contract.
const STAGING_RP_ID: u64 = 46;

/// ECDSA private key for the staging RP (secp256k1).
const STAGING_RP_SIGNING_KEY: [u8; 32] = alloy::primitives::hex!(
    "1111111111111111111111111111111111111111111111111111111111111111"
);

/// Builds a signed test proof request using hardcoded staging RP keys.
fn build_test_request(
    issuer_schema_id: u64,
    signal: &str,
    expires_in: u64,
) -> eyre::Result<CoreProofRequest> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs();

    let nonce = FieldElement::random(&mut OsRng);
    let created_at = now;
    let expires_at = now + expires_in;

    let signer = PrivateKeySigner::from_bytes(&STAGING_RP_SIGNING_KEY.into())
        .wrap_err("failed to create signer")?;

    let action = FieldElement::from(1u64);
    let msg = world_id_core::primitives::rp::compute_rp_signature_msg(
        *nonce,
        created_at,
        expires_at,
        Some(*action),
    );
    let signature = signer.sign_message_sync(&msg).wrap_err("signing failed")?;

    let rp_id = RpId::new(STAGING_RP_ID);
    let request_item = RequestItem::new(
        "test".to_string(),
        issuer_schema_id,
        Some(signal.as_bytes().to_vec()),
        None,
        None,
    );

    Ok(CoreProofRequest {
        id: "test_request".to_string(),
        version: RequestVersion::V1,
        created_at,
        expires_at,
        rp_id,
        oprf_key_id: serde_json::from_value(serde_json::json!(format!(
            "0x{:040x}",
            STAGING_RP_ID
        )))
        .wrap_err("failed to construct oprf_key_id")?,
        session_id: None,
        action: Some(action),
        signature,
        nonce,
        requests: vec![request_item],
        constraints: None,
    })
}

fn run_generate_test_request(
    cli: &Cli,
    issuer_schema_id: u64,
    signal: &str,
    expires_in: u64,
) -> eyre::Result<()> {
    let request = build_test_request(issuer_schema_id, signal, expires_in)?;
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

    if !cli.json {
        eprintln!("Issuing test credential from faux issuer...");
    }
    let issued = issue_test_credential(&authenticator, &store).await?;

    if !cli.json {
        eprintln!("Generating test proof request...");
    }
    let proof_request = build_test_request(FAUX_ISSUER_SCHEMA_ID, signal, 300)?;

    if !cli.json {
        eprintln!("Generating proof...");
    }
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs();
    let walletkit_request =
        ProofRequest::from_json(&serde_json::to_string(&proof_request)?)
            .wrap_err("invalid proof request")?;
    let proof_response = authenticator
        .generate_proof(&walletkit_request, Some(ts))
        .await
        .wrap_err("proof generation failed")?;

    if !cli.json {
        eprintln!("Verifying proof on-chain...");
    }
    let results =
        verify_proof_onchain(cli, &proof_request, &proof_response.0, None).await?;
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
        } => run_generate_test_request(cli, *issuer_schema_id, signal, *expires_in),
        ProofCommand::Verify {
            request,
            response,
            verifier_address,
        } => run_verify(cli, request, response, verifier_address.as_deref()).await,
        ProofCommand::Test { signal } => run_test(cli, signal).await,
    }
}
