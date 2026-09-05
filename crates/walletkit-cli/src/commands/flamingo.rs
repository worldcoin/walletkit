//! Image-to-attested-statement demo over the verifier host's HTTP API.

use std::{
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::{Args, Subcommand};
use eyre::{ensure, WrapErr as _};
use flamingo_verifier_protocol::match_token::{
    self, EdDSAPublicKey, MatchClaims, MatchToken,
};
use pontifex::{PcrConfig, Verifier};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use walletkit_core::flamingo::{
    FlamingoMatchOutcome, FlamingoMatchRequest, FlamingoMatcher,
};

use super::Cli;
use crate::output;

#[derive(Subcommand)]
pub enum FlamingoCommand {
    /// Compare three image files and save a verified statement (not a ZK proof).
    Match(MatchArgs),
}

#[derive(Args)]
pub struct MatchArgs {
    /// Forwarded HTTP host URL, e.g. <http://127.0.0.1:8000>.
    #[arg(long, default_value = "http://127.0.0.1:8000")]
    host_url: String,
    /// Trusted PCR0/1/2 JSON. Omit to use `WalletKit`'s hardcoded measurements.
    #[arg(long)]
    measurements: Option<PathBuf>,
    /// Reference image (the enrolled thumbnail when using a real PCP).
    #[arg(long)]
    credential_image: PathBuf,
    /// Live capture image.
    #[arg(long)]
    live_image: PathBuf,
    /// RP challenge image.
    #[arg(long)]
    challenge_image: PathBuf,
    /// Exact hashes.json from a PCP; omitted means generate a demo commitment.
    #[arg(long)]
    hashes_json: Option<PathBuf>,
    /// Optional second live frame for servers supporting `LightGuard`.
    #[arg(long)]
    light_guard_image: Option<PathBuf>,
    /// Similarity threshold in [0, 1].
    #[arg(long, default_value = "0.9", value_parser = parse_threshold)]
    threshold: f32,
    /// Statement JSON destination. Existing files are never overwritten.
    #[arg(long, default_value = "flamingo-statement.json")]
    output: PathBuf,
}

fn parse_threshold(value: &str) -> Result<f32, String> {
    let value: f32 = value.parse().map_err(|_| "threshold must be a number")?;
    if value.is_finite() && (0.0..=1.0).contains(&value) {
        Ok(value)
    } else {
        Err("threshold must be finite and between 0 and 1".to_string())
    }
}

#[expect(clippy::too_many_lines)]
pub async fn run(cli: &Cli, command: &FlamingoCommand) -> eyre::Result<()> {
    let FlamingoCommand::Match(args) = command;
    let measurements = args
        .measurements
        .as_ref()
        .map(|path| {
            let bytes = fs::read(path)
                .wrap_err_with(|| format!("cannot read {}", path.display()))?;
            let json = serde_json::from_slice(&bytes)
                .wrap_err_with(|| format!("invalid JSON in {}", path.display()))?;
            parse_measurements(&json)
                .wrap_err_with(|| format!("invalid measurements in {}", path.display()))
        })
        .transpose()?;
    let credential_image = fs::read(&args.credential_image)
        .wrap_err_with(|| format!("cannot read {}", args.credential_image.display()))?;
    let hashes_json = match &args.hashes_json {
        Some(path) => fs::read(path)
            .wrap_err_with(|| format!("cannot read {}", path.display()))?,
        None => demo_hashes_json(&credential_image),
    };
    let request = FlamingoMatchRequest {
        live_image: fs::read(&args.live_image)
            .wrap_err_with(|| format!("cannot read {}", args.live_image.display()))?,
        credential_image,
        hashes_json,
        light_guard_image: args
            .light_guard_image
            .as_deref()
            .map(|path| {
                fs::read(path)
                    .wrap_err_with(|| format!("cannot read {}", path.display()))
            })
            .transpose()?,
        challenge_image: fs::read(&args.challenge_image).wrap_err_with(|| {
            format!("cannot read {}", args.challenge_image.display())
        })?,
        match_threshold: args.threshold,
    };

    validate_thumbnail(&request.credential_image, &request.hashes_json)?;
    let expected = ExpectedClaims {
        live: Sha256::digest(&request.live_image).into(),
        credential: Sha256::digest(&request.hashes_json).into(),
        challenge: Sha256::digest(&request.challenge_image).into(),
        threshold: args.threshold,
    };

    let matcher = FlamingoMatcher::with_measurements(&args.host_url, measurements)?;

    if !cli.json {
        eprintln!("Attested face-match demo — no ZK proof or enrollment verification.");
        eprintln!(
            "Credential commitment: {}",
            if args.hashes_json.is_some() {
                "provided PCP hashes.json"
            } else {
                "generated from reference image"
            }
        );
        eprintln!(
            "Calling {} (PCR0/1/2 verification, encrypted request and response)...",
            args.host_url
        );
    }

    let started = Instant::now();
    let result = matcher
        .perform_match(request)
        .await
        .wrap_err("attested match failed")?;

    let statement = match result {
        FlamingoMatchOutcome::Matched(statement) => statement,
        FlamingoMatchOutcome::Rejected(reason) => {
            eyre::bail!("match response reported a rejection: {reason:?}")
        }
    };
    let measurements =
        measurements.unwrap_or_else(FlamingoMatcher::default_measurements);
    let claims = verify_statement(&statement, &measurements, &expected)?;
    let artifact = statement_artifact(&statement, &claims);
    save_statement(&args.output, &artifact)?;

    if cli.json {
        output::print_json_data(
            &json!({"matched": true, "statement_path": args.output,
            "claims": artifact["claims"], "elapsed_seconds": started.elapsed().as_secs_f64()}),
            true,
        );
    } else {
        println!(
            "{} Enclave attestations and token signature verified",
            output::pass_label()
        );
        println!("{} All three input commitments match", output::pass_label());
        println!(
            "Live similarity: {:.6} (requested threshold: {:.6})",
            claims.match_coefficient, args.threshold
        );
        println!(
            "Statement + signing-key attestation: {}",
            args.output.display()
        );
        println!("Completed in {:.2}s", started.elapsed().as_secs_f64());
    }

    Ok(())
}

fn parse_measurements(value: &Value) -> eyre::Result<[[u8; 48]; 3]> {
    // Accept both the build script's flat JSON and nitro-cli's Measurements envelope.
    let value = value.get("Measurements").unwrap_or(value);
    let mut result = [[0; 48]; 3];
    for (index, name) in ["PCR0", "PCR1", "PCR2"].iter().enumerate() {
        let hex = value
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| eyre::eyre!("measurements must contain {name}"))?;
        let bytes = hex::decode(hex.strip_prefix("0x").unwrap_or(hex))
            .wrap_err_with(|| format!("invalid hex for {name}"))?;
        result[index] = bytes.try_into().map_err(|_| {
            eyre::eyre!("{name} must be exactly 48 bytes (96 hex characters)")
        })?;
        ensure!(
            result[index].iter().any(|byte| *byte != 0),
            "{name} is zero; debug enclave measurements are not accepted"
        );
    }
    Ok(result)
}

fn demo_hashes_json(credential_image: &[u8]) -> Vec<u8> {
    format!(
        r#"{{"thumbnail.png":"{}"}}"#,
        hex::encode(Sha256::digest(credential_image))
    )
    .into_bytes()
}

fn validate_thumbnail(image: &[u8], hashes: &[u8]) -> eyre::Result<()> {
    let hashes: Value =
        serde_json::from_slice(hashes).wrap_err("invalid hashes.json")?;
    let hash = hashes
        .get("thumbnail.png")
        .and_then(Value::as_str)
        .ok_or_else(|| eyre::eyre!("hashes.json is missing thumbnail.png"))?;
    let committed = hex::decode(hash).wrap_err("invalid thumbnail.png hash")?;
    ensure!(
        committed.as_slice() == Sha256::digest(image).as_slice(),
        "credential image does not match hashes.json thumbnail.png"
    );
    Ok(())
}

struct ExpectedClaims {
    live: [u8; 32],
    credential: [u8; 32],
    challenge: [u8; 32],
    threshold: f32,
}

fn verify_statement(
    statement: &walletkit_core::flamingo::VerifiedMatchToken,
    measurements: &[[u8; 48]; 3],
    expected: &ExpectedClaims,
) -> eyre::Result<MatchClaims> {
    // Independently read the signed claims and bind the returned artifact to these input files.
    let key = attested_signing_key(statement.signing_key_attestation(), measurements)?;
    let claims = match_token::verify(
        &MatchToken::from_bytes(statement.as_bytes().to_vec()),
        &key,
    )
    .map_err(|error| eyre::eyre!("invalid match token: {error:?}"))?;
    expected.check(&claims)?;
    Ok(claims)
}

fn attested_signing_key(
    document: &[u8],
    measurements: &[[u8; 48]; 3],
) -> eyre::Result<EdDSAPublicKey> {
    let policy = Verifier::new(
        vec![PcrConfig::new(measurements[0])
            .with_pcr(1, measurements[1])
            .with_pcr(2, measurements[2])],
        Duration::from_secs(3_600),
    );
    let attestation = policy.verify_attestation_document(document)?;
    let key: [u8; 32] = attestation
        .document()
        .public_key
        .as_ref()
        .ok_or_else(|| eyre::eyre!("attested signing key is missing"))?
        .as_slice()
        .try_into()
        .map_err(|_| eyre::eyre!("attested signing key is not 32 bytes"))?;
    EdDSAPublicKey::from_compressed_bytes(key)
        .map_err(|error| eyre::eyre!("invalid signing key: {error:?}"))
}

impl ExpectedClaims {
    fn check(&self, claims: &MatchClaims) -> eyre::Result<()> {
        ensure!(
            claims.live_image_hash == self.live,
            "signed live image hash differs from submitted image"
        );
        ensure!(
            claims.credential_claim == self.credential,
            "signed credential commitment differs from submitted hashes.json"
        );
        ensure!(
            claims.challenger_image_hash == self.challenge,
            "signed challenge image hash differs from the original challenge"
        );
        ensure!(
            claims.match_coefficient.is_finite()
                && claims.match_coefficient >= self.threshold,
            "signed live similarity is below the requested threshold"
        );
        Ok(())
    }
}

fn statement_artifact(
    statement: &walletkit_core::flamingo::VerifiedMatchToken,
    claims: &MatchClaims,
) -> Value {
    json!({
        "format": "walletkit-flamingo-demo-v1",
        "token_base64": STANDARD.encode(statement.as_bytes()),
        "signing_key_attestation_base64": STANDARD.encode(statement.signing_key_attestation()),
        "claims": {
            "live_image_hash": hex::encode(claims.live_image_hash),
            "credential_claim": hex::encode(claims.credential_claim),
            "challenger_image_hash": hex::encode(claims.challenger_image_hash),
            "match_coefficient": claims.match_coefficient,
        },
    })
}

fn save_statement(path: impl AsRef<Path>, statement: &Value) -> eyre::Result<()> {
    let path = path.as_ref();
    let encoded = serde_json::to_vec_pretty(statement)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .wrap_err_with(|| format!("cannot open {} for writing", path.display()))?;
    file.write_all(&encoded)
        .wrap_err("cannot write statement")?;
    file.write_all(b"\n")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn measurements() -> Value {
        json!({"PCR0": "42".repeat(48), "PCR1": "43".repeat(48), "PCR2": "44".repeat(48)})
    }

    #[test]
    fn rejects_an_untrusted_attestation_even_when_the_pcrs_match() {
        use ciborium::Value as Cbor;
        use pontifex::{attestation::Error, nsm::Digest, AttestationDoc};

        let measurements = [[0x42; 48], [0x43; 48], [0x44; 48]];
        // A parseable document with matching pins is insufficient: the signing key must
        // come from a document with a valid certificate chain and COSE signature.
        let document = AttestationDoc {
            module_id: "untrusted-test-enclave".to_owned(),
            digest: Digest::SHA384,
            timestamp: 0,
            pcrs: measurements
                .iter()
                .enumerate()
                .map(|(index, bytes)| (index, bytes.to_vec().into()))
                .collect(),
            certificate: Vec::new().into(),
            cabundle: Vec::new(),
            public_key: Some(vec![1; 32].into()),
            user_data: None,
            nonce: None,
        };
        let mut payload = Vec::new();
        ciborium::into_writer(&document, &mut payload).unwrap();
        let mut protected = Vec::new();
        ciborium::into_writer(
            &Cbor::Map(vec![(Cbor::Integer(1.into()), Cbor::Integer((-35).into()))]),
            &mut protected,
        )
        .unwrap();
        let envelope = Cbor::Array(vec![
            Cbor::Bytes(protected),
            Cbor::Map(Vec::new()),
            Cbor::Bytes(payload),
            Cbor::Bytes(vec![0; 96]),
        ]);
        let mut encoded = Vec::new();
        ciborium::into_writer(&envelope, &mut encoded).unwrap();

        let error = attested_signing_key(&encoded, &measurements).unwrap_err();
        assert!(matches!(
            error.downcast_ref::<Error>(),
            Some(Error::ChainInvalid(_))
        ));
    }

    #[test]
    fn requires_all_three_nonzero_full_length_measurements() {
        assert_eq!(
            parse_measurements(&measurements()).unwrap(),
            [[0x42; 48], [0x43; 48], [0x44; 48]]
        );
        assert_eq!(
            parse_measurements(&json!({"Measurements": measurements()})).unwrap(),
            parse_measurements(&measurements()).unwrap()
        );
        for pcr in ["PCR0", "PCR1", "PCR2"] {
            for invalid in [
                Value::Null,
                json!("00".repeat(48)),
                json!("42".repeat(47)),
                json!("gg".repeat(48)),
            ] {
                let mut value = measurements();
                value[pcr] = invalid;
                assert!(parse_measurements(&value).is_err());
            }
        }
    }

    #[test]
    fn generated_hashes_bind_only_the_supplied_reference() {
        let hashes = demo_hashes_json(b"reference");
        validate_thumbnail(b"reference", &hashes).unwrap();
        assert!(validate_thumbnail(b"other reference", &hashes).is_err());
    }

    #[test]
    fn detects_substituted_inputs_and_insufficient_score() {
        let expected = ExpectedClaims {
            live: [1; 32],
            credential: [2; 32],
            challenge: [3; 32],
            threshold: 0.7,
        };
        let claims = MatchClaims {
            live_image_hash: expected.live,
            credential_claim: expected.credential,
            challenger_image_hash: expected.challenge,
            match_coefficient: 0.8,
        };
        expected.check(&claims).unwrap();
        for altered in [
            MatchClaims {
                live_image_hash: [4; 32],
                ..claims
            },
            MatchClaims {
                credential_claim: [4; 32],
                ..claims
            },
            MatchClaims {
                challenger_image_hash: [4; 32],
                ..claims
            },
            MatchClaims {
                match_coefficient: 0.6,
                ..claims
            },
            MatchClaims {
                match_coefficient: f32::NAN,
                ..claims
            },
        ] {
            assert!(expected.check(&altered).is_err());
        }
    }

    #[test]
    fn statement_output_overwrites_existing_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("statement.json");
        save_statement(&path, &json!({"token": "longer original token"})).unwrap();
        save_statement(&path, &json!({"token": "second"})).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(path).unwrap()).unwrap()["token"],
            "second"
        );
    }

    #[test]
    fn rejects_nonfinite_and_out_of_range_thresholds() {
        for input in ["NaN", "inf", "-0.1", "1.1"] {
            assert!(parse_threshold(input).is_err());
        }
        assert!(parse_threshold("0.9").is_ok());
    }
}
