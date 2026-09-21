//! Browser bindings for attested Flamingo matching.
//!
//! Attestation verification, encryption, and result verification stay in Rust.
//! These bindings do not implement camera capture, enrollment, or World ID proving.

use std::{collections::HashMap, sync::Arc};

use serde::Deserialize;
use walletkit_core::flamingo::{
    FlamingoError, FlamingoMatchOutcome, FlamingoMatchRejection, FlamingoMatchRequest,
    FlamingoMatcher, VerifiedMatchToken,
};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(typescript_custom_section)]
const TYPES: &str = r#"
export interface FlamingoConfig {
    hostUrl: string;
    /** Approved, nonzero 48-byte measurements encoded as hex. PCR0, 1 and 2 are required. */
    measurements: Record<number, string>;
    /** Service authorization headers, never the user's identity or backup secrets. */
    headers?: Record<string, string>;
}
export interface FlamingoMatchInput {
    liveImage: Uint8Array;
    credentialImage: Uint8Array;
    /** Exact PCP archive bytes; do not parse and reserialize. */
    hashesJson: Uint8Array;
    challengeImage: Uint8Array;
    matchThreshold: number;
}
export type FlamingoErrorCode = "invalid_input" | "configuration" | "verifier";
export interface FlamingoClientError extends Error { code: FlamingoErrorCode; }
"#;

#[wasm_bindgen]
extern "C" {
    /// Browser client configuration.
    #[wasm_bindgen(typescript_type = "FlamingoConfig")]
    pub type FlamingoConfig;

    /// Inputs for the existing three-way match operation.
    #[wasm_bindgen(typescript_type = "FlamingoMatchInput")]
    pub type FlamingoMatchInput;
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Config {
    host_url: String,
    measurements: HashMap<String, String>,
    #[serde(default)]
    headers: HashMap<String, String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Input {
    #[serde(with = "serde_bytes")]
    live_image: Vec<u8>,
    #[serde(with = "serde_bytes")]
    credential_image: Vec<u8>,
    #[serde(with = "serde_bytes")]
    hashes_json: Vec<u8>,
    #[serde(with = "serde_bytes")]
    challenge_image: Vec<u8>,
    match_threshold: f32,
}

/// Browser client using `WalletKit`'s measurement-pinned Flamingo matcher.
#[wasm_bindgen]
pub struct FlamingoClient {
    inner: FlamingoMatcher,
}

#[wasm_bindgen]
impl FlamingoClient {
    /// Creates a client. No network request is made until `performMatch`.
    ///
    /// # Errors
    /// Rejects malformed configuration and missing, zero, or invalid measurements.
    #[wasm_bindgen(constructor)]
    pub fn new(config: FlamingoConfig) -> Result<Self, JsValue> {
        let config: Config = serde_wasm_bindgen::from_value(config.into())
            .map_err(|_| error("configuration", "Invalid Flamingo configuration"))?;
        let measurements = config
            .measurements
            .into_iter()
            .map(|(index, value)| {
                let index = index.parse::<u32>().map_err(|_| {
                    error("configuration", "Measurement keys must be PCR indices")
                })?;
                hex::decode(value.strip_prefix("0x").unwrap_or(&value))
                    .map(|bytes| (index, bytes))
                    .map_err(|_| {
                        error("configuration", "Measurements must be hex encoded")
                    })
            })
            .collect::<Result<HashMap<_, _>, _>>()?;
        let inner = FlamingoMatcher::new(&config.host_url)
            .and_then(|client| client.with_measurements(measurements))
            .and_then(|client| client.with_headers(config.headers))
            .map_err(client_error)?;
        Ok(Self { inner })
    }

    /// Performs an attested, encrypted three-way match.
    ///
    /// # Errors
    /// Rejects invalid inputs, untrusted attestation, transport failures, or unverifiable results.
    #[wasm_bindgen(js_name = performMatch)]
    #[cfg_attr(
        target_arch = "wasm32",
        expect(
            clippy::future_not_send,
            reason = "browser Fetch futures stay on the originating JavaScript worker"
        )
    )]
    pub async fn perform_match(
        &self,
        input: FlamingoMatchInput,
    ) -> Result<MatchOutcome, JsValue> {
        let input: Input = serde_wasm_bindgen::from_value(input.into())
            .map_err(|_| error("invalid_input", "Invalid Flamingo match input"))?;
        let inner = self
            .inner
            .perform_match(FlamingoMatchRequest {
                live_image: input.live_image,
                credential_image: input.credential_image,
                hashes_json: input.hashes_json,
                challenge_image: input.challenge_image,
                light_guard_image: None,
                match_threshold: input.match_threshold,
            })
            .await
            .map_err(client_error)?;
        Ok(MatchOutcome { inner })
    }
}

/// Verified success or a typed, unsigned rejection. Neither is a World ID proof.
#[wasm_bindgen]
pub struct MatchOutcome {
    inner: FlamingoMatchOutcome,
}

#[wasm_bindgen]
impl MatchOutcome {
    /// Whether a signed match token was verified against its attested signing key.
    #[wasm_bindgen(getter)]
    #[must_use]
    #[expect(
        clippy::missing_const_for_fn,
        reason = "wasm-bindgen cannot export const functions"
    )]
    pub fn matched(&self) -> bool {
        matches!(self.inner, FlamingoMatchOutcome::Matched(_))
    }

    /// The rejection code, or `undefined` for success. Rejections are not signed evidence.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn rejection(&self) -> Option<String> {
        let FlamingoMatchOutcome::Rejected(reason) = &self.inner else {
            return None;
        };
        Some(
            match reason {
                FlamingoMatchRejection::MalformedInputs => "malformed_inputs",
                FlamingoMatchRejection::InvalidHashesJson => "invalid_hashes_json",
                FlamingoMatchRejection::ThumbnailHashMismatch => {
                    "thumbnail_hash_mismatch"
                }
                FlamingoMatchRejection::MatchBelowThreshold => "match_below_threshold",
                FlamingoMatchRejection::ImageAnalysisFailed => "image_analysis_failed",
            }
            .to_owned(),
        )
    }

    /// An opaque verified token handle for later Rust proof integration.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn verified(&self) -> Option<VerifiedMatch> {
        match &self.inner {
            FlamingoMatchOutcome::Matched(token) => Some(VerifiedMatch {
                inner: Arc::clone(token),
            }),
            FlamingoMatchOutcome::Rejected(_) => None,
        }
    }
}

/// Opaque match evidence, constructible only after verification succeeds.
/// The signed biometric commitments are not exported as a JavaScript byte buffer.
#[wasm_bindgen]
pub struct VerifiedMatch {
    inner: Arc<VerifiedMatchToken>,
}

#[wasm_bindgen]
impl VerifiedMatch {
    /// Signing-key attestation to accompany a future proof; not a proof of matching itself.
    #[wasm_bindgen(js_name = signingKeyAttestation)]
    #[must_use]
    pub fn signing_key_attestation(&self) -> Vec<u8> {
        self.inner.signing_key_attestation().to_vec()
    }
}

fn client_error(value: FlamingoError) -> JsValue {
    match value {
        FlamingoError::InvalidInput { attribute, reason } => {
            error("invalid_input", &format!("Invalid {attribute}: {reason}"))
        }
        FlamingoError::Configuration(_) => {
            error("configuration", "Invalid Flamingo configuration")
        }
        // Underlying HTTP errors can contain URLs or service response data. Keep the public error
        // stable and avoid forwarding those details to analytics or a parent page.
        FlamingoError::Verifier(_) => {
            error("verifier", "Flamingo request or verification failed")
        }
    }
}

fn error(code: &str, message: &str) -> JsValue {
    let value = js_sys::Error::new(message);
    value.set_name("FlamingoError");
    let _ = js_sys::Reflect::set(&value, &"code".into(), &code.into());
    value.into()
}
