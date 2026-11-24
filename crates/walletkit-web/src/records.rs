//! The records and enums that cross the worker boundary as plain data.
//!
//! Each `#[js_type]` declaration generates the TypeScript type of the same name and
//! the [`ToJs`](crate::js::ToJs) / [`FromJs`](crate::js::FromJs) conversions. Most
//! describe a type from `walletkit-core` or the selfie enrollment client
//! (`remote = ...`), whose fields they must list in full. The declared names stand
//! for those types only inside these declarations, so this module imports the
//! remote types by module, not by name.

use ruint_uniffi::Uint256;
use selfie_enrollment_api_types::POSEGUARD_CHALLENGE_COUNT;
use selfie_enrollment_client as client;
use selfie_enrollment_sealed_types as sealed;
use walletkit_core::{
    logger, proof_request_credential_constraints_check as constraints, storage,
};
use walletkit_web_macros::js_type;
use wasm_bindgen::prelude::*;

use crate::{enrollment::poseguard_images_from_js, js};

#[js_type(remote = walletkit_core::Environment, input)]
enum Environment {
    Production,
    Staging,
}

#[js_type(remote = walletkit_core::Region, input)]
enum Region {
    Eu,
    Us,
    Ap,
}

#[js_type(remote = logger::LogLevel, input)]
enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[js_type(remote = walletkit_core::RecoveryData, output)]
struct RecoveryData {
    authenticator_address: String,
    authenticator_pubkey: String,
    offchain_signer_commitment: String,
}

#[js_type(remote = walletkit_core::RecoveryUpdateSignature, output)]
struct RecoveryUpdateSignature {
    signature: Vec<u8>,
    /// 0x-prefixed, zero-padded 256-bit hex string.
    #[js(ts = "string", to_js = padded_hex)]
    nonce: Uint256,
}

#[js_type(remote = walletkit_core::RegistrationStatus, output, tag = "state")]
enum RegistrationStatus {
    Queued,
    Batching,
    Submitted,
    Finalized,
    Failed {
        error: String,
        error_code: Option<String>,
    },
}

#[js_type(remote = walletkit_core::GatewayRequestStatus, output, tag = "state")]
enum GatewayRequestStatus {
    Queued,
    Batching,
    Submitted {
        tx_hash: String,
    },
    Finalized {
        tx_hash: String,
    },
    Failed {
        error: String,
        error_code: Option<String>,
    },
}

#[js_type(remote = storage::CredentialRecord, output)]
struct CredentialRecord {
    credential_id: u64,
    issuer_schema_id: u64,
    genesis_issued_at: u64,
    expires_at: u64,
    is_expired: bool,
}

#[js_type(remote = storage::ActivityOutcome, input, output, rename_all = "lowercase")]
enum ActivityOutcome {
    Completed,
    Declined,
    Cancelled,
    Failed,
    Incomplete,
}

#[js_type(
    remote = storage::ActivityFailureReason,
    input,
    output,
    rename_all = "lowercase"
)]
enum ActivityFailureReason {
    NetworkError,
    Timeout,
    DeviceAuthenticationFailed,
    ProofGenerationFailed,
    RelyingPartyRejected,
}

#[js_type(remote = storage::ActivityEntry, input, output)]
struct ActivityEntry {
    id: Option<u64>,
    rp_id: u64,
    app_identifier: String,
    client_id: String,
    /// Local-only diagnostic ID. Excluded from vault backups; keep out of logs.
    challenge_id: Option<String>,
    /// World ID protocol version.
    #[js(ts = "3 | 4", to_js = protocol_to_js, from_js = protocol_from_js)]
    protocol: storage::ProtocolVersion,
    timestamp: Option<u64>,
    outcome: ActivityOutcome,
    issuer_schema_ids: Vec<u64>,
    failure_reason: Option<ActivityFailureReason>,
}

#[js_type(remote = storage::ActivityMetadata, output)]
struct ActivityMetadata {
    total_count: u64,
}

#[js_type(remote = constraints::CredentialConstraintsCheckItem, output)]
struct CredentialConstraintsCheckItem {
    identifier: String,
    issuer_schema_id: u64,
    has_credential: bool,
}

#[js_type(remote = constraints::CredentialConstraintsCheckResult, output)]
struct CredentialConstraintsCheckResult {
    is_satisfied: bool,
    check_results: Vec<CredentialConstraintsCheckItem>,
}

#[js_type(remote = sealed::FaceEmbedding, output)]
struct FaceEmbedding {
    embedding: String,
    embedding_type: String,
    embedding_version: String,
    embedding_inference_backend: String,
}

#[js_type(remote = sealed::ChallengeFailure, output)]
enum SelfieChallengeFailure {
    InvalidImage,
    QualityRejected,
    ExtractionFailed,
    PoseMismatch,
    IdentityMismatch,
}

#[js_type(remote = sealed::Failure, output, tag = "reason")]
enum SelfieFailure {
    InvalidImage,
    QualityRejected,
    ExtractionFailed,
    InvalidRequest,
    Challenge {
        index: u32,
        #[js(rename = "challengeReason")]
        reason: SelfieChallengeFailure,
    },
}

/// Embedding extraction never reports a challenge failure; the facade rejects one
/// as a protocol error.
#[js_type(remote = sealed::EmbeddingResult, output, tag = "status")]
enum SelfieEmbeddingResult {
    Success {
        embedding: FaceEmbedding,
    },
    Failed {
        #[js(flatten, ts = "Exclude<SelfieFailure, { reason: \"challenge\" }>")]
        reason: SelfieFailure,
    },
}

#[js_type(remote = sealed::EnrollmentField, output)]
struct SelfieEnrollmentField {
    name: String,
    value: String,
}

#[js_type(remote = sealed::EnrollmentBundle, output)]
struct SelfieEnrollmentBundle {
    // An object type, not the interface, so a field stays assignable to
    // `Record<string, string>`.
    #[js(ts = "Pick<SelfieEnrollmentField, keyof SelfieEnrollmentField>[]")]
    fields: Vec<SelfieEnrollmentField>,
    attestation_header: String,
    encrypted_custody: Vec<u8>,
}

#[js_type(remote = sealed::EnrollmentResult, output, tag = "status")]
enum SelfieEnrollmentResult {
    Success {
        enrollment: SelfieEnrollmentBundle,
    },
    Failed {
        #[js(flatten)]
        reason: SelfieFailure,
    },
}

#[wasm_bindgen(typescript_custom_section)]
const TS_SELFIE_CAPTURE_FAILURE: &str = r#"
export type SelfieCaptureFailure = Exclude<SelfieEnrollmentResult, { status: "success" }>;
"#;

/// Signed angles in degrees in the captured image: negative yaw is left, negative pitch is down.
#[js_type(remote = client::PoseGuardTarget, output, readonly)]
struct PoseGuardTarget {
    target_pitch: f32,
    target_yaw: f32,
}

/// A verified `PoseGuard` prompt, as the page's capture callback receives it.
#[js_type(output, readonly)]
pub struct PoseGuardPrompt {
    #[js(ts = "readonly [PoseGuardTarget, PoseGuardTarget, PoseGuardTarget]")]
    pub targets: [client::PoseGuardTarget; POSEGUARD_CHALLENGE_COUNT],
    /// Enclave expiry in Unix seconds.
    pub expires_at: f64,
    /// Milliseconds remaining when the worker sent this prompt.
    pub capture_timeout_ms: f64,
}

#[js_type(remote = client::PoseGuardImages, input, from_js = poseguard_images_from_js)]
struct PoseGuardImages {
    central_png: Vec<u8>,
    /// One image for each target, in the issued order.
    #[js(ts = "readonly [Uint8Array, Uint8Array, Uint8Array]")]
    captures: [Vec<u8>; POSEGUARD_CHALLENGE_COUNT],
}

impl js::JsSchema for Uint256 {
    type Schema = Self;
}

impl js::JsSchema for storage::ProtocolVersion {
    type Schema = Self;
}

#[allow(clippy::unnecessary_wraps, reason = "the signature `to_js` expects")]
fn padded_hex(value: &Uint256) -> Result<JsValue, JsValue> {
    Ok(value.to_padded_hex_string().into())
}

#[allow(
    clippy::unnecessary_wraps,
    clippy::trivially_copy_pass_by_ref,
    reason = "the signature `to_js` expects"
)]
fn protocol_to_js(protocol: &storage::ProtocolVersion) -> Result<JsValue, JsValue> {
    Ok(f64::from(*protocol as u8).into())
}

fn protocol_from_js(
    value: &JsValue,
    name: &str,
) -> Result<storage::ProtocolVersion, JsValue> {
    match value.as_f64() {
        Some(3.0) => Ok(storage::ProtocolVersion::V3),
        Some(4.0) => Ok(storage::ProtocolVersion::V4),
        _ => Err(js::expected(name, "3 or 4")),
    }
}

#[cfg(test)]
mod tests {
    use walletkit_core::{storage::ActivityEntry, RegistrationStatus};
    use wasm_bindgen_test::wasm_bindgen_test;

    use super::*;
    use crate::js::{FromJs, ToJs};

    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_dedicated_worker);

    fn json(value: &JsValue) -> serde_json::Value {
        let json = js_sys::JSON::stringify(value).unwrap().as_string().unwrap();
        serde_json::from_str(&json).unwrap()
    }

    fn type_error(error: &JsValue) -> String {
        let error = error.dyn_ref::<js_sys::TypeError>().unwrap();
        error.message().into()
    }

    #[wasm_bindgen_test]
    fn tagged_enum_names_its_variant_and_fields() {
        let failed = RegistrationStatus::Failed {
            error: "rejected".into(),
            error_code: Some("E1".into()),
        };
        assert_eq!(
            json(&failed.to_js().unwrap()),
            serde_json::json!({ "state": "failed", "error": "rejected", "errorCode": "E1" }),
        );
        assert_eq!(
            json(&RegistrationStatus::Queued.to_js().unwrap()),
            serde_json::json!({ "state": "queued" }),
        );
    }

    #[wasm_bindgen_test]
    #[expect(clippy::manual_assert_eq, reason = "`ActivityEntry` has no `Debug`")]
    fn activity_entry_round_trips() {
        let entry = ActivityEntry {
            id: Some(7),
            rp_id: 1,
            app_identifier: "app_test".into(),
            client_id: "client".into(),
            protocol: storage::ProtocolVersion::V3,
            timestamp: None,
            outcome: storage::ActivityOutcome::Failed,
            issuer_schema_ids: vec![1, 2],
            failure_reason: Some(storage::ActivityFailureReason::NetworkError),
            challenge_id: None,
        };
        let value = entry.to_js().unwrap();
        assert_eq!(js::get(&value, "protocol").unwrap(), JsValue::from(3));
        assert_eq!(
            js::get(&value, "failureReason").unwrap(),
            JsValue::from_str("networkerror")
        );
        assert!(js::get(&value, "timestamp").unwrap().is_undefined());
        assert!(ActivityEntry::from_js(value, "entry").unwrap() == entry);
    }

    #[wasm_bindgen_test]
    fn invalid_activity_entries_name_the_field() {
        let valid = || {
            let object = js_sys::Object::new();
            for (key, value) in [
                ("rpId", JsValue::from(1_u64)),
                ("appIdentifier", "app".into()),
                ("clientId", "client".into()),
                ("protocol", 4.into()),
                ("outcome", "completed".into()),
                ("issuerSchemaIds", js::array([JsValue::from(1_u64)])),
            ] {
                js::set(&object, key, &value).unwrap();
            }
            object
        };
        let rejected = |key: &str, value: JsValue| {
            let entry = valid();
            js::set(&entry, key, &value).unwrap();
            type_error(&ActivityEntry::from_js(entry.into(), "entry").unwrap_err())
        };

        assert!(ActivityEntry::from_js(valid().into(), "entry").is_ok());
        assert_eq!(rejected("outcome", "won".into()), "Unknown outcome: won");
        assert_eq!(rejected("protocol", 5.into()), "`protocol` must be 3 or 4");
        assert!(rejected("rpId", 1.into()).starts_with("`rpId` must be a bigint"));
        assert!(
            rejected("issuerSchemaIds", JsValue::from(-1)).contains("must be an array")
        );
        assert!(rejected("issuerSchemaIds", js::array([JsValue::from(-1)]))
            .starts_with("`issuerSchemaIds[0]` must be a bigint"));
        assert_eq!(
            rejected("clientId", JsValue::NULL),
            "`clientId` must be a string"
        );
        assert_eq!(
            type_error(&ActivityEntry::from_js(JsValue::NULL, "entry").unwrap_err()),
            "`entry` must be an object"
        );
    }
}
