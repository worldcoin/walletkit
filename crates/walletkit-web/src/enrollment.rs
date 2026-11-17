//! Embedding extraction and `PoseGuard` enrollment over the dedicated TEE channel.
use js_sys::{Array, Promise, Reflect, Uint8Array};
use selfie_enrollment_api_types::{MAX_IMAGE_BYTES, POSEGUARD_CHALLENGE_COUNT};
use selfie_enrollment_client::{Config, EnrollmentClient, Error};
use selfie_enrollment_sealed_types::{
    ChallengeFailure, EmbeddingResult, EnrollmentResult, Failure, PoseGuardCapture,
};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::{
    error::{invalid_argument, to_js},
    js,
};

#[wasm_bindgen(typescript_custom_section)]
const TS_TYPES: &str = r#"
export type SelfieEmbeddingResult =
  | { status: "success"; embedding: FaceEmbedding }
  | { status: "failed"; reason: "invalid_image" | "quality_rejected" | "extraction_failed" | "invalid_request" };

export type SelfieCaptureFailure =
  | Exclude<SelfieEmbeddingResult, { status: "success" }>
  | { status: "failed"; reason: "challenge"; index: number; challengeReason: "invalid_image" | "quality_rejected" | "extraction_failed" | "pose_mismatch" | "identity_mismatch" };

export interface PoseGuardCapture {
  image: Uint8Array;
  targetPitch: number;
  targetYaw: number;
}

export type PoseGuardCaptures = [PoseGuardCapture, PoseGuardCapture, PoseGuardCapture];

export interface SelfieEnrollmentBundle {
  fields: { name: string; value: string }[];
  attestationHeader: string;
  encryptedCustody: Uint8Array;
}

export type SelfieEnrollmentResult =
  | { status: "success"; enrollment: SelfieEnrollmentBundle }
  | SelfieCaptureFailure;

export interface FaceEmbedding {
  embedding: string;
  embeddingType: string;
  embeddingVersion: string;
  embeddingInferenceBackend: string;
}
"#;

/// Extracts an embedding after verifying Nitro measurements.
///
/// `configJson` is the trusted release policy from the enrollment deployment.
/// The image is sealed inside this worker before upload and is never persisted.
///
/// Calls have a bounded deadline. Terminate the `WalletKit` instance to cancel an
/// in-flight enrollment immediately. This operation does not issue a credential.
///
/// # Errors
/// Throws a `TypeError` before connecting if `image` is empty or exceeds 8 MiB.
/// Throws a `SelfieEnrollmentError` for invalid policy, rejected attestation, or
/// transport failures. Image/quality rejections return a typed failed result.
#[wasm_bindgen(js_name = extractSelfieEmbedding, unchecked_return_type = "Promise<SelfieEmbeddingResult>")]
pub fn extract_selfie_embedding(config_json: String, image: &Uint8Array) -> Promise {
    // The worker zero-fills `image` as soon as this call returns, so copy it before
    // the deferred future runs.
    let mut image = match owned_image(image) {
        Ok(image) => image,
        Err(error) => return Promise::reject(&error),
    };
    js::promise(async move {
        let config: Config =
            serde_json::from_str(&config_json).map_err(|_| to_js(Error::Config))?;
        let result = selfie_enrollment_client::browser::extract(
            config,
            std::mem::take(&mut *image),
            None,
        )
        .await
        .map_err(to_js)?;
        result_to_js(&result)
    })
}

/// Submits a central PNG and three pose captures through the attested TEE channel.
///
/// The enclave returns the enrollment fields, Nitro header and PCP encrypted to
/// `custodyPublicKey`. Retain the PCP before adding the ownership challenge and
/// proof to the signup-service submission. The custody private key stays with the caller.
///
/// Targets are supplied with the captures; this call neither issues targets nor
/// binds them to a fresh enclave challenge. Terminate `WalletKit` to cancel.
///
/// # Errors
/// Throws a `TypeError` for an invalid batch, image or custody key. Invalid release
/// policy, attestation and transport errors reject with `SelfieEnrollmentError`.
/// Worker rejections return a typed failure, including the rejected capture index.
#[wasm_bindgen(js_name = enrollSelfieWithPoseGuard, unchecked_return_type = "Promise<SelfieEnrollmentResult>")]
pub fn enroll_selfie_with_poseguard(
    config_json: String,
    central_png: &Uint8Array,
    #[wasm_bindgen(unchecked_param_type = "PoseGuardCaptures")] captures: &JsValue,
    sub: String,
    custody_public_key: &Uint8Array,
) -> Promise {
    // Copy synchronously: the worker clears transferred arguments before polling the future.
    let input = (|| {
        let central = owned_image(central_png)?;
        if !central.starts_with(b"\x89PNG\r\n\x1a\n") {
            return Err(invalid_argument("`centralPng` must be a PNG"));
        }
        let captures = owned_captures(captures)?;
        if custody_public_key.length() != 32 {
            return Err(invalid_argument("`custodyPublicKey` must contain 32 bytes"));
        }
        let mut key = [0; 32];
        custody_public_key.copy_to(&mut key);
        Ok((central, captures, key))
    })();
    let (mut central, captures, key) = match input {
        Ok(input) => input,
        Err(error) => return Promise::reject(&error),
    };
    js::promise(async move {
        let config: Config =
            serde_json::from_str(&config_json).map_err(|_| to_js(Error::Config))?;
        let client = EnrollmentClient::new(config).map_err(to_js)?;
        // TODO: Bind submission to enclave-issued challenges when the TEE adds issuance:
        // https://github.com/worldcoin/biometrics-tee/pull/132
        let session = client.connect(None).await.map_err(to_js)?;
        let result = session
            .enroll_with_poseguard(std::mem::take(&mut *central), captures, sub, key)
            .await
            .map_err(to_js)?;
        enrollment_to_js(&result)
    })
}

fn owned_captures(
    value: &JsValue,
) -> Result<[PoseGuardCapture; POSEGUARD_CHALLENGE_COUNT], JsValue> {
    let captures = value
        .dyn_ref::<Array>()
        .filter(|captures| captures.length() as usize == POSEGUARD_CHALLENGE_COUNT)
        .ok_or_else(|| {
            invalid_argument("`captures` must contain exactly three poses")
        })?;
    captures
        .iter()
        .map(|capture| {
            let image = Reflect::get(&capture, &"image".into())?;
            let image = image.dyn_ref::<Uint8Array>().ok_or_else(|| {
                invalid_argument("Each capture image must be a Uint8Array")
            })?;
            let mut image = owned_image(image)?;
            let target_pitch = target_angle(&capture, "targetPitch")?;
            let target_yaw = target_angle(&capture, "targetYaw")?;
            let capture = PoseGuardCapture {
                image: std::mem::take(&mut *image),
                target_pitch,
                target_yaw,
            };
            capture.validate().map_err(|_| {
                invalid_argument("Pose target angles are outside the supported range")
            })?;
            Ok(capture)
        })
        .collect::<Result<Vec<_>, JsValue>>()?
        .try_into()
        .map_err(|_| invalid_argument("`captures` must contain exactly three poses"))
}

fn target_angle(capture: &JsValue, name: &str) -> Result<f32, JsValue> {
    #[allow(
        clippy::cast_possible_truncation,
        reason = "the TEE validates f32 angles, rejecting non-finite and out-of-range values"
    )]
    Ok(js::number_field(capture, name)? as f32)
}

/// Copies `image` into WASM memory after checking it against the service limit.
fn owned_image(image: &Uint8Array) -> Result<Zeroizing<Vec<u8>>, JsValue> {
    let length = image.length() as usize;
    if length == 0 || length > MAX_IMAGE_BYTES {
        return Err(invalid_argument("`image` must be between 1 byte and 8 MiB"));
    }
    Ok(Zeroizing::new(image.to_vec()))
}

fn result_to_js(result: &EmbeddingResult) -> Result<JsValue, JsValue> {
    match result {
        EmbeddingResult::Success { embedding } => js::object(&[
            ("status", "success".into()),
            (
                "embedding",
                js::object(&[
                    ("embedding", embedding.embedding.as_str().into()),
                    ("embeddingType", embedding.embedding_type.as_str().into()),
                    (
                        "embeddingVersion",
                        embedding.embedding_version.as_str().into(),
                    ),
                    (
                        "embeddingInferenceBackend",
                        embedding.embedding_inference_backend.as_str().into(),
                    ),
                ])?,
            ),
        ]),
        EmbeddingResult::Failed {
            reason: Failure::Challenge { .. },
        } => Err(to_js(Error::Protocol)),
        EmbeddingResult::Failed { reason } => failure_to_js(*reason),
    }
}

fn enrollment_to_js(result: &EnrollmentResult) -> Result<JsValue, JsValue> {
    match result {
        EnrollmentResult::Success { enrollment } => {
            let fields = enrollment
                .fields
                .iter()
                .map(|field| {
                    js::object(&[
                        ("name", field.name.as_str().into()),
                        ("value", field.value.as_str().into()),
                    ])
                })
                .collect::<Result<Vec<_>, _>>()?;
            js::object(&[
                ("status", "success".into()),
                (
                    "enrollment",
                    js::object(&[
                        ("fields", js::array(fields)),
                        (
                            "attestationHeader",
                            enrollment.attestation_header.as_str().into(),
                        ),
                        (
                            "encryptedCustody",
                            Uint8Array::from(enrollment.encrypted_custody.as_slice())
                                .into(),
                        ),
                    ])?,
                ),
            ])
        }
        EnrollmentResult::Failed { reason } => failure_to_js(*reason),
    }
}

fn failure_to_js(failure: Failure) -> Result<JsValue, JsValue> {
    let reason = match failure {
        Failure::InvalidImage => "invalid_image",
        Failure::QualityRejected => "quality_rejected",
        Failure::ExtractionFailed => "extraction_failed",
        Failure::InvalidRequest => "invalid_request",
        Failure::Challenge { index, reason } => {
            let reason = match reason {
                ChallengeFailure::InvalidImage => "invalid_image",
                ChallengeFailure::QualityRejected => "quality_rejected",
                ChallengeFailure::ExtractionFailed => "extraction_failed",
                ChallengeFailure::PoseMismatch => "pose_mismatch",
                ChallengeFailure::IdentityMismatch => "identity_mismatch",
            };
            return js::object(&[
                ("status", "failed".into()),
                ("reason", "challenge".into()),
                ("index", index.into()),
                ("challengeReason", reason.into()),
            ]);
        }
    };
    js::object(&[("status", "failed".into()), ("reason", reason.into())])
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfie_enrollment_sealed_types::{
        EnrollmentBundle, EnrollmentField, FaceEmbedding, ENROLLMENT_FIELDS,
    };
    use wasm_bindgen_test::wasm_bindgen_test;

    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_dedicated_worker);

    #[wasm_bindgen(inline_js = "
        export function messageRoundTrip(value) {
            return new Promise((resolve, reject) => {
                const { port1, port2 } = new MessageChannel();
                const close = () => { port1.close(); port2.close(); };
                port2.onmessage = ({ data }) => { close(); resolve(data); };
                port2.onmessageerror = () => { close(); reject(new Error('Clone failed')); };
                try { port1.postMessage(value); } catch (error) { close(); reject(error); }
            });
        }
    ")]
    extern "C" {
        #[wasm_bindgen(js_name = messageRoundTrip)]
        fn message_round_trip(value: JsValue) -> Promise;
    }

    #[wasm_bindgen_test]
    fn image_copy_survives_the_worker_clearing_its_argument() {
        let image = Uint8Array::from([1, 2, 3].as_slice());
        let copy = owned_image(&image).unwrap();
        image.fill(0, 0, image.length());
        assert_eq!(*copy, [1, 2, 3]);
    }

    #[wasm_bindgen_test]
    fn pose_copies_survive_the_worker_clearing_nested_arguments() {
        let captures = Array::new();
        for byte in [1_u8, 2, 3] {
            captures.push(
                &js::object(&[
                    ("image", Uint8Array::from([byte].as_slice()).into()),
                    ("targetPitch", 10.0.into()),
                    ("targetYaw", (-20.0).into()),
                ])
                .unwrap(),
            );
        }
        let owned = owned_captures(captures.as_ref()).unwrap();
        for capture in captures.iter() {
            let image = Reflect::get(&capture, &"image".into())
                .unwrap()
                .unchecked_into::<Uint8Array>();
            image.fill(0, 0, image.length());
        }
        for (capture, byte) in owned.iter().zip([1_u8, 2, 3]) {
            assert_eq!(capture.image, [byte]);
            assert_eq!(capture.target_pitch.to_bits(), 10.0_f32.to_bits());
            assert_eq!(capture.target_yaw.to_bits(), (-20.0_f32).to_bits());
        }
    }

    #[wasm_bindgen_test]
    #[expect(clippy::future_not_send, reason = "JavaScript values are worker-local")]
    async fn enrollment_bundle_survives_zeroization_and_post_message() {
        let fields: Vec<_> = ENROLLMENT_FIELDS
            .iter()
            .map(|name| EnrollmentField {
                name: (*name).into(),
                value: format!("unchanged-{name}"),
            })
            .collect();
        let result = EnrollmentResult::Success {
            enrollment: EnrollmentBundle {
                fields,
                attestation_header: "AAECAw==".into(),
                encrypted_custody: vec![0, 128, 255],
            },
        };
        let value = enrollment_to_js(&result).unwrap();
        drop(result);
        let cloned = wasm_bindgen_futures::JsFuture::from(message_round_trip(value))
            .await
            .unwrap();
        let bundle = Reflect::get(&cloned, &"enrollment".into()).unwrap();
        assert_eq!(js::string_field(&cloned, "status").unwrap(), "success");
        assert_eq!(
            js::string_field(&bundle, "attestationHeader").unwrap(),
            "AAECAw=="
        );
        let pcp = Reflect::get(&bundle, &"encryptedCustody".into())
            .unwrap()
            .dyn_into::<Uint8Array>()
            .unwrap();
        assert_eq!(pcp.to_vec(), [0, 128, 255]);
        let fields = Reflect::get(&bundle, &"fields".into())
            .unwrap()
            .dyn_into::<Array>()
            .unwrap();
        assert_eq!(fields.length(), 12);
        for (field, name) in fields.iter().zip(ENROLLMENT_FIELDS) {
            assert_eq!(js::string_field(&field, "name").unwrap(), name);
            assert_eq!(
                js::string_field(&field, "value").unwrap(),
                format!("unchanged-{name}")
            );
        }
    }

    #[wasm_bindgen_test]
    fn pose_rejection_preserves_its_index_and_reason() {
        let reason = Failure::Challenge {
            index: 2,
            reason: ChallengeFailure::IdentityMismatch,
        };
        let result = EnrollmentResult::Failed { reason };
        let value = enrollment_to_js(&result).unwrap();
        assert_eq!(js::string_field(&value, "status").unwrap(), "failed");
        assert_eq!(js::string_field(&value, "reason").unwrap(), "challenge");
        assert_eq!(
            Reflect::get(&value, &"index".into()).unwrap(),
            JsValue::from(2_u32)
        );
        assert_eq!(
            js::string_field(&value, "challengeReason").unwrap(),
            "identity_mismatch"
        );
        assert!(result_to_js(&EmbeddingResult::Failed { reason }).is_err());
    }

    #[wasm_bindgen_test]
    #[expect(clippy::future_not_send, reason = "JavaScript values are worker-local")]
    async fn success_preserves_face_pcp_fields_across_post_message() {
        let result = EmbeddingResult::Success {
            embedding: FaceEmbedding {
                embedding: "synthetic-embedding".into(),
                embedding_type: "ghostfacenet_flipped_mean".into(),
                embedding_version: "2.0.0".into(),
                embedding_inference_backend: "face-engine".into(),
            },
        };
        let cloned = wasm_bindgen_futures::JsFuture::from(message_round_trip(
            result_to_js(&result).unwrap(),
        ))
        .await
        .unwrap();
        let json = js_sys::JSON::stringify(&cloned)
            .unwrap()
            .as_string()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&json).unwrap(),
            serde_json::json!({
                "status": "success",
                "embedding": {
                    "embedding": "synthetic-embedding",
                    "embeddingType": "ghostfacenet_flipped_mean",
                    "embeddingVersion": "2.0.0",
                    "embeddingInferenceBackend": "face-engine",
                },
            }),
        );
    }
}
