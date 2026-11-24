//! Embedding extraction and `PoseGuard` enrollment over the dedicated TEE channel.
use std::time::Duration;

use js_sys::{Array, Function, Promise, Uint8Array};
use selfie_enrollment_api_types::{
    MAX_IMAGE_BYTES, POSEGUARD_CHALLENGE_COUNT, POSEGUARD_CHALLENGE_TTL_SECS,
};
use selfie_enrollment_client::{
    self as client, Config, EnrollmentClient, Error, PoseGuardImages,
};
use selfie_enrollment_sealed_types::{EmbeddingResult, Failure};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::AbortSignal;
use web_time::Instant;
use zeroize::Zeroizing;

use crate::{
    error::{invalid_argument, to_js},
    js::{self, FromJs, ToJs},
    records::PoseGuardPrompt,
};

// Matches the private subject limit in GeneratePoseGuardTargetsRequest::validate.
const MAX_SUB_BYTES: usize = 66;

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

/// Runs one attempt over the attested TEE channel. The TEE client takes `capture`
/// as a single-use callback, invoked after verifying the prompt and targets.
///
/// The enclave returns the enrollment fields, Nitro header and PCP encrypted to
/// `custodyPublicKey`. Retain the PCP before adding the ownership challenge and
/// proof to the signup-service submission. The custody private key stays with the caller.
///
/// # Errors
/// Throws a `TypeError` for an invalid subject, batch, image or custody key. Invalid
/// release policy, attestation and transport errors reject with `SelfieEnrollmentError`.
/// Worker rejections return a typed failure, including the rejected capture index.
#[wasm_bindgen(js_name = runPoseGuardEnrollment, unchecked_return_type = "Promise<SelfieEnrollmentResult>")]
pub fn run_poseguard_enrollment(
    config_json: String,
    sub: String,
    custody_public_key: &Uint8Array,
    #[wasm_bindgen(
        unchecked_param_type = "(prompt: PoseGuardPrompt) => Promise<PoseGuardImages>"
    )]
    capture: Function,
    signal: AbortSignal,
) -> Promise {
    if custody_public_key.length() != 32 {
        return Promise::reject(&invalid_argument(
            "`custodyPublicKey` must contain 32 bytes",
        ));
    }
    if sub.is_empty() || sub.len() > MAX_SUB_BYTES {
        return Promise::reject(&invalid_argument(&format!(
            "`sub` must contain 1 to {MAX_SUB_BYTES} UTF-8 bytes",
        )));
    }
    let mut key = [0; 32];
    custody_public_key.copy_to(&mut key);
    js::promise(async move {
        let config: Config =
            serde_json::from_str(&config_json).map_err(|_| to_js(Error::Config))?;
        let client = EnrollmentClient::new(config).map_err(to_js)?;
        let session = client.connect(Some(signal)).await.map_err(to_js)?;
        // The TEE client starts this same budget on entering enroll_with_poseguard.
        let deadline =
            Instant::now() + Duration::from_secs(POSEGUARD_CHALLENGE_TTL_SECS);
        let mut capture_error = None;
        let result = session
            .enroll_with_poseguard(sub, key, async |prompt| {
                request_images(&capture, prompt, deadline)
                    .await
                    .map_err(|error| {
                        capture_error = Some(error);
                        Error::Capture
                    })
            })
            .await;
        let result =
            result.map_err(|error| capture_error.unwrap_or_else(|| to_js(error)))?;
        result.to_js()
    })
}

#[expect(
    clippy::future_not_send,
    reason = "the capture promise is worker-local"
)]
async fn request_images(
    capture: &Function,
    prompt: client::PoseGuardPrompt,
    deadline: Instant,
) -> Result<PoseGuardImages, JsValue> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    let pending =
        capture.call1(&JsValue::UNDEFINED, &prompt_to_js(prompt, remaining)?)?;
    let images = JsFuture::from(Promise::resolve(&pending)).await?;
    PoseGuardImages::from_js(images, "images")
}

fn prompt_to_js(
    prompt: client::PoseGuardPrompt,
    remaining: Duration,
) -> Result<JsValue, JsValue> {
    #[allow(
        clippy::cast_precision_loss,
        reason = "Unix seconds fit within a JS number"
    )]
    let expires_at = prompt.expires_at as f64;
    PoseGuardPrompt {
        targets: prompt.targets,
        expires_at,
        capture_timeout_ms: (remaining.as_secs_f64() * 1000.0).floor(),
    }
    .to_js()
}

/// Reads [`PoseGuardImages`], clearing the page's copy of each image it reads. Each
/// image moves into the zeroizing record as soon as it is read, so an invalid later
/// image also wipes the earlier ones.
pub fn poseguard_images_from_js(
    value: &JsValue,
    name: &str,
) -> Result<PoseGuardImages, JsValue> {
    let value = js::expect_object(value.clone(), name)?;
    let captures = js::get(&value, "captures")?;
    let captures = captures
        .dyn_ref::<Array>()
        .filter(|captures| captures.length() as usize == POSEGUARD_CHALLENGE_COUNT)
        .ok_or_else(|| {
            invalid_argument("`captures` must contain exactly three images")
        })?;
    let mut central = take_image(&js::get(&value, "centralPng")?)?;
    if !central.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Err(invalid_argument("`centralPng` must be a PNG"));
    }
    let mut images = PoseGuardImages {
        central_png: std::mem::take(&mut *central),
        captures: Default::default(),
    };
    for (slot, image) in images.captures.iter_mut().zip(captures.iter()) {
        *slot = std::mem::take(&mut *take_image(&image)?);
    }
    Ok(images)
}

fn take_image(value: &JsValue) -> Result<Zeroizing<Vec<u8>>, JsValue> {
    let image = value
        .dyn_ref::<Uint8Array>()
        .ok_or_else(|| invalid_argument("Each image must be a Uint8Array"))?;
    let owned = owned_image(image);
    image.fill(0, 0, image.length());
    owned
}

/// Copies `image` into WASM memory after checking it against the service limit.
fn owned_image(image: &Uint8Array) -> Result<Zeroizing<Vec<u8>>, JsValue> {
    let length = image.length() as usize;
    if length == 0 || length > MAX_IMAGE_BYTES {
        return Err(invalid_argument("`image` must be between 1 byte and 8 MiB"));
    }
    Ok(Zeroizing::new(image.to_vec()))
}

/// Converts an extraction result; a challenge failure is a protocol violation here.
fn result_to_js(result: &EmbeddingResult) -> Result<JsValue, JsValue> {
    if let EmbeddingResult::Failed {
        reason: Failure::Challenge { .. },
    } = result
    {
        return Err(to_js(Error::Protocol));
    }
    result.to_js()
}

#[cfg(test)]
mod tests {
    use super::*;
    use js_sys::Reflect;
    use selfie_enrollment_sealed_types::{
        ChallengeFailure, EnrollmentBundle, EnrollmentField, EnrollmentResult,
        FaceEmbedding, ENROLLMENT_FIELDS,
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

    fn string_field(object: &JsValue, key: &str) -> Result<String, JsValue> {
        String::from_js(js::get(object, key)?, key)
    }

    #[wasm_bindgen_test]
    fn image_copy_survives_the_worker_clearing_its_argument() {
        let image = Uint8Array::from([1, 2, 3].as_slice());
        let copy = owned_image(&image).unwrap();
        image.fill(0, 0, image.length());
        assert_eq!(*copy, [1, 2, 3]);
    }

    #[wasm_bindgen_test]
    fn capture_import_copies_images_in_order_and_clears_worker_buffers() {
        let png = b"\x89PNG\r\n\x1a\n";
        let central = Uint8Array::from(png.as_slice());
        let captures = [1_u8, 2, 3].map(|byte| Uint8Array::from([byte].as_slice()));
        let value = js_sys::Object::new();
        js::set(&value, "centralPng", &central.clone().into()).unwrap();
        js::set(
            &value,
            "captures",
            &js::array(captures.iter().cloned().map(JsValue::from)),
        )
        .unwrap();
        let owned = PoseGuardImages::from_js(value.into(), "images").unwrap();
        assert_eq!(owned.central_png, png);
        assert_eq!(owned.captures, [vec![1], vec![2], vec![3]]);
        assert_eq!(central.to_vec(), [0; 8]);
        assert!(captures.iter().all(|capture| capture.to_vec() == [0]));
    }

    #[wasm_bindgen_test]
    fn capture_import_rejects_invalid_images() {
        let image = |byte: u8| JsValue::from(Uint8Array::from([byte].as_slice()));
        let images = |captures: JsValue| {
            let value = js_sys::Object::new();
            let central = Uint8Array::from(b"\x89PNG\r\n\x1a\n".as_slice());
            js::set(&value, "centralPng", &central.into()).unwrap();
            js::set(&value, "captures", &captures).unwrap();
            JsValue::from(value)
        };
        for (value, expected) in [
            (JsValue::NULL, "`images` must be an object"),
            (
                images(js::array([image(1), image(2)])),
                "`captures` must contain exactly three images",
            ),
            (
                images(js::array([image(1), "2".into(), image(3)])),
                "Each image must be a Uint8Array",
            ),
        ] {
            let Err(error) = PoseGuardImages::from_js(value, "images") else {
                panic!("expected {expected}");
            };
            let error = error.dyn_ref::<js_sys::TypeError>().unwrap();
            assert_eq!(String::from(error.message()), expected);
        }
    }

    #[wasm_bindgen_test]
    fn embedding_failure_flattens_its_reason() {
        let value = result_to_js(&EmbeddingResult::Failed {
            reason: Failure::QualityRejected,
        })
        .unwrap();
        assert_eq!(string_field(&value, "status").unwrap(), "failed");
        assert_eq!(string_field(&value, "reason").unwrap(), "quality_rejected");
    }

    #[wasm_bindgen_test]
    #[expect(clippy::future_not_send, reason = "JavaScript values are worker-local")]
    async fn poseguard_validates_subject_before_parsing_release_policy() {
        let key = Uint8Array::new_with_length(32);
        let capture = Function::new_no_args("throw new Error('Unexpected capture')");
        for (sub, expected) in [
            (String::new(), "TypeError"),
            ("é".repeat(34), "TypeError"),
            ("é".repeat(33), "SelfieEnrollmentError"),
        ] {
            let error = JsFuture::from(run_poseguard_enrollment(
                String::new(),
                sub,
                &key,
                capture.clone(),
                AbortSignal::abort(),
            ))
            .await
            .unwrap_err();
            assert_eq!(string_field(&error, "name").unwrap(), expected);
        }
    }

    #[wasm_bindgen_test]
    fn prompt_preserves_signed_angles_and_target_order() {
        use selfie_enrollment_client::PoseGuardTarget;

        let prompt = client::PoseGuardPrompt {
            targets: [(0.0, -31.0), (-17.0, 0.0), (0.0, 34.0)].map(
                |(target_pitch, target_yaw)| PoseGuardTarget {
                    target_pitch,
                    target_yaw,
                },
            ),
            expires_at: 1_800_000_000,
        };
        let value = prompt_to_js(prompt, Duration::from_millis(41_000)).unwrap();
        let json = js_sys::JSON::stringify(&value)
            .unwrap()
            .as_string()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&json).unwrap(),
            serde_json::json!({
                "targets": [
                    { "targetPitch": 0, "targetYaw": -31 },
                    { "targetPitch": -17, "targetYaw": 0 },
                    { "targetPitch": 0, "targetYaw": 34 },
                ],
                "expiresAt": 1_800_000_000,
                "captureTimeoutMs": 41_000,
            })
        );
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
        let value = result.to_js().unwrap();
        drop(result);
        let cloned = wasm_bindgen_futures::JsFuture::from(message_round_trip(value))
            .await
            .unwrap();
        let bundle = Reflect::get(&cloned, &"enrollment".into()).unwrap();
        assert_eq!(string_field(&cloned, "status").unwrap(), "success");
        assert_eq!(
            string_field(&bundle, "attestationHeader").unwrap(),
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
            assert_eq!(string_field(&field, "name").unwrap(), name);
            assert_eq!(
                string_field(&field, "value").unwrap(),
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
        let value = result.to_js().unwrap();
        assert_eq!(string_field(&value, "status").unwrap(), "failed");
        assert_eq!(string_field(&value, "reason").unwrap(), "challenge");
        assert_eq!(
            Reflect::get(&value, &"index".into()).unwrap(),
            JsValue::from(2_u32)
        );
        assert_eq!(
            string_field(&value, "challengeReason").unwrap(),
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
