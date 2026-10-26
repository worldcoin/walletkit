//! Embedding enrollment over the dedicated browser-compatible TEE channel.
use js_sys::{Promise, Uint8Array};
use selfie_enrollment_api_types::MAX_IMAGE_BYTES;
use selfie_enrollment_client::{Config, Error};
use selfie_enrollment_sealed_types::{EmbeddingResult, Failure};
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
        EmbeddingResult::Failed { reason } => {
            let reason = match reason {
                Failure::InvalidImage => "invalid_image",
                Failure::QualityRejected => "quality_rejected",
                Failure::ExtractionFailed => "extraction_failed",
                Failure::InvalidRequest => "invalid_request",
            };
            js::object(&[("status", "failed".into()), ("reason", reason.into())])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfie_enrollment_sealed_types::FaceEmbedding;
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
