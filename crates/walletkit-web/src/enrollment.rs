//! Embedding enrollment over the dedicated browser-compatible TEE channel.
use js_sys::Promise;
use selfie_enrollment_client::{Config, Error};
use selfie_enrollment_sealed_types::{EmbeddingResult, Failure};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::{error::to_js, js};

#[wasm_bindgen(typescript_custom_section)]
const TS_TYPES: &str = r#"
export type SelfieEmbeddingResult =
  | { status: "success"; embedding: SelfieEmbedding }
  | { status: "failed"; reason: "invalid_image" | "quality_rejected" | "extraction_failed" | "busy" | "invalid_request" };

export interface SelfieEmbedding {
  vector: string;
  embeddingType: string;
  version: string;
  inferenceBackend: string;
  worker: { profile: string; executableSha384: string };
}
"#;

/// Extracts an embedding after verifying Nitro measurements and the worker identity.
///
/// `configJson` is the trusted release policy from the enrollment deployment.
/// The image is sealed inside this worker before upload and is never persisted.
///
/// Calls have a bounded deadline. Terminate the `WalletKit` instance to cancel an
/// in-flight enrollment immediately. This operation does not issue a credential.
///
/// # Errors
/// Throws a `SelfieEnrollmentError` for invalid policy, rejected attestation, or
/// transport failures. Image/quality rejections return a typed failed result.
#[wasm_bindgen(js_name = extractSelfieEmbedding, unchecked_return_type = "Promise<SelfieEmbeddingResult>")]
pub fn extract_selfie_embedding(config_json: String, image: Vec<u8>) -> Promise {
    let mut image = Zeroizing::new(image);
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

fn result_to_js(result: &EmbeddingResult) -> Result<JsValue, JsValue> {
    match result {
        EmbeddingResult::Success { embedding } => js::object(&[
            ("status", "success".into()),
            (
                "embedding",
                js::object(&[
                    ("vector", embedding.vector.as_str().into()),
                    ("embeddingType", embedding.embedding_type.as_str().into()),
                    ("version", embedding.version.as_str().into()),
                    (
                        "inferenceBackend",
                        embedding.inference_backend.as_str().into(),
                    ),
                    (
                        "worker",
                        js::object(&[
                            ("profile", embedding.worker.profile.as_str().into()),
                            (
                                "executableSha384",
                                embedding.worker.executable_sha384.as_str().into(),
                            ),
                        ])?,
                    ),
                ])?,
            ),
        ]),
        EmbeddingResult::Failed { reason } => {
            let reason = match reason {
                Failure::InvalidImage => "invalid_image",
                Failure::QualityRejected => "quality_rejected",
                Failure::ExtractionFailed => "extraction_failed",
                Failure::Busy => "busy",
                Failure::InvalidRequest => "invalid_request",
            };
            js::object(&[("status", "failed".into()), ("reason", reason.into())])
        }
    }
}
