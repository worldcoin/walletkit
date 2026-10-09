//! Embedding enrollment over the dedicated browser-compatible TEE channel.
use js_sys::{Promise, Reflect, Uint8Array};
use selfie_enrollment_client::{Config, Error};
use selfie_enrollment_sealed_types::{EmbeddingResult, Failure};
use wasm_bindgen::{prelude::*, JsCast};
use wasm_bindgen_futures::JsFuture;
use zeroize::Zeroizing;

use crate::{
    error::{invalid_argument, to_js},
    js,
};

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
/// `admissionPath` is a same-origin absolute path whose POST handler returns a
/// P256 admission ticket. Only the public server challenge is sent to that handler.
/// The handler must authorize the caller before signing; its key stays server-side.
/// The image is sealed inside this worker before upload and is never persisted.
///
/// Calls have a bounded deadline. Terminate the `WalletKit` instance to cancel an
/// in-flight enrollment immediately. This operation does not issue a credential.
///
/// # Errors
/// Throws a `TypeError` for an invalid admission path or browser context, and a
/// `SelfieEnrollmentError` for invalid policy, rejected attestation/admission, or
/// transport failures. Image/quality rejections return a typed failed result.
#[wasm_bindgen(js_name = extractSelfieEmbedding, unchecked_return_type = "Promise<SelfieEmbeddingResult>")]
pub fn extract_selfie_embedding(
    config_json: String,
    image: Vec<u8>,
    admission_path: String,
) -> Promise {
    let mut image = Zeroizing::new(image);
    js::promise(async move {
        if !admission_path.starts_with('/')
            || admission_path.starts_with("//")
            || admission_path.contains(['\\', '#', '\r', '\n', '\t'])
        {
            return Err(invalid_argument(
                "admissionPath must be an absolute same-origin path",
            ));
        }
        let scope = js_sys::global()
            .dyn_into::<web_sys::WorkerGlobalScope>()
            .map_err(|_| {
                invalid_argument("Enrollment requires the WalletKit worker")
            })?;
        let issuer_url = format!("{}{}", scope.location().origin(), admission_path);
        let config: Config =
            serde_json::from_str(&config_json).map_err(|_| to_js(Error::Config))?;
        let result = selfie_enrollment_client::browser::extract(
            &config,
            std::mem::take(&mut *image),
            move |challenge| async move {
                let abort = AdmissionFetch(
                    web_sys::AbortController::new().map_err(|_| Error::Admission)?,
                );
                let options = web_sys::RequestInit::new();
                options.set_method("POST");
                options.set_credentials(web_sys::RequestCredentials::SameOrigin);
                options.set_mode(web_sys::RequestMode::SameOrigin);
                options.set_signal(Some(&abort.0.signal()));
                options.set_body(
                    &serde_json::to_string(&challenge)
                        .map_err(|_| Error::Admission)?
                        .into(),
                );
                let request =
                    web_sys::Request::new_with_str_and_init(&issuer_url, &options)
                        .map_err(|_| Error::Admission)?;
                request
                    .headers()
                    .set("Content-Type", "application/json")
                    .map_err(|_| Error::Admission)?;
                let response = JsFuture::from(scope.fetch_with_request(&request))
                    .await
                    .map_err(|_| Error::Admission)?
                    .dyn_into::<web_sys::Response>()
                    .map_err(|_| Error::Admission)?;
                let body = read_admission(response).await?;
                serde_json::from_slice(&body).map_err(|_| Error::Admission)
            },
            None,
        )
        .await
        .map_err(to_js)?;
        result_to_js(&result)
    })
}

// Aborting on drop also stops the fetch when the enclosing enrollment future times out.
struct AdmissionFetch(web_sys::AbortController);
impl Drop for AdmissionFetch {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn read_admission(response: web_sys::Response) -> Result<Vec<u8>, Error> {
    if !response.ok() {
        return Err(Error::Admission);
    }
    let reader = response
        .body()
        .ok_or(Error::Admission)?
        .get_reader()
        .dyn_into::<web_sys::ReadableStreamDefaultReader>()
        .map_err(|_| Error::Admission)?;
    let mut body = Vec::with_capacity(2048);
    loop {
        let chunk = JsFuture::from(reader.read())
            .await
            .map_err(|_| Error::Admission)?;
        let done = Reflect::get(&chunk, &"done".into())
            .map_err(|_| Error::Admission)?
            .as_bool()
            .ok_or(Error::Admission)?;
        if done {
            return Ok(body);
        }
        let bytes = Reflect::get(&chunk, &"value".into())
            .map_err(|_| Error::Admission)?
            .dyn_into::<Uint8Array>()
            .map_err(|_| Error::Admission)?;
        if bytes.length() as usize > 2048 - body.len() {
            return Err(Error::Admission);
        }
        body.extend_from_slice(&bytes.to_vec());
    }
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
