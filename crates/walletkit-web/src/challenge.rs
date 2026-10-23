//! Draft challenge facade awaiting the enrollment client's generation RPC.
use js_sys::Promise;
use selfie_enrollment_client::Config;
use selfie_enrollment_sealed_types::challenge::ChallengeTranscript;
use wasm_bindgen::prelude::*;

use crate::{error::invalid_argument, js};

#[wasm_bindgen(typescript_custom_section)]
const TS_TYPES: &str = r#"
/** Forward, anatomical left and anatomical right, respectively. */
export type ChallengeOption = 0x00 | 0x01 | 0x02;

/** Requested poses, not captured evidence or proof of completion. */
export interface ChallengeTranscript {
  /** Lowercase hexadecimal encoding of the 16-byte challenge ID. */
  challengeId: string;
  targetOptions: readonly [ChallengeOption, ChallengeOption, ChallengeOption];
  /** UTC milliseconds for the countdown UI; expiry must be enforced by the TEE. */
  expiresAtUnixMs: number;
}
"#;

/// Prepares a TEE-generated challenge transcript (draft, not operational yet).
///
/// `configJson` supplies the enrollment endpoint and trusted Nitro release policy.
/// The current draft validates this policy, then rejects without connecting.
/// Generation awaits the upstream enrollment-client RPC; it never runs locally.
///
/// # Errors
/// Throws a `TypeError` for invalid configuration, otherwise a
/// `SelfieChallengeError` with code `Unavailable` until the RPC is implemented.
#[wasm_bindgen(js_name = prepareSelfieChallenge, unchecked_return_type = "Promise<ChallengeTranscript>")]
pub fn prepare_selfie_challenge(config_json: String) -> Promise {
    js::promise(async move {
        let invalid_config =
            || invalid_argument("Invalid selfie challenge configuration");
        let config: Config =
            serde_json::from_str(&config_json).map_err(|_| invalid_config())?;
        config.validate().map_err(|_| invalid_config())?;
        let transcript = request_transcript(config).await?;
        transcript_to_js(&transcript)
    })
}

#[expect(
    clippy::unused_async,
    reason = "The upstream generation RPC will be asynchronous"
)]
async fn request_transcript(_config: Config) -> Result<ChallengeTranscript, JsValue> {
    // TODO: Delegate to the enrollment client once it exposes a generation RPC.
    let error = js_sys::Error::new(
        "TEE challenge generation is not available in the enrollment client yet",
    );
    error.set_name("SelfieChallengeError");
    js_sys::Reflect::set(&error, &"code".into(), &"Unavailable".into())?;
    Err(error.into())
}

fn transcript_to_js(transcript: &ChallengeTranscript) -> Result<JsValue, JsValue> {
    if transcript.expires_at_unix_ms > 9_007_199_254_740_991 {
        return Err(invalid_argument(
            "Challenge expiry exceeds JavaScript's safe integer range",
        ));
    }
    #[expect(
        clippy::cast_precision_loss,
        reason = "The safe-integer bound above guarantees an exact conversion"
    )]
    let expires_at_unix_ms = transcript.expires_at_unix_ms as f64;
    js::object(&[
        ("challengeId", hex::encode(transcript.challenge_id).into()),
        (
            "targetOptions",
            js::array(transcript.target_options.encode().map(JsValue::from)),
        ),
        ("expiresAtUnixMs", expires_at_unix_ms.into()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
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
    #[expect(clippy::future_not_send, reason = "JavaScript values are worker-local")]
    async fn transcript_preserves_id_order_and_expiry_across_post_message() {
        let mut bytes = [0; 27];
        bytes[..16].copy_from_slice(&[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
            0x0c, 0x0d, 0x0e, 0x0f,
        ]);
        bytes[16..19].copy_from_slice(&[0x02, 0x00, 0x01]);
        bytes[19..].copy_from_slice(&1_800_000_090_000_u64.to_be_bytes());
        let transcript = ChallengeTranscript::decode(&bytes).unwrap();
        let cloned = wasm_bindgen_futures::JsFuture::from(message_round_trip(
            transcript_to_js(&transcript).unwrap(),
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
                "challengeId": "000102030405060708090a0b0c0d0e0f",
                "targetOptions": [2, 0, 1],
                "expiresAtUnixMs": 1_800_000_090_000_u64,
            }),
        );

        let mut transcript = transcript;
        transcript.expires_at_unix_ms = 9_007_199_254_740_991;
        let value = transcript_to_js(&transcript).unwrap();
        let expiry = js_sys::Reflect::get(&value, &"expiresAtUnixMs".into()).unwrap();
        assert_eq!(expiry.as_f64(), Some(9_007_199_254_740_991.0));
        transcript.expires_at_unix_ms += 1;
        let error = transcript_to_js(&transcript).unwrap_err();
        assert!(error.is_instance_of::<js_sys::TypeError>());
    }
}
