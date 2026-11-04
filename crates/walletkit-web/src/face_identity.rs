//! Worker-owned face identity derivation.

use walletkit_core::face_identity::FaceIdentity;
use wasm_bindgen::prelude::*;

use crate::error::invalid_argument;

/// A face identity kept inside the WalletKit worker until `free()` or worker close.
#[wasm_bindgen(js_name = FaceIdentity)]
pub struct JsFaceIdentity(FaceIdentity);

#[wasm_bindgen(js_class = FaceIdentity)]
impl JsFaceIdentity {
    /// Derives a face identity from a dedicated 32-byte secret seed.
    ///
    /// # Errors
    /// Throws a `TypeError` unless `seed` contains exactly 32 bytes.
    #[wasm_bindgen(js_name = fromSeed)]
    pub fn from_seed(seed: Vec<u8>) -> Result<Self, JsValue> {
        FaceIdentity::from_seed(seed)
            .map(Self)
            .map_err(|error| invalid_argument(&error.to_string()))
    }

    /// Returns the public commitment as `0x` followed by 64 lowercase hex digits.
    #[must_use]
    pub fn commitment(&self) -> String {
        self.0.commitment()
    }
}
