//! Worker-owned face identity derivation.

use walletkit_core::identity::{Identity, IdentityContext};
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

use crate::error::invalid_argument;

/// Domain separation for an identity commitment.
#[wasm_bindgen(js_name = IdentityContext)]
#[derive(Clone, Copy)]
pub enum JsIdentityContext {
    /// The face enrollment identity domain used by Oxide.
    Face,
}

/// An identity kept inside the `WalletKit` worker until `free()` or worker close.
#[wasm_bindgen(js_name = Identity)]
pub struct JsIdentity(Identity);

#[wasm_bindgen(js_class = Identity)]
impl JsIdentity {
    /// Derives a face identity from a dedicated 32-byte secret seed.
    ///
    /// # Errors
    /// Throws a `TypeError` unless `seed` contains exactly 32 bytes and
    /// `context` is `IdentityContext.Face`.
    #[wasm_bindgen(js_name = fromSeed)]
    pub fn from_seed(
        mut seed: Vec<u8>,
        #[wasm_bindgen(unchecked_param_type = "IdentityContext")] context: &JsValue,
    ) -> Result<Self, JsValue> {
        let context =
            if context.as_f64() == Some(f64::from(JsIdentityContext::Face as u32)) {
                IdentityContext::Face
            } else {
                seed.zeroize();
                return Err(invalid_argument("context must be IdentityContext.Face"));
            };
        Identity::from_seed(seed, context)
            .map(Self)
            .map_err(|error| invalid_argument(&error.to_string()))
    }

    /// Returns the public commitment as `0x` followed by 64 lowercase hex digits.
    #[must_use]
    pub fn commitment(&self) -> String {
        self.0.commitment()
    }
}
