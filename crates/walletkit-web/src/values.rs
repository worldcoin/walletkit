//! Value objects shared by the authenticator and storage APIs.
//!
//! Each class mirrors the object of the same name in the Swift and Kotlin bindings.

#![allow(
    clippy::missing_const_for_fn,
    reason = "`#[wasm_bindgen]` does not support `const fn`"
)]

use js_sys::BigInt;
use walletkit_core::{
    requests::{ProofRequest, ProofResponse},
    Credential, FieldElement,
};
use wasm_bindgen::prelude::*;

use crate::{error::to_js, js};

/// An element of the scalar field used by the World ID proofs.
#[wasm_bindgen(js_name = FieldElement)]
pub struct JsFieldElement(pub(crate) FieldElement);

#[wasm_bindgen(js_class = FieldElement)]
impl JsFieldElement {
    /// Parses a 32-byte big-endian field element.
    ///
    /// # Errors
    /// Throws a `WalletKitError` when the input is not a canonical field element.
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, JsValue> {
        FieldElement::from_bytes(bytes).map(Self).map_err(to_js)
    }

    /// # Errors
    /// Throws a `TypeError` when `value` is not a bigint in the `u64` range.
    #[wasm_bindgen(js_name = fromU64)]
    pub fn from_u64(value: BigInt) -> Result<Self, JsValue> {
        Ok(Self(FieldElement::from_u64(js::u64_arg("value", value)?)))
    }

    /// Parses a hex string with an optional `0x` prefix.
    ///
    /// # Errors
    /// Throws a `WalletKitError` when the input is not a valid field element.
    #[wasm_bindgen(js_name = tryFromHexString)]
    pub fn try_from_hex_string(hex_string: &str) -> Result<Self, JsValue> {
        FieldElement::try_from_hex_string(hex_string)
            .map(Self)
            .map_err(to_js)
    }

    #[wasm_bindgen(js_name = toBytes)]
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    #[wasm_bindgen(js_name = toHexString)]
    #[must_use]
    pub fn to_hex_string(&self) -> String {
        self.0.to_hex_string()
    }
}

/// A World ID credential issued to the holder.
#[wasm_bindgen(js_name = Credential)]
pub struct JsCredential(pub(crate) Credential);

#[wasm_bindgen(js_class = Credential)]
impl JsCredential {
    /// Deserializes a credential from its serialized bytes.
    ///
    /// # Errors
    /// Throws a `WalletKitError` when the bytes are not a credential.
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, JsValue> {
        Credential::from_bytes(bytes).map(Self).map_err(to_js)
    }

    #[must_use]
    pub fn sub(&self) -> JsFieldElement {
        JsFieldElement(self.0.sub())
    }

    #[wasm_bindgen(js_name = issuerSchemaId)]
    #[must_use]
    pub fn issuer_schema_id(&self) -> u64 {
        self.0.issuer_schema_id()
    }

    #[wasm_bindgen(js_name = genesisIssuedAt)]
    #[must_use]
    pub fn genesis_issued_at(&self) -> u64 {
        self.0.genesis_issued_at()
    }

    #[wasm_bindgen(js_name = expiresAt)]
    #[must_use]
    pub fn expires_at(&self) -> u64 {
        self.0.expires_at()
    }

    #[wasm_bindgen(js_name = associatedDataCommitment)]
    #[must_use]
    pub fn associated_data_commitment(&self) -> JsFieldElement {
        JsFieldElement(self.0.associated_data_commitment())
    }

    #[wasm_bindgen(unchecked_return_type = "FieldElement[]")]
    #[must_use]
    pub fn claims(&self) -> JsValue {
        js::array(
            self.0
                .claims()
                .iter()
                .map(|claim| JsFieldElement(claim.as_ref().clone()).into()),
        )
    }

    #[wasm_bindgen(js_name = claimsHex)]
    #[must_use]
    pub fn claims_hex(&self) -> Vec<String> {
        self.0.claims_hex()
    }

    /// Serializes the credential.
    ///
    /// # Errors
    /// Throws a `WalletKitError` when serialization fails.
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Result<Vec<u8>, JsValue> {
        self.0.to_bytes().map_err(to_js)
    }
}

/// A proof request received from a relying party.
#[wasm_bindgen(js_name = ProofRequest)]
pub struct JsProofRequest(pub(crate) ProofRequest);

#[wasm_bindgen(js_class = ProofRequest)]
impl JsProofRequest {
    /// Parses a proof request from its JSON form.
    ///
    /// # Errors
    /// Throws a `WalletKitError` when the JSON is not a valid proof request.
    #[wasm_bindgen(js_name = fromJson)]
    pub fn from_json(json: &str) -> Result<Self, JsValue> {
        ProofRequest::from_json(json).map(Self).map_err(to_js)
    }

    /// Serializes the request to JSON.
    ///
    /// # Errors
    /// Throws a `WalletKitError` when serialization fails.
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        self.0.to_json().map_err(to_js)
    }

    #[must_use]
    pub fn id(&self) -> String {
        self.0.id()
    }

    #[must_use]
    pub fn version(&self) -> u8 {
        self.0.version()
    }
}

/// The response to a [`JsProofRequest`].
#[wasm_bindgen(js_name = ProofResponse)]
pub struct JsProofResponse(pub(crate) ProofResponse);

#[wasm_bindgen(js_class = ProofResponse)]
impl JsProofResponse {
    /// Serializes the response to JSON.
    ///
    /// # Errors
    /// Throws a `WalletKitError` when serialization fails.
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        self.0.to_json().map_err(to_js)
    }

    #[must_use]
    pub fn id(&self) -> String {
        self.0.id()
    }

    #[must_use]
    pub fn version(&self) -> u8 {
        self.0.version()
    }

    #[must_use]
    pub fn error(&self) -> Option<String> {
        self.0.error()
    }
}
