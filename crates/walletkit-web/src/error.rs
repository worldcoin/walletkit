//! Conversion of `WalletKit` errors into JavaScript `Error` objects.
//!
//! Every error carries a `name` naming its source, a human-readable `message`,
//! and a `detail` string with the variant and its fields so failures can be
//! triaged without a debugger. Hex values that may be secrets are redacted.

use std::fmt::{Debug, Display};

use js_sys::{Error, Reflect};
use walletkit_core::{
    error::WalletKitError, logger::sanitize_hex_secrets,
    proof_request_credential_constraints_check::CredentialConstraintsCheckError,
    storage::StorageError,
};
use wasm_bindgen::JsValue;

/// A Rust error that can be reported to JavaScript.
pub trait JsReportable: Display + Debug {
    /// The `name` of the resulting JavaScript error.
    const NAME: &'static str;
}

impl JsReportable for WalletKitError {
    const NAME: &'static str = "WalletKitError";
}

impl JsReportable for StorageError {
    const NAME: &'static str = "StorageError";
}

impl JsReportable for CredentialConstraintsCheckError {
    const NAME: &'static str = "CredentialConstraintsCheckError";
}

/// Converts a `WalletKit` error into a JavaScript `Error`.
#[allow(clippy::needless_pass_by_value)] // Used as `map_err(to_js)`.
pub fn to_js<E: JsReportable>(error: E) -> JsValue {
    build(
        E::NAME,
        &sanitize_hex_secrets(error.to_string()),
        Some(&sanitize_hex_secrets(format!("{error:?}"))),
    )
}

/// An argument failed validation before reaching `WalletKit`.
pub fn invalid_argument(message: &str) -> JsValue {
    build("TypeError", message, None)
}

fn build(name: &str, message: &str, detail: Option<&str>) -> JsValue {
    let error = Error::new(message);
    error.set_name(name);
    if let Some(detail) = detail {
        // Setting a property on a fresh `Error` cannot fail.
        let _ = Reflect::set(&error, &"detail".into(), &detail.into());
    }
    error.into()
}
