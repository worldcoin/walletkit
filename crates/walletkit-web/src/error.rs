//! Conversion of `WalletKit` errors into JavaScript `Error` objects.
//!
//! Every error carries a `name` naming its source, a human-readable `message`,
//! a `code` with the variant name, and a `detail` string with the variant and its
//! fields so failures can be triaged without a debugger. Hex values that may be
//! secrets are redacted.

use std::fmt::{Debug, Display};

use js_sys::{Error, Reflect, TypeError};
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
///
/// Besides the `name` of the source, the error carries a stable `code` (the variant
/// name, for example `NullifierReplay`) to branch on, and a `detail` string with the
/// variant and its fields.
#[allow(clippy::needless_pass_by_value)] // Used as `map_err(to_js)`.
pub fn to_js<E: JsReportable>(error: E) -> JsValue {
    let debug = format!("{error:?}");
    let code = debug
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .next()
        .unwrap_or_default();
    let error_object = Error::new(&sanitize_hex_secrets(error.to_string()));
    error_object.set_name(E::NAME);
    // Setting a property on a fresh `Error` cannot fail.
    let _ = Reflect::set(&error_object, &"code".into(), &code.into());
    let _ = Reflect::set(
        &error_object,
        &"detail".into(),
        &sanitize_hex_secrets(debug.clone()).into(),
    );
    error_object.into()
}

/// An argument failed validation before reaching `WalletKit`.
pub fn invalid_argument(message: &str) -> JsValue {
    TypeError::new(&sanitize_hex_secrets(message.to_string())).into()
}
