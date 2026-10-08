//! Small helpers for building and reading plain JavaScript values.
//!
//! Records cross the worker boundary with `postMessage`, so they are plain objects
//! rather than exported Rust types. Rust objects stay in the worker and are
//! addressed by handle.

use std::future::Future;

use js_sys::{Array, BigInt, Object, Promise, Reflect};
use walletkit_core::logger::{sanitize_hex_secrets, LogLevel, Logger};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use crate::error::invalid_argument;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console, js_name = error)]
    pub fn console_error(message: &str);

    #[wasm_bindgen(js_namespace = console, js_name = warn)]
    fn console_warn(message: &str);
}

/// Forwards core's warnings and errors to the worker console.
///
/// Core reports best-effort failures through `tracing` only, for example a vault
/// that could not be deleted or a credential that could not be loaded for proving.
/// Lower levels are dropped to keep the console quiet, and hex secrets are redacted.
pub struct ConsoleLogger;

impl Logger for ConsoleLogger {
    fn log(&self, level: LogLevel, message: String) {
        let message = sanitize_hex_secrets(message);
        match level {
            LogLevel::Error => console_error(&message),
            LogLevel::Warn => console_warn(&message),
            LogLevel::Trace | LogLevel::Debug | LogLevel::Info => {}
        }
    }
}

/// Builds a plain object, which survives `postMessage` unlike exported Rust types.
pub fn object(fields: &[(&str, JsValue)]) -> Result<JsValue, JsValue> {
    let object = Object::new();
    for (key, value) in fields {
        Reflect::set(&object, &JsValue::from_str(key), value)?;
    }
    Ok(object.into())
}

/// Builds a JavaScript array from already-converted values.
pub fn array(items: impl IntoIterator<Item = JsValue>) -> JsValue {
    items.into_iter().collect::<Array>().into()
}

/// Runs `future` on the JavaScript event loop and exposes it as a `Promise`.
pub fn promise(
    future: impl Future<Output = Result<JsValue, JsValue>> + 'static,
) -> Promise {
    future_to_promise(future)
}

/// The current unix time in seconds, from the JavaScript clock.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "`Date.now()` is a positive integer number of milliseconds"
)]
pub fn now_seconds() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

/// Validates a `u64` argument passed as a `bigint`.
///
/// A direct `u64` parameter would wrap silently: `2n ** 64n + 7n` would become `7`,
/// and `-1n` would become `u64::MAX`.
pub fn u64_arg(name: &str, value: BigInt) -> Result<u64, JsValue> {
    u64::try_from(JsValue::from(value)).map_err(|_| {
        invalid_argument(&format!(
            "`{name}` must be a bigint between 0 and {}",
            u64::MAX
        ))
    })
}

/// Like [`u64_arg`], for an argument that may be omitted.
pub fn optional_u64_arg(
    name: &str,
    value: Option<BigInt>,
) -> Result<Option<u64>, JsValue> {
    value.map(|value| u64_arg(name, value)).transpose()
}

/// Validates an unsigned 32-bit integer argument.
///
/// Taking the argument as a JavaScript number and checking it here avoids the silent
/// wrap-around of `-1`, `2**32` or `NaN` that a direct `u32` parameter would get.
pub fn u32_arg(name: &str, value: f64) -> Result<u32, JsValue> {
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "the range and integrality are checked first"
    )]
    if (0.0..=f64::from(u32::MAX)).contains(&value) && value.fract() == 0.0 {
        return Ok(value as u32);
    }
    Err(invalid_argument(&format!(
        "`{name}` must be an integer between 0 and {}",
        u32::MAX
    )))
}

/// Reads the field `key` of a plain object argument.
fn field(object: &JsValue, key: &str) -> Result<JsValue, JsValue> {
    if !object.is_object() {
        return Err(invalid_argument("Expected an object"));
    }
    Reflect::get(object, &JsValue::from_str(key))
}

/// Reads a required `bigint` field.
pub fn u64_field(object: &JsValue, key: &str) -> Result<u64, JsValue> {
    u64::try_from(field(object, key)?)
        .map_err(|_| invalid_argument(&format!("`{key}` must be a bigint")))
}

/// Reads an optional `bigint` field, treating `undefined` and `null` as absent.
pub fn optional_u64_field(object: &JsValue, key: &str) -> Result<Option<u64>, JsValue> {
    let value = field(object, key)?;
    if value.is_undefined() || value.is_null() {
        return Ok(None);
    }
    u64::try_from(value)
        .map(Some)
        .map_err(|_| invalid_argument(&format!("`{key}` must be a bigint")))
}

/// Reads a required string field.
pub fn string_field(object: &JsValue, key: &str) -> Result<String, JsValue> {
    field(object, key)?
        .as_string()
        .ok_or_else(|| invalid_argument(&format!("`{key}` must be a string")))
}

/// Reads an optional string field, treating `undefined` and `null` as absent.
pub fn optional_string_field(
    object: &JsValue,
    key: &str,
) -> Result<Option<String>, JsValue> {
    let value = field(object, key)?;
    if value.is_undefined() || value.is_null() {
        return Ok(None);
    }
    value
        .as_string()
        .map(Some)
        .ok_or_else(|| invalid_argument(&format!("`{key}` must be a string")))
}

/// Reads a required number field.
pub fn number_field(object: &JsValue, key: &str) -> Result<f64, JsValue> {
    field(object, key)?
        .as_f64()
        .ok_or_else(|| invalid_argument(&format!("`{key}` must be a number")))
}

/// Reads a required array-of-`bigint` field.
pub fn u64_array_field(object: &JsValue, key: &str) -> Result<Vec<u64>, JsValue> {
    u64_array_arg(key, &field(object, key)?)
}

/// Validates a `bigint[]` argument, with the same range checks as [`u64_arg`].
pub fn u64_array_arg(name: &str, value: &JsValue) -> Result<Vec<u64>, JsValue> {
    if !Array::is_array(value) {
        return Err(invalid_argument(&format!("`{name}` must be an array")));
    }
    Array::from(value)
        .iter()
        .map(|item| {
            u64::try_from(item).map_err(|_| {
                invalid_argument(&format!("`{name}` must contain only bigints"))
            })
        })
        .collect()
}
