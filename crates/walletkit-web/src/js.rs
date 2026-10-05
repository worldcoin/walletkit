//! Small helpers for building and reading plain JavaScript values.
//!
//! Records cross the worker boundary with `postMessage`, so they are plain objects
//! rather than exported Rust types. Rust objects stay in the worker and are
//! addressed by handle.

use std::future::Future;

use js_sys::{Array, Object, Promise, Reflect};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use crate::error::invalid_argument;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console, js_name = error)]
    pub fn console_error(message: &str);
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
    let value = field(object, key)?;
    if !Array::is_array(&value) {
        return Err(invalid_argument(&format!("`{key}` must be an array")));
    }
    Array::from(&value)
        .iter()
        .map(|item| {
            u64::try_from(item).map_err(|_| {
                invalid_argument(&format!("`{key}` must contain only bigints"))
            })
        })
        .collect()
}
