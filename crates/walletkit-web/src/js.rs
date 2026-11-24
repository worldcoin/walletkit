//! Small helpers for building and reading plain JavaScript values.
//!
//! Records cross the worker boundary with `postMessage`, so they are plain objects
//! rather than exported Rust types. Rust objects stay in the worker and are
//! addressed by handle.

use std::future::Future;

use js_sys::{Array, BigInt, Error, Object, Promise, Reflect, Uint8Array};
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
    u64::from_js(value.into(), name)
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
    u32::from_js(value.into(), name)
}

/// Validates an array-of-`bigint` argument, each in the `u64` range.
pub fn u64_array_arg(name: &str, value: &JsValue) -> Result<Vec<u64>, JsValue> {
    Vec::from_js(value.clone(), name)
}

/// Converts a Rust value into plain data that survives `postMessage`.
///
/// `#[js_type]` implements it for records and enums; the TypeScript type of the
/// result is the declaration that the same attribute generates.
pub trait ToJs {
    /// # Errors
    /// Fails when a property cannot be set or a field conversion fails.
    fn to_js(&self) -> Result<JsValue, JsValue>;
}

/// Parses plain data received from JavaScript.
pub trait FromJs: Sized {
    /// Parses `value`, naming it `name` in the `TypeError` for invalid input.
    ///
    /// # Errors
    /// Throws a `TypeError` when `value` has the wrong type or an unknown variant.
    fn from_js(value: JsValue, name: &str) -> Result<Self, JsValue>;
}

/// Links a Rust type to the type that stands for it in `#[js_type]` declarations.
///
/// A remote declaration lists the fields of a type from another crate with the types
/// of their JavaScript form, such as `Vec<CredentialRecord>`. [`assert_schema`] checks
/// each declared type against the remote field's type, so a declaration cannot drift
/// from the type it describes.
pub trait JsSchema {
    /// The type that `#[js_type]` declarations name for this type.
    type Schema;
}

/// Compiles only when the schema of `T` is `S`.
pub const fn assert_schema<T: JsSchema<Schema = S>, S>(_: &T) {}

/// The `TypeError` for a `name` argument or field that is not `what`.
pub fn expected(name: &str, what: &str) -> JsValue {
    invalid_argument(&format!("`{name}` must be {what}"))
}

/// The `TypeError` for an enum `value` that names no variant.
pub fn unknown_value(name: &str, value: &str) -> JsValue {
    invalid_argument(&format!("Unknown {name}: {value}"))
}

/// Sets the `key` property of `object`.
pub fn set(object: &Object, key: &str, value: &JsValue) -> Result<(), JsValue> {
    Reflect::set(object, &JsValue::from_str(key), value).map(drop)
}

/// Reads the `key` property of `object`.
pub fn get(object: &JsValue, key: &str) -> Result<JsValue, JsValue> {
    Reflect::get(object, &JsValue::from_str(key))
}

/// Checks that the `name` argument is an object, before its fields are read.
pub fn expect_object(value: JsValue, name: &str) -> Result<JsValue, JsValue> {
    if value.is_object() {
        Ok(value)
    } else {
        Err(expected(name, "an object"))
    }
}

/// Reuses the object that a flattened field converted into.
pub fn into_object(value: JsValue) -> Result<Object, JsValue> {
    value
        .dyn_into()
        .map_err(|_| Error::new("A flattened field must convert to an object").into())
}

macro_rules! schema_is_self {
    ($($ty:ty),*) => {
        $(impl JsSchema for $ty {
            type Schema = Self;
        })*
    };
}

schema_is_self!(bool, u32, f32, f64, u64, String, Vec<u8>);

impl<T: JsSchema> JsSchema for Option<T> {
    type Schema = Option<T::Schema>;
}

impl<T: JsSchema> JsSchema for Vec<T> {
    type Schema = Vec<T::Schema>;
}

impl<T: JsSchema, const N: usize> JsSchema for [T; N] {
    type Schema = [T::Schema; N];
}

impl ToJs for bool {
    fn to_js(&self) -> Result<JsValue, JsValue> {
        Ok(JsValue::from_bool(*self))
    }
}

impl ToJs for u32 {
    fn to_js(&self) -> Result<JsValue, JsValue> {
        Ok((*self).into())
    }
}

impl FromJs for u32 {
    fn from_js(value: JsValue, name: &str) -> Result<Self, JsValue> {
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "the range and integrality are checked first"
        )]
        match value.as_f64() {
            Some(number)
                if (0.0..=f64::from(Self::MAX)).contains(&number)
                    && number.fract() == 0.0 =>
            {
                Ok(number as Self)
            }
            _ => Err(expected(
                name,
                &format!("an integer between 0 and {}", Self::MAX),
            )),
        }
    }
}

impl ToJs for f32 {
    fn to_js(&self) -> Result<JsValue, JsValue> {
        Ok((*self).into())
    }
}

impl ToJs for f64 {
    fn to_js(&self) -> Result<JsValue, JsValue> {
        Ok((*self).into())
    }
}

impl ToJs for u64 {
    fn to_js(&self) -> Result<JsValue, JsValue> {
        Ok((*self).into())
    }
}

impl FromJs for u64 {
    fn from_js(value: JsValue, name: &str) -> Result<Self, JsValue> {
        Self::try_from(value).map_err(|_| {
            expected(name, &format!("a bigint between 0 and {}", Self::MAX))
        })
    }
}

impl ToJs for String {
    fn to_js(&self) -> Result<JsValue, JsValue> {
        Ok(JsValue::from_str(self))
    }
}

impl FromJs for String {
    fn from_js(value: JsValue, name: &str) -> Result<Self, JsValue> {
        value.as_string().ok_or_else(|| expected(name, "a string"))
    }
}

/// `None` is `undefined`.
impl<T: ToJs> ToJs for Option<T> {
    fn to_js(&self) -> Result<JsValue, JsValue> {
        self.as_ref().map_or(Ok(JsValue::UNDEFINED), ToJs::to_js)
    }
}

/// `undefined` and `null` are `None`.
impl<T: FromJs> FromJs for Option<T> {
    fn from_js(value: JsValue, name: &str) -> Result<Self, JsValue> {
        if value.is_undefined() || value.is_null() {
            return Ok(None);
        }
        T::from_js(value, name).map(Some)
    }
}

/// Bytes are a `Uint8Array`; [`Vec<T>`] of any other `T` is an array.
impl ToJs for Vec<u8> {
    fn to_js(&self) -> Result<JsValue, JsValue> {
        Ok(Uint8Array::from(self.as_slice()).into())
    }
}

impl<T: ToJs> ToJs for Vec<T> {
    fn to_js(&self) -> Result<JsValue, JsValue> {
        self.as_slice()
            .iter()
            .map(ToJs::to_js)
            .collect::<Result<Array, _>>()
            .map(Into::into)
    }
}

impl<T: FromJs> FromJs for Vec<T> {
    fn from_js(value: JsValue, name: &str) -> Result<Self, JsValue> {
        if !Array::is_array(&value) {
            return Err(expected(name, "an array"));
        }
        Array::from(&value)
            .iter()
            .enumerate()
            .map(|(index, item)| T::from_js(item, &format!("{name}[{index}]")))
            .collect()
    }
}

impl<T: ToJs, const N: usize> ToJs for [T; N] {
    fn to_js(&self) -> Result<JsValue, JsValue> {
        self.iter()
            .map(ToJs::to_js)
            .collect::<Result<Array, _>>()
            .map(Into::into)
    }
}
