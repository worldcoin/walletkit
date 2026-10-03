//! Small helpers for building plain JavaScript values.

use js_sys::{Object, Reflect};
use wasm_bindgen::prelude::*;

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
