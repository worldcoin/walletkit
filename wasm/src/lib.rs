//! WebAssembly bindings for `walletkit_core`.
//!
//! This crate exposes a minimal surface of the `Authenticator` API for usage in
//! browser and Node (CJS / ESM) environments through `wasm-bindgen`.

#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

use js_sys::{Function, Promise, Reflect};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::future_to_promise;

const ENV_STAGING: &str = "staging";
const ENV_PRODUCTION: &str = "production";

#[wasm_bindgen]
pub struct Authenticator;

#[wasm_bindgen]
#[allow(clippy::missing_const_for_fn)]
impl Authenticator {
    /// Initializes a new authenticator using SDK defaults.
    ///
    /// # Errors
    /// Returns a rejected promise when initialization fails or input parsing fails.
    #[wasm_bindgen(js_name = initWithDefaults)]
    pub fn init_with_defaults(
        _seed: Vec<u8>,
        _rpc_url: String,
        _environment: Environment,
    ) -> Promise {
        future_to_promise(async move {
            Err(JsValue::from_str(
                "Authenticator.initWithDefaults is not available in this WASM build.",
            ))
        })
    }

    /// Initializes a new authenticator using a JSON config.
    ///
    /// # Errors
    /// Returns a rejected promise when initialization fails or input parsing fails.
    #[wasm_bindgen(js_name = init)]
    pub fn init(_seed: Vec<u8>, _config_json: String) -> Promise {
        future_to_promise(async move {
            Err(JsValue::from_str(
                "Authenticator.init is not available in this WASM build.",
            ))
        })
    }

    /// Initializes (or creates) an authenticator using SDK defaults.
    ///
    /// # Errors
    /// Returns a rejected promise when initialization fails or input parsing fails.
    #[wasm_bindgen(js_name = initOrCreateBlockingWithDefaults)]
    pub fn init_or_create_blocking_with_defaults(
        _seed: Vec<u8>,
        _rpc_url: String,
        _environment: Environment,
        _recovery_address: Option<String>,
    ) -> Promise {
        future_to_promise(async move {
            Err(JsValue::from_str(
                "Authenticator.initOrCreateBlockingWithDefaults is not available in this WASM build.",
            ))
        })
    }

    /// Initializes (or creates) an authenticator using a JSON config.
    ///
    /// # Errors
    /// Returns a rejected promise when initialization fails or input parsing fails.
    #[wasm_bindgen(js_name = initOrCreateBlocking)]
    pub fn init_or_create_blocking(
        _seed: Vec<u8>,
        _config_json: String,
        _recovery_address: Option<String>,
    ) -> Promise {
        future_to_promise(async move {
            Err(JsValue::from_str(
                "Authenticator.initOrCreateBlocking is not available in this WASM build.",
            ))
        })
    }

    /// Returns the packed account index for the holder's World ID.
    ///
    /// # Errors
    /// Returns a stringified error if the value cannot be converted to a `BigInt`.
    #[wasm_bindgen(js_name = accountId)]
    pub fn account_id(&self) -> Result<JsValue, JsValue> {
        Err(JsValue::from_str(
            "accountId is not available in this WASM build.",
        ))
    }

    /// Returns the on-chain address as a checksum-encoded string.
    #[wasm_bindgen(js_name = onchainAddress)]
    #[must_use]
    pub fn onchain_address(&self) -> String {
        String::new()
    }

    /// Retrieves the packed account index from the registry.
    ///
    /// # Errors
    /// Returns a rejected promise if the remote call fails.
    #[wasm_bindgen(js_name = getPackedAccountIndexRemote)]
    pub fn get_packed_account_index_remote(&self) -> Promise {
        future_to_promise(async move {
            Err(JsValue::from_str(
                "getPackedAccountIndexRemote is not available in this WASM build.",
            ))
        })
    }
}

#[wasm_bindgen]
pub struct Environment(InnerEnvironment);

#[wasm_bindgen]
#[allow(clippy::missing_const_for_fn)]
impl Environment {
    #[must_use]
    #[wasm_bindgen(js_name = Staging)]
    pub fn staging() -> Self {
        Self(InnerEnvironment::Staging)
    }

    #[must_use]
    #[wasm_bindgen(js_name = Production)]
    pub fn production() -> Self {
        Self(InnerEnvironment::Production)
    }

    #[must_use]
    #[wasm_bindgen(js_name = toString)]
    pub fn to_string_js(&self) -> String {
        match self.0 {
            InnerEnvironment::Staging => ENV_STAGING,
            InnerEnvironment::Production => ENV_PRODUCTION,
        }
        .to_string()
    }
}

#[allow(clippy::missing_const_for_fn)]
impl Environment {}

fn big_int_from_hex(hex: &str) -> Result<JsValue, JsValue> {
    let global = js_sys::global();
    let bigint_value = Reflect::get(&global, &JsValue::from_str("BigInt"))?
        .dyn_into::<Function>()?
        .call1(&JsValue::undefined(), &JsValue::from_str(hex))?;
    Ok(bigint_value)
}

#[derive(Clone, Copy)]
enum InnerEnvironment {
    Staging,
    Production,
}

#[wasm_bindgen(typescript_custom_section)]
const TYPESCRIPT_DEFS: &str = r#"
export class Authenticator {
    static initWithDefaults(
        seed: Uint8Array,
        rpcUrl: string,
        environment: Environment
    ): Promise<Authenticator>;

    static init(seed: Uint8Array, configJson: string): Promise<Authenticator>;

    static initOrCreateBlockingWithDefaults(
        seed: Uint8Array,
        rpcUrl: string,
        environment: Environment,
        recoveryAddress?: string
    ): Promise<Authenticator>;

    static initOrCreateBlocking(
        seed: Uint8Array,
        configJson: string,
        recoveryAddress?: string
    ): Promise<Authenticator>;

    accountId(): bigint;
    onchainAddress(): string;
    getPackedAccountIndexRemote(): Promise<bigint>;
}

export class Environment {
    static Staging(): Environment;
    static Production(): Environment;
    toString(): "staging" | "production";
}
"#;
