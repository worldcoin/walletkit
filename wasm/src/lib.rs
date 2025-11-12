//! WebAssembly bindings for `walletkit_core`.
//!
//! This crate exposes a minimal surface of the `Authenticator` API for usage in
//! browser and Node (CJS / ESM) environments through `wasm-bindgen`.

#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

use std::sync::Arc;

use js_sys::{Function, Promise, Reflect};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::future_to_promise;

use walletkit_core::error::WalletKitError;
use walletkit_core::{
    Authenticator as CoreAuthenticator, Environment as CoreEnvironment,
};

const ENV_STAGING: &str = "staging";
const ENV_PRODUCTION: &str = "production";

#[wasm_bindgen]
pub struct Authenticator(Arc<CoreAuthenticator>);

#[wasm_bindgen]
impl Authenticator {
    /// Initializes a new authenticator using SDK defaults.
    ///
    /// # Errors
    /// Returns a rejected promise when initialization fails or input parsing fails.
    #[wasm_bindgen(js_name = initWithDefaults)]
    pub fn init_with_defaults(
        seed: Vec<u8>,
        rpc_url: String,
        environment: Environment,
    ) -> Promise {
        future_to_promise(async move {
            let environment = environment.into_core();
            CoreAuthenticator::init_with_defaults(&seed, rpc_url, &environment)
                .await
                .map(|auth| Self(Arc::new(auth)))
                .map(JsValue::from)
                .map_err(|err| walletkit_error_to_jsvalue(&err))
        })
    }

    /// Initializes a new authenticator using a JSON config.
    ///
    /// # Errors
    /// Returns a rejected promise when initialization fails or input parsing fails.
    #[wasm_bindgen(js_name = init)]
    pub fn init(seed: Vec<u8>, config_json: String) -> Promise {
        future_to_promise(async move {
            CoreAuthenticator::init(&seed, &config_json)
                .await
                .map(|auth| Self(Arc::new(auth)))
                .map(JsValue::from)
                .map_err(|err| walletkit_error_to_jsvalue(&err))
        })
    }

    /// Initializes (or creates) an authenticator using SDK defaults.
    ///
    /// # Errors
    /// Returns a rejected promise when initialization fails or input parsing fails.
    #[wasm_bindgen(js_name = initOrCreateBlockingWithDefaults)]
    pub fn init_or_create_blocking_with_defaults(
        seed: Vec<u8>,
        rpc_url: String,
        environment: Environment,
        recovery_address: Option<String>,
    ) -> Promise {
        future_to_promise(async move {
            let environment = environment.into_core();
            CoreAuthenticator::init_or_create_blocking_with_defaults(
                &seed,
                rpc_url,
                &environment,
                recovery_address,
            )
            .await
            .map(|auth| Self(Arc::new(auth)))
            .map(JsValue::from)
            .map_err(|err| walletkit_error_to_jsvalue(&err))
        })
    }

    /// Initializes (or creates) an authenticator using a JSON config.
    ///
    /// # Errors
    /// Returns a rejected promise when initialization fails or input parsing fails.
    #[wasm_bindgen(js_name = initOrCreateBlocking)]
    pub fn init_or_create_blocking(
        seed: Vec<u8>,
        config_json: String,
        recovery_address: Option<String>,
    ) -> Promise {
        future_to_promise(async move {
            CoreAuthenticator::init_or_create_blocking(
                &seed,
                &config_json,
                recovery_address,
            )
            .await
            .map(|auth| Self(Arc::new(auth)))
            .map(JsValue::from)
            .map_err(|err| walletkit_error_to_jsvalue(&err))
        })
    }

    /// Returns the packed account index for the holder's World ID.
    ///
    /// # Errors
    /// Returns a stringified error if the value cannot be converted to a `BigInt`.
    #[wasm_bindgen(js_name = accountId)]
    pub fn account_id(&self) -> Result<JsValue, JsValue> {
        let hex = self.0.account_id().to_hex_string();
        big_int_from_hex(&hex)
    }

    /// Returns the on-chain address as a checksum-encoded string.
    #[wasm_bindgen(js_name = onchainAddress)]
    #[must_use]
    pub fn onchain_address(&self) -> String {
        self.0.onchain_address()
    }

    /// Retrieves the packed account index from the registry.
    ///
    /// # Errors
    /// Returns a rejected promise if the remote call fails.
    #[wasm_bindgen(js_name = getPackedAccountIndexRemote)]
    pub fn get_packed_account_index_remote(&self) -> Promise {
        let authenticator = Arc::clone(&self.0);
        future_to_promise(async move {
            match authenticator.get_packed_account_index_remote().await {
                Ok(value) => big_int_from_hex(&value.to_hex_string()),
                Err(err) => Err(walletkit_error_to_jsvalue(&err)),
            }
        })
    }
}

#[wasm_bindgen]
pub struct Environment(CoreEnvironment);

#[wasm_bindgen]
#[allow(clippy::missing_const_for_fn)]
impl Environment {
    #[must_use]
    #[wasm_bindgen(js_name = Staging)]
    pub fn staging() -> Self {
        Self(CoreEnvironment::Staging)
    }

    #[must_use]
    #[wasm_bindgen(js_name = Production)]
    pub fn production() -> Self {
        Self(CoreEnvironment::Production)
    }

    #[must_use]
    #[wasm_bindgen(js_name = toString)]
    pub fn to_string_js(&self) -> String {
        match self.0 {
            CoreEnvironment::Staging => ENV_STAGING,
            CoreEnvironment::Production => ENV_PRODUCTION,
        }
        .to_string()
    }
}

#[allow(clippy::missing_const_for_fn)]
impl Environment {
    fn into_core(self) -> CoreEnvironment {
        self.0
    }
}

fn big_int_from_hex(hex: &str) -> Result<JsValue, JsValue> {
    let global = js_sys::global();
    let bigint_value = Reflect::get(&global, &JsValue::from_str("BigInt"))?
        .dyn_into::<Function>()?
        .call1(&JsValue::undefined(), &JsValue::from_str(hex))?;
    Ok(bigint_value)
}

fn walletkit_error_to_jsvalue(error: &WalletKitError) -> JsValue {
    JsValue::from_str(&error.to_string())
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
