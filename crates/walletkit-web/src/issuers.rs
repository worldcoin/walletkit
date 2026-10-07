//! Credential issuer clients.
//!
//! Requests go out through `fetch`, so the issuer services must allow the page's
//! origin (CORS) for these calls to succeed in the browser.

use std::{collections::HashMap, sync::Arc};

use js_sys::{BigInt, Object, Promise};
use walletkit_core::issuers::{RecoveryBindingManager, TfhNfcIssuer};
use wasm_bindgen::prelude::*;

use crate::{
    authenticator::{parse_environment, JsAuthenticator},
    error::{invalid_argument, to_js},
    js,
    user_agent::JsUserAgentBuilder,
    values::JsCredential,
};

#[wasm_bindgen(typescript_custom_section)]
const TS_TYPES: &str = r#"
export interface RecoveryBinding {
  /** Hex address of the recovery agent. */
  recoveryAgent?: string;
  /** Hex address of the pending recovery agent. */
  pendingRecoveryAgent?: string;
  /** When the pending update takes effect, in seconds since the Unix epoch. */
  executeAfter?: string;
}
"#;

/// Client for the TFH NFC credential issuer (passport, eID, MNC).
#[wasm_bindgen(js_name = TfhNfcIssuer)]
pub struct JsTfhNfcIssuer(Arc<TfhNfcIssuer>);

#[wasm_bindgen(js_class = TfhNfcIssuer)]
impl JsTfhNfcIssuer {
    /// # Errors
    /// Throws a `TypeError` for an unknown environment.
    #[wasm_bindgen(js_name = new)]
    pub fn new(
        #[wasm_bindgen(unchecked_param_type = "Environment")] environment: &str,
        user_agent: String,
    ) -> Result<Self, JsValue> {
        let environment = parse_environment(environment)?;
        Ok(Self(Arc::new(TfhNfcIssuer::new(&environment, user_agent))))
    }

    /// Refreshes an NFC credential (migrates a PCP credential to v4).
    ///
    /// # Errors
    /// Rejects with `NfcNonRetryable` when the document cannot be refreshed, or with
    /// a `NetworkError` when the request fails.
    #[wasm_bindgen(js_name = refreshNfcCredential, unchecked_return_type = "Promise<Credential>")]
    pub fn refresh_nfc_credential(
        &self,
        request_body: String,
        #[wasm_bindgen(unchecked_param_type = "Record<string, string>")]
        headers: &JsValue,
    ) -> Promise {
        let issuer = Arc::clone(&self.0);
        let headers = string_map("headers", headers);
        js::promise(async move {
            let credential = issuer
                .refresh_nfc_credential(&request_body, headers?)
                .await
                .map_err(to_js)?;
            Ok(JsCredential(credential).into())
        })
    }
}

/// Registers and removes recovery agents through the Proof-of-Personhood backend.
#[wasm_bindgen(js_name = RecoveryBindingManager)]
pub struct JsRecoveryBindingManager(Arc<RecoveryBindingManager>);

#[wasm_bindgen(js_class = RecoveryBindingManager)]
impl JsRecoveryBindingManager {
    /// # Errors
    /// Throws a `TypeError` for an unknown environment.
    #[wasm_bindgen(js_name = new)]
    pub fn new(
        #[wasm_bindgen(unchecked_param_type = "Environment")] environment: &str,
        user_agent_builder: &JsUserAgentBuilder,
    ) -> Result<Self, JsValue> {
        let environment = parse_environment(environment)?;
        RecoveryBindingManager::new(&environment, &user_agent_builder.0)
            .map(|manager| Self(Arc::new(manager)))
            .map_err(to_js)
    }

    /// # Errors
    /// Throws a `WalletKitError` when the client cannot be built.
    #[wasm_bindgen(js_name = newWithBaseUrl)]
    pub fn new_with_base_url(
        base_url: &str,
        user_agent_builder: &JsUserAgentBuilder,
    ) -> Result<Self, JsValue> {
        RecoveryBindingManager::new_with_base_url(base_url, &user_agent_builder.0)
            .map(|manager| Self(Arc::new(manager)))
            .map_err(to_js)
    }

    /// Registers `recoveryAgentAddress` as the recovery agent, authorized by
    /// `authenticator`'s key.
    ///
    /// # Errors
    /// Rejects when the challenge, signing or backend request fails, or when the user
    /// is not eligible for recovery.
    #[wasm_bindgen(js_name = bindRecoveryAgent, unchecked_return_type = "Promise<void>")]
    pub fn bind_recovery_agent(
        &self,
        authenticator: &JsAuthenticator,
        sub: String,
        recovery_agent_address: String,
    ) -> Promise {
        let manager = Arc::clone(&self.0);
        let authenticator = Arc::clone(&authenticator.0);
        js::promise(async move {
            manager
                .bind_recovery_agent(&authenticator, sub, recovery_agent_address)
                .await
                .map_err(to_js)?;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// Removes the registered recovery agent.
    ///
    /// # Errors
    /// Rejects when the challenge, signing or backend request fails, or when the
    /// account does not exist.
    #[wasm_bindgen(js_name = unbindRecoveryAgent, unchecked_return_type = "Promise<void>")]
    pub fn unbind_recovery_agent(
        &self,
        authenticator: &JsAuthenticator,
        sub: String,
    ) -> Promise {
        let manager = Arc::clone(&self.0);
        let authenticator = Arc::clone(&authenticator.0);
        js::promise(async move {
            manager
                .unbind_recovery_agent(&authenticator, sub)
                .await
                .map_err(to_js)?;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// Fetches the recovery binding of the account at `leafIndex`.
    ///
    /// # Errors
    /// Rejects with `RecoveryBindingDoesNotExist` when there is no binding, or with a
    /// `NetworkError` when the request fails.
    #[wasm_bindgen(js_name = getRecoveryBinding, unchecked_return_type = "Promise<RecoveryBinding>")]
    pub fn get_recovery_binding(&self, leaf_index: BigInt) -> Promise {
        let manager = Arc::clone(&self.0);
        let leaf_index = js::u64_arg("leafIndex", leaf_index);
        js::promise(async move {
            let binding = manager
                .get_recovery_binding(leaf_index?)
                .await
                .map_err(to_js)?;
            let optional =
                |value: Option<String>| value.map_or(JsValue::UNDEFINED, Into::into);
            js::object(&[
                ("recoveryAgent", optional(binding.recovery_agent)),
                (
                    "pendingRecoveryAgent",
                    optional(binding.pending_recovery_agent),
                ),
                ("executeAfter", optional(binding.execute_after)),
            ])
        })
    }
}

/// Reads a plain object whose values are all strings.
fn string_map(name: &str, value: &JsValue) -> Result<HashMap<String, String>, JsValue> {
    let error = || invalid_argument(&format!("`{name}` must be an object of strings"));
    if !value.is_object() {
        return Err(error());
    }
    Object::entries(value.unchecked_ref())
        .iter()
        .map(|entry| {
            let entry: js_sys::Array = entry.unchecked_into();
            Some((entry.get(0).as_string()?, entry.get(1).as_string()?))
        })
        .collect::<Option<_>>()
        .ok_or_else(error)
}
