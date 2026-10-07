//! The `User-Agent` value that `WalletKit` sends with issuer requests.
//!
//! Browsers may ignore or override the header; the value is still useful to hosts
//! that forward it in another header.

#![allow(
    clippy::missing_const_for_fn,
    reason = "`#[wasm_bindgen]` does not support `const fn`"
)]

use walletkit_core::{UserAgent, UserAgentBuilder};
use wasm_bindgen::prelude::*;

/// A built `User-Agent` value.
#[wasm_bindgen(js_name = UserAgent)]
pub struct JsUserAgent(UserAgent);

#[wasm_bindgen(js_class = UserAgent)]
impl JsUserAgent {
    #[wasm_bindgen(js_name = headerValue)]
    #[must_use]
    pub fn header_value(&self) -> String {
        self.0.header_value()
    }
}

/// Builds a [`JsUserAgent`] from `name/version` segments.
#[wasm_bindgen(js_name = UserAgentBuilder)]
pub struct JsUserAgentBuilder(pub(crate) UserAgentBuilder);

#[wasm_bindgen(js_class = UserAgentBuilder)]
impl JsUserAgentBuilder {
    #[wasm_bindgen(js_name = new)]
    #[must_use]
    pub fn new() -> Self {
        Self(UserAgentBuilder::new())
    }

    /// Appends `{name}/{version}`.
    #[wasm_bindgen(js_name = withSegment)]
    #[must_use]
    pub fn with_segment(&self, name: &str, version: &str) -> Self {
        Self(self.0.with_segment(name, version))
    }

    /// Appends `WorldID/{appVersion}` for World ID app clients and
    /// `WorldApp/{appVersion}` otherwise.
    #[wasm_bindgen(js_name = withAppSegmentForClient)]
    #[must_use]
    pub fn with_app_segment_for_client(
        &self,
        app_version: &str,
        client_name: &str,
    ) -> Self {
        Self(self.0.with_app_segment_for_client(app_version, client_name))
    }

    /// Appends `walletkit-core/{version}`.
    #[wasm_bindgen(js_name = withWalletkitSegment)]
    #[must_use]
    pub fn with_walletkit_segment(&self) -> Self {
        Self(self.0.with_walletkit_segment())
    }

    /// Appends `{clientName}/{osVersion}`.
    #[wasm_bindgen(js_name = withClientSegment)]
    #[must_use]
    pub fn with_client_segment(&self, client_name: &str, os_version: &str) -> Self {
        Self(self.0.with_client_segment(client_name, os_version))
    }

    #[must_use]
    pub fn build(&self) -> JsUserAgent {
        JsUserAgent(self.0.build())
    }
}

impl Default for JsUserAgentBuilder {
    fn default() -> Self {
        Self::new()
    }
}
