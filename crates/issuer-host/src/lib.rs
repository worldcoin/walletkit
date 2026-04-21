//! IssuerHost — host orchestrator for the host-mediated Issuers SDK experiment.
//!
//! The host is **fully generic**: it knows nothing about Orb, NFC, or any
//! credential-domain concept.  It maintains a registry of named
//! [`IssuerDriver`] implementations and dispatches `handle_message` calls
//! to whichever one the caller requests.
//!
//! ## UniFFI scaffolding
//!
//! `issuer-sdk` owns `setup_scaffolding!("issuer_sdk")` and exports
//! `IssuerDriver`, `IssuerMsg`, and `IssuerValue` as proper UniFFI types.
//! This crate re-exports those symbols into its own binary via
//! `issuer_sdk::uniffi_reexport_scaffolding!()` — the same pattern used by
//! `walletkit` / `walletkit-core` in the main branch.

// Force the linker to include issuer-sdk's exported UniFFI symbols in this
// binary (mirrors walletkit_core::uniffi_reexport_scaffolding!() in main).
extern crate issuer_sdk;
issuer_sdk::uniffi_reexport_scaffolding!();

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use thiserror::Error;

pub use issuer_sdk::{IssuerDriver, IssuerMsg, IssuerValue, SdkError};

/// Result type for issuer-host operations.
pub type HostResult<T> = Result<T, HostError>;

/// Errors returned by the issuer host.
#[derive(Debug, Clone, PartialEq, Eq, Error, uniffi::Error)]
pub enum HostError {
    /// Issuer names must be non-empty.
    #[error("issuer name must not be empty")]
    InvalidIssuerName,
    /// Registering a duplicate issuer name is rejected.
    #[error("issuer `{name}` is already registered")]
    IssuerAlreadyRegistered {
        /// Duplicate issuer name.
        name: String,
    },
    /// A requested issuer name was not registered.
    #[error("issuer `{name}` was not found")]
    IssuerNotFound {
        /// Missing issuer name.
        name: String,
    },
    /// The issuer driver returned a [`SdkError`].
    #[error("issuer error: {0}")]
    IssuerError(String),
    /// The issuer driver returned an [`IssuerValue`] variant the host did not
    /// expect for this operation (protocol mismatch).
    #[error("unexpected issuer value: {0}")]
    UnexpectedValue(String),
    /// Unexpected UniFFI callback errors are surfaced explicitly.
    #[error("unexpected UniFFI callback error: {reason}")]
    UnexpectedUniFFICallback {
        /// Reason reported by UniFFI.
        reason: String,
    },
}

impl From<SdkError> for HostError {
    fn from(error: SdkError) -> Self {
        Self::IssuerError(error.to_string())
    }
}

impl From<uniffi::UnexpectedUniFFICallbackError> for HostError {
    fn from(error: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::UnexpectedUniFFICallback {
            reason: error.reason,
        }
    }
}

// ── Registry and dispatcher ───────────────────────────────────────────────────

/// Registry and dispatcher for named credential issuers.
///
/// Completely generic: the host has no knowledge of what any issuer does or
/// what credential types it produces.
#[derive(uniffi::Object)]
pub struct IssuerHost {
    registry: RwLock<HashMap<String, Arc<dyn IssuerDriver>>>,
}

impl Default for IssuerHost {
    fn default() -> Self {
        Self::new()
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl IssuerHost {
    /// Creates an empty issuer host.
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self {
            registry: RwLock::new(HashMap::new()),
        }
    }

    /// Registers a named issuer implementation.
    ///
    /// Accepts any `Arc<dyn IssuerDriver>` — the single-method UniFFI callback
    /// interface exported by `issuer-sdk`.  Rust implementations of [`Issuer`]
    /// satisfy `IssuerDriver` automatically via the blanket impl in `issuer-sdk`.
    ///
    /// # Errors
    ///
    /// Returns an error if the name is blank or already registered.
    pub fn register_issuer(
        &self,
        name: String,
        issuer: Arc<dyn IssuerDriver>,
    ) -> HostResult<()> {
        let normalized = normalize_name(name)?;
        let mut registry = self
            .registry
            .write()
            .expect("issuer-host registry lock should not be poisoned");

        if registry.contains_key(&normalized) {
            return Err(HostError::IssuerAlreadyRegistered { name: normalized });
        }

        registry.insert(normalized, issuer);
        Ok(())
    }

    /// Returns all registered issuer names in sorted order.
    pub fn available_issuers(&self) -> Vec<String> {
        let mut issuers = self
            .registry
            .read()
            .expect("issuer-host registry lock should not be poisoned")
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        issuers.sort();
        issuers
    }

    /// Dispatches a `FetchCredential` message to the named issuer and returns
    /// the JSON-serialised credential.
    ///
    /// Internally sends `IssuerMsg::FetchCredential { request_json }` via
    /// `handle_message` and unwraps the expected `IssuerValue::Credential`.
    ///
    /// # Errors
    ///
    /// Returns an error if the issuer is unknown, its callback fails, the
    /// driver returns a [`SdkError`], or the returned [`IssuerValue`] is not
    /// `Credential` (protocol mismatch).
    pub async fn fetch_credential_with(
        &self,
        name: String,
        request_json: String,
    ) -> HostResult<String> {
        let normalized = normalize_name(name)?;
        let issuer = self
            .registry
            .read()
            .expect("issuer-host registry lock should not be poisoned")
            .get(&normalized)
            .cloned()
            .ok_or_else(|| HostError::IssuerNotFound {
                name: normalized.clone(),
            })?;

        let value = tokio::task::spawn_blocking(move || {
            issuer.handle_message(IssuerMsg::FetchCredential { request_json })
        })
        .await
        .map_err(|e| HostError::UnexpectedUniFFICallback {
            reason: e.to_string(),
        })?
        .map_err(HostError::from)?;

        match value {
            IssuerValue::Credential { json } => Ok(json),
            #[allow(unreachable_patterns)] // guard for future IssuerValue variants
            other => Err(HostError::UnexpectedValue(format!("{other:?}"))),
        }
    }
}

fn normalize_name(name: String) -> HostResult<String> {
    let normalized = name.trim().to_string();
    if normalized.is_empty() {
        return Err(HostError::InvalidIssuerName);
    }
    Ok(normalized)
}

uniffi::setup_scaffolding!("issuer_host");

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{HostError, IssuerDriver, IssuerHost, IssuerMsg, IssuerValue, SdkError};

    // FakeIssuer implements IssuerDriver directly (handle_message), since
    // implementing Issuer would require a dep on issuer-sdk's Issuer trait
    // re-imported here — simpler to inline for tests.
    struct FakeIssuer {
        prefix: &'static str,
    }

    impl IssuerDriver for FakeIssuer {
        fn handle_message(&self, msg: IssuerMsg) -> Result<IssuerValue, SdkError> {
            match msg {
                IssuerMsg::FetchCredential { request_json } => Ok(IssuerValue::Credential {
                    json: format!("{}:{request_json}", self.prefix),
                }),
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn registers_and_dispatches_to_named_issuers() {
        let host = IssuerHost::new();
        host.register_issuer("orb-kit".to_string(), Arc::new(FakeIssuer { prefix: "orb" }))
            .expect("register orb-kit");
        host.register_issuer("nfc-kit".to_string(), Arc::new(FakeIssuer { prefix: "nfc" }))
            .expect("register nfc-kit");

        assert_eq!(
            host.available_issuers(),
            vec!["nfc-kit".to_string(), "orb-kit".to_string()]
        );
        assert_eq!(
            host.fetch_credential_with("orb-kit".to_string(), "payload".to_string())
                .await
                .expect("dispatch orb-kit"),
            "orb:payload"
        );
        assert_eq!(
            host.fetch_credential_with("nfc-kit".to_string(), "payload".to_string())
                .await
                .expect("dispatch nfc-kit"),
            "nfc:payload"
        );
    }

    #[test]
    fn rejects_duplicate_registration() {
        let host = IssuerHost::new();
        host.register_issuer("orb-kit".to_string(), Arc::new(FakeIssuer { prefix: "a" }))
            .expect("first registration should succeed");

        let error = host
            .register_issuer("orb-kit".to_string(), Arc::new(FakeIssuer { prefix: "b" }))
            .expect_err("duplicate should fail");

        assert_eq!(
            error,
            HostError::IssuerAlreadyRegistered {
                name: "orb-kit".to_string(),
            }
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn rejects_unknown_issuers() {
        let host = IssuerHost::new();
        let error = host
            .fetch_credential_with("missing".to_string(), "payload".to_string())
            .await
            .expect_err("unknown issuer should fail");

        assert_eq!(
            error,
            HostError::IssuerNotFound {
                name: "missing".to_string(),
            }
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn maps_sdk_error_to_host_error() {
        struct FailingIssuer;
        impl IssuerDriver for FailingIssuer {
            fn handle_message(&self, _msg: IssuerMsg) -> Result<IssuerValue, SdkError> {
                Err(SdkError::IssuanceFailed("boom".to_string()))
            }
        }

        let host = IssuerHost::new();
        host.register_issuer("bad".to_string(), Arc::new(FailingIssuer))
            .expect("register");

        let error = host
            .fetch_credential_with("bad".to_string(), "payload".to_string())
            .await
            .expect_err("should propagate issuer error");

        assert!(matches!(error, HostError::IssuerError(_)));
    }
}
