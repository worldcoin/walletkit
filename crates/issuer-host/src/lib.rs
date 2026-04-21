//! IssuerHost — host orchestrator for the host-mediated Issuers SDK experiment.
//!
//! The host is **fully generic**: it knows nothing about Orb, NFC, or any
//! credential-domain concept.  It maintains a registry of named
//! [`issuer_sdk::IssuerDriver`] implementations and dispatches
//! `fetch_credential` calls to whichever one the caller requests.
//!
//! ## UniFFI callback interface
//!
//! `issuer-sdk` defines [`issuer_sdk::IssuerDriver`] as a plain Rust trait so
//! that `orb-kit` and `nfc-kit` can implement it without depending on this
//! crate.  Here we declare the UniFFI callback interface — named
//! `IssuerDriverCallback` to avoid a name clash — that the Python (or Swift /
//! Kotlin) host implements.  An `Arc<dyn IssuerDriverCallback>` stored in the
//! registry is also an `Arc<dyn issuer_sdk::IssuerDriver>` via the blanket impl
//! below, so the two halves compose cleanly.

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use thiserror::Error;

// Bring the plain Rust trait into scope so `issuer-host` and its tests can use
// it without always writing the full path.
pub use issuer_sdk::{IssuerDriver, SdkError};

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
    /// The issuer driver returned an SDK-level error.
    #[error("issuer error: {0}")]
    IssuerError(String),
    /// Unexpected callback errors from UniFFI are surfaced explicitly.
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

// ── UniFFI callback interface ─────────────────────────────────────────────────

/// UniFFI callback interface: the contract that foreign (Python / Swift /
/// Kotlin) implementations must satisfy to register as an issuer.
///
/// Uses [`HostError`] as its error type (a UniFFI-annotated enum) so it can
/// cross the FFI boundary.  A blanket `impl IssuerDriver for T where T:
/// IssuerDriverCallback` maps `HostError` back to `SdkError::IssuanceFailed`
/// for the Rust-native pathway.
#[uniffi::export(with_foreign)]
pub trait IssuerDriverCallback: Send + Sync {
    /// Accept a JSON-serialized `CredentialRequest` and return a
    /// JSON-serialized `Credential`, or a `HostError` on failure.
    fn fetch_credential(&self, request_json: String) -> Result<String, HostError>;
}



// ── Registry and dispatcher ───────────────────────────────────────────────────

/// Registry and dispatcher for named credential issuers.
///
/// Completely generic: the host has no knowledge of what any issuer does or
/// what credential types it produces.
#[derive(uniffi::Object)]
pub struct IssuerHost {
    registry: RwLock<HashMap<String, Arc<dyn IssuerDriverCallback>>>,
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
    /// # Errors
    ///
    /// Returns an error if the name is blank or already registered.
    pub fn register_issuer(
        &self,
        name: String,
        issuer: Arc<dyn IssuerDriverCallback>,
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

    /// Dispatches a JSON credential request to the named issuer.
    ///
    /// # Errors
    ///
    /// Returns an error if the issuer is unknown, its callback fails, or the
    /// issuer driver returns an [`SdkError`].
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

        tokio::task::spawn_blocking(move || {
            IssuerDriverCallback::fetch_credential(issuer.as_ref(), request_json)
        })
        .await
        .map_err(|e| HostError::UnexpectedUniFFICallback {
            reason: e.to_string(),
        })?
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

    use super::{HostError, IssuerDriverCallback, IssuerHost};

    struct FakeIssuer {
        prefix: &'static str,
    }

    impl IssuerDriverCallback for FakeIssuer {
        fn fetch_credential(&self, request_json: String) -> Result<String, HostError> {
            Ok(format!("{}:{request_json}", self.prefix))
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
    async fn propagates_issuer_host_error() {
        struct FailingIssuer;
        impl IssuerDriverCallback for FailingIssuer {
            fn fetch_credential(&self, _: String) -> Result<String, HostError> {
                Err(HostError::IssuerError("boom".to_string()))
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
