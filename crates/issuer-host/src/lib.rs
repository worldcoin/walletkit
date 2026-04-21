//! IssuerHost — host orchestrator for the host-mediated Issuers SDK experiment.
//!
//! The host exposes a UniFFI callback trait (`IssuerDriver`) that foreign
//! implementations (orb-kit, nfc-kit) satisfy at runtime. The Python harness
//! registers concrete issuers and the host dispatches `fetch_credential` calls
//! to whichever issuer the caller requests.

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use thiserror::Error;

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
    /// Unexpected callback errors from UniFFI are surfaced explicitly.
    #[error("unexpected UniFFI callback error: {reason}")]
    UnexpectedUniFFICallback {
        /// Reason reported by UniFFI.
        reason: String,
    },
}

impl From<uniffi::UnexpectedUniFFICallbackError> for HostError {
    fn from(error: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::UnexpectedUniFFICallback {
            reason: error.reason,
        }
    }
}

/// Driver interface that each issuer implementation must satisfy.
///
/// The host calls this synchronously; adapters in the Python harness bridge
/// the call into the async `fetch_credential_async` methods exported by
/// `orb-kit` and `nfc-kit`.
#[uniffi::export(with_foreign)]
pub trait IssuerDriver: Send + Sync {
    /// Accepts a JSON-serialized `CredentialRequest` and returns a
    /// JSON-serialized `Credential` (or an error).
    fn fetch_credential(&self, request_json: String) -> HostResult<String>;
}

/// Registry and dispatcher for named credential issuers.
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

    /// Dispatches a JSON credential request to the named issuer.
    ///
    /// # Errors
    ///
    /// Returns an error if the issuer is unknown or its callback fails.
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

        tokio::task::spawn_blocking(move || issuer.fetch_credential(request_json))
            .await
            .map_err(|error| HostError::UnexpectedUniFFICallback {
                reason: error.to_string(),
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

    use super::{HostError, IssuerDriver, IssuerHost, HostResult};

    struct FakeIssuer {
        prefix: &'static str,
    }

    impl IssuerDriver for FakeIssuer {
        fn fetch_credential(&self, request_json: String) -> HostResult<String> {
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
}
