//! IssuerHost — host orchestrator for the host-mediated Issuers SDK experiment.
//!
//! The host is **fully generic**.  It holds a registry of named
//! [`IssuerDriver`] implementations and dispatches `fetch_credential_with`
//! calls by sending an [`IssuerMsg`] and awaiting the result directly — no
//! `spawn_blocking` needed since `handle_message` is async.
//!
//! ## UniFFI scaffolding
//!
//! `issuer-sdk` owns `setup_scaffolding!("issuer_sdk")` and exports
//! `IssuerDriver`, `IssuerMsg`, and `IssuerValue` as proper UniFFI types.
//! This crate re-exports those symbols via
//! `issuer_sdk::uniffi_reexport_scaffolding!()`.

extern crate issuer_sdk;
issuer_sdk::uniffi_reexport_scaffolding!();

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use thiserror::Error;

pub use issuer_sdk::{IssuerDriver, IssuerMsg, IssuerValue, SdkError};

pub type HostResult<T> = Result<T, HostError>;

/// Errors returned by the issuer host.
#[derive(Debug, Clone, PartialEq, Eq, Error, uniffi::Error)]
pub enum HostError {
    #[error("issuer name must not be empty")]
    InvalidIssuerName,
    #[error("issuer `{name}` is already registered")]
    IssuerAlreadyRegistered { name: String },
    #[error("issuer `{name}` was not found")]
    IssuerNotFound { name: String },
    #[error("issuer error: {0}")]
    IssuerError(String),
    /// The driver returned an [`IssuerValue`] variant the host did not expect
    /// for this operation (protocol mismatch; guard for future variants).
    #[error("unexpected issuer value: {0}")]
    UnexpectedValue(String),
    #[error("unexpected UniFFI callback error: {reason}")]
    UnexpectedUniFFICallback { reason: String },
}

impl From<SdkError> for HostError {
    fn from(e: SdkError) -> Self {
        Self::IssuerError(e.to_string())
    }
}

impl From<uniffi::UnexpectedUniFFICallbackError> for HostError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::UnexpectedUniFFICallback { reason: e.reason }
    }
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
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self {
            registry: RwLock::new(HashMap::new()),
        }
    }

    /// Registers a named issuer.  Accepts any `Arc<dyn IssuerDriver>`.
    pub fn register_issuer(
        &self,
        name: String,
        issuer: Arc<dyn IssuerDriver>,
    ) -> HostResult<()> {
        let normalized = normalize_name(name)?;
        let mut registry = self.registry.write().expect("lock poisoned");
        if registry.contains_key(&normalized) {
            return Err(HostError::IssuerAlreadyRegistered { name: normalized });
        }
        registry.insert(normalized, issuer);
        Ok(())
    }

    pub fn available_issuers(&self) -> Vec<String> {
        let mut v: Vec<_> = self
            .registry
            .read()
            .expect("lock poisoned")
            .keys()
            .cloned()
            .collect();
        v.sort();
        v
    }

    /// Sends `IssuerMsg::FetchCredential` to the named issuer, awaits the
    /// result, and unwraps the `IssuerValue::Credential` payload.
    ///
    /// Because `handle_message` is async, this is a direct await — no
    /// `spawn_blocking` required.
    pub async fn fetch_credential_with(
        &self,
        name: String,
        request_json: String,
    ) -> HostResult<String> {
        let normalized = normalize_name(name)?;
        let issuer = self
            .registry
            .read()
            .expect("lock poisoned")
            .get(&normalized)
            .cloned()
            .ok_or_else(|| HostError::IssuerNotFound {
                name: normalized.clone(),
            })?;

        let value = issuer
            .handle_message(IssuerMsg::FetchCredential { request_json })
            .await
            .map_err(HostError::from)?;

        match value {
            IssuerValue::Credential { json } => Ok(json),
            #[allow(unreachable_patterns)]
            other => Err(HostError::UnexpectedValue(format!("{other:?}"))),
        }
    }
}

fn normalize_name(name: String) -> HostResult<String> {
    let s = name.trim().to_string();
    if s.is_empty() {
        return Err(HostError::InvalidIssuerName);
    }
    Ok(s)
}

uniffi::setup_scaffolding!("issuer_host");

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{HostError, IssuerDriver, IssuerHost, IssuerMsg, IssuerValue, SdkError};

    struct FakeIssuer {
        prefix: &'static str,
    }

    #[async_trait::async_trait]
    impl IssuerDriver for FakeIssuer {
        async fn handle_message(&self, msg: IssuerMsg) -> Result<IssuerValue, SdkError> {
            match msg {
                IssuerMsg::FetchCredential { request_json } => {
                    Ok(IssuerValue::Credential {
                        json: format!("{}:{request_json}", self.prefix),
                    })
                }
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn registers_and_dispatches() {
        let host = IssuerHost::new();
        host.register_issuer("orb-kit".into(), Arc::new(FakeIssuer { prefix: "orb" }))
            .unwrap();
        host.register_issuer("nfc-kit".into(), Arc::new(FakeIssuer { prefix: "nfc" }))
            .unwrap();

        assert_eq!(
            host.available_issuers(),
            vec!["nfc-kit".to_string(), "orb-kit".to_string()]
        );
        assert_eq!(
            host.fetch_credential_with("orb-kit".into(), "payload".into())
                .await
                .unwrap(),
            "orb:payload"
        );
        assert_eq!(
            host.fetch_credential_with("nfc-kit".into(), "payload".into())
                .await
                .unwrap(),
            "nfc:payload"
        );
    }

    #[test]
    fn rejects_duplicate_registration() {
        let host = IssuerHost::new();
        host.register_issuer("orb-kit".into(), Arc::new(FakeIssuer { prefix: "a" }))
            .unwrap();
        let err = host
            .register_issuer("orb-kit".into(), Arc::new(FakeIssuer { prefix: "b" }))
            .unwrap_err();
        assert_eq!(
            err,
            HostError::IssuerAlreadyRegistered {
                name: "orb-kit".into()
            }
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn rejects_unknown_issuers() {
        let host = IssuerHost::new();
        let err = host
            .fetch_credential_with("missing".into(), "payload".into())
            .await
            .unwrap_err();
        assert_eq!(err, HostError::IssuerNotFound { name: "missing".into() });
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn maps_sdk_error_to_host_error() {
        struct FailingIssuer;
        #[async_trait::async_trait]
        impl IssuerDriver for FailingIssuer {
            async fn handle_message(&self, _: IssuerMsg) -> Result<IssuerValue, SdkError> {
                Err(SdkError::IssuanceFailed("boom".into()))
            }
        }
        let host = IssuerHost::new();
        host.register_issuer("bad".into(), Arc::new(FailingIssuer))
            .unwrap();
        let err = host
            .fetch_credential_with("bad".into(), "payload".into())
            .await
            .unwrap_err();
        assert!(matches!(err, HostError::IssuerError(_)));
    }
}
