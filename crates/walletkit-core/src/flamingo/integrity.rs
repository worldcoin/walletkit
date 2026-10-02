//! Native request-integrity callbacks used to authenticate Flamingo connections.

use std::{sync::Arc, time::Duration};

/// The platform determines the native signature encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum RequestIntegrityPlatform {
    /// An App Attest assertion encoded as CBOR.
    Ios,
    /// An Android Keystore ECDSA signature encoded as DER.
    Android,
}

/// Request-integrity failures without token, key, or native diagnostic contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum RequestIntegrityError {
    /// The host could not prepare an integrity session.
    #[error("request integrity is unavailable")]
    Unavailable,
    /// The prepared session contains an unusable token.
    #[error("request integrity session is invalid")]
    InvalidSession,
    /// The native signer failed or returned an empty signature.
    #[error("request integrity signing failed")]
    SigningFailed,
    /// Preparing or signing exceeded the authentication deadline.
    #[error("request integrity authentication timed out")]
    TimedOut,
}

impl From<uniffi::UnexpectedUniFFICallbackError> for RequestIntegrityError {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Unavailable
    }
}

/// Signs a SHA-256 client-data digest with the key certified by the session token.
///
/// The host captures the key identifier and audience in this object. `WalletKit` never
/// receives private-key material. The callback is invoked on a blocking worker.
/// A running native signing operation cannot be cancelled when authentication times
/// out; its late result is discarded.
#[uniffi::export(with_foreign)]
pub trait RequestDigestSigner: Send + Sync {
    /// Signs exactly 32 bytes and returns the platform's native signature encoding.
    ///
    /// iOS returns an App Attest assertion; Android returns a DER ECDSA signature.
    /// The digest must be forwarded to the existing native signing operation unchanged.
    ///
    /// # Errors
    /// Returns [`RequestIntegrityError`] if native signing cannot complete.
    fn sign_digest(
        &self,
        client_data_hash: Vec<u8>,
    ) -> Result<Vec<u8>, RequestIntegrityError>;
}

/// A token and the signer pinned to the exact key certified by that token.
///
/// The provider must create the pair atomically so a later key rotation cannot mix them.
/// An already-returned signer must keep using its captured key. The host adapts its native
/// session to these callbacks without passing private-key material or other SDK callback types.
#[derive(Clone, uniffi::Record)]
pub struct RequestIntegritySession {
    /// A valid integrity token for the host-selected Flamingo audience.
    pub token: String,
    /// Encoding expected from the native signer.
    pub platform: RequestIntegrityPlatform,
    /// A signer capturing the matching hardware key and native signing context.
    pub signer: Arc<dyn RequestDigestSigner>,
}

/// Supplies authentication material before each WebSocket connection or reassignment.
///
/// The host owns token acquisition, refresh, audience policy, and hardware-key lifecycle.
/// It selects the audience when configuring the provider; `WalletKit` does not decode the
/// token or receive the audience or key identifier. Preparing and signing share a 30-second
/// deadline in the matcher.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait RequestIntegrityProvider: Send + Sync {
    /// Returns a usable token and its matching signer, reusing a cached token when valid.
    ///
    /// # Errors
    /// Returns [`RequestIntegrityError`] if an integrity session is unavailable.
    async fn prepare(&self) -> Result<RequestIntegritySession, RequestIntegrityError>;
}

const AUTHENTICATION_TIMEOUT: Duration = Duration::from_secs(30);

// TODO: Replace this placeholder with attested-request canonical signing before release.
const MOCK_CLIENT_DATA_HASH: [u8; 32] = [0xA5; 32];

pub(super) async fn prepare_mock_signature(
    provider: Arc<dyn RequestIntegrityProvider>,
) -> Result<(), RequestIntegrityError> {
    tokio::time::timeout(AUTHENTICATION_TIMEOUT, async move {
        let session = provider.prepare().await?;
        if session.token.is_empty()
            || !session
                .token
                .bytes()
                .all(|byte| (0x21..=0x7e).contains(&byte))
        {
            return Err(RequestIntegrityError::InvalidSession);
        }

        let signature = tokio::task::spawn_blocking(move || {
            session.signer.sign_digest(MOCK_CLIENT_DATA_HASH.to_vec())
        })
        .await
        .map_err(|_| RequestIntegrityError::SigningFailed)??;
        if signature.is_empty() {
            return Err(RequestIntegrityError::SigningFailed);
        }

        Ok(())
    })
    .await
    .map_err(|_| RequestIntegrityError::TimedOut)?
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicU8, Ordering},
        Mutex,
    };

    use super::*;

    struct SessionSigner {
        key: u8,
        runtime_thread: std::thread::ThreadId,
        signed_keys: Arc<Mutex<Vec<u8>>>,
    }

    impl RequestDigestSigner for SessionSigner {
        fn sign_digest(
            &self,
            client_data_hash: Vec<u8>,
        ) -> Result<Vec<u8>, RequestIntegrityError> {
            assert_eq!(client_data_hash, MOCK_CLIENT_DATA_HASH);
            assert_ne!(std::thread::current().id(), self.runtime_thread);
            self.signed_keys.lock().unwrap().push(self.key);
            Ok(vec![1, self.key])
        }
    }

    struct RotatingProvider {
        next_key: AtomicU8,
        runtime_thread: std::thread::ThreadId,
        prepared_tokens: Mutex<Vec<String>>,
        signed_keys: Arc<Mutex<Vec<u8>>>,
    }

    #[async_trait::async_trait]
    impl RequestIntegrityProvider for RotatingProvider {
        async fn prepare(
            &self,
        ) -> Result<RequestIntegritySession, RequestIntegrityError> {
            let key = self.next_key.fetch_add(1, Ordering::Relaxed);
            let token = format!("token-for-key-{key}");
            self.prepared_tokens.lock().unwrap().push(token.clone());
            Ok(RequestIntegritySession {
                token,
                platform: RequestIntegrityPlatform::Ios,
                signer: Arc::new(SessionSigner {
                    key,
                    runtime_thread: self.runtime_thread,
                    signed_keys: self.signed_keys.clone(),
                }),
            })
        }
    }

    #[tokio::test]
    async fn prepares_a_fresh_key_bound_session_and_signs_off_executor() {
        let provider = Arc::new(RotatingProvider {
            next_key: AtomicU8::new(1),
            runtime_thread: std::thread::current().id(),
            prepared_tokens: Mutex::new(Vec::new()),
            signed_keys: Arc::new(Mutex::new(Vec::new())),
        });
        for _ in 0..2 {
            prepare_mock_signature(provider.clone()).await.unwrap();
        }
        assert_eq!(provider.next_key.load(Ordering::Relaxed), 3);
        assert_eq!(
            *provider.prepared_tokens.lock().unwrap(),
            ["token-for-key-1", "token-for-key-2"]
        );
        assert_eq!(*provider.signed_keys.lock().unwrap(), [1, 2]);
    }

    struct FailingProvider;

    #[async_trait::async_trait]
    impl RequestIntegrityProvider for FailingProvider {
        async fn prepare(
            &self,
        ) -> Result<RequestIntegritySession, RequestIntegrityError> {
            Err(RequestIntegrityError::Unavailable)
        }
    }

    #[tokio::test]
    async fn preserves_provider_failure() {
        assert!(matches!(
            prepare_mock_signature(Arc::new(FailingProvider)).await,
            Err(RequestIntegrityError::Unavailable)
        ));
    }

    struct PendingProvider;

    #[async_trait::async_trait]
    impl RequestIntegrityProvider for PendingProvider {
        async fn prepare(
            &self,
        ) -> Result<RequestIntegritySession, RequestIntegrityError> {
            std::future::pending().await
        }
    }

    #[tokio::test(start_paused = true)]
    async fn times_out_a_provider_that_never_returns() {
        let started = tokio::time::Instant::now();
        assert_eq!(
            prepare_mock_signature(Arc::new(PendingProvider)).await,
            Err(RequestIntegrityError::TimedOut)
        );
        assert_eq!(started.elapsed(), AUTHENTICATION_TIMEOUT);
    }

    struct FixedProvider(RequestIntegritySession);

    #[async_trait::async_trait]
    impl RequestIntegrityProvider for FixedProvider {
        async fn prepare(
            &self,
        ) -> Result<RequestIntegritySession, RequestIntegrityError> {
            Ok(self.0.clone())
        }
    }

    struct FixedSigner(Result<Vec<u8>, RequestIntegrityError>);

    impl RequestDigestSigner for FixedSigner {
        fn sign_digest(&self, _: Vec<u8>) -> Result<Vec<u8>, RequestIntegrityError> {
            self.0.clone()
        }
    }

    fn fixed_provider(
        token: &str,
        signature: Result<Vec<u8>, RequestIntegrityError>,
    ) -> Arc<dyn RequestIntegrityProvider> {
        Arc::new(FixedProvider(RequestIntegritySession {
            token: token.to_string(),
            platform: RequestIntegrityPlatform::Android,
            signer: Arc::new(FixedSigner(signature)),
        }))
    }

    #[tokio::test]
    async fn rejects_unusable_tokens_before_signing() {
        for token in ["", " ", "token\r\ninjected: value", "non-ascii-\u{00e9}"] {
            assert!(matches!(
                prepare_mock_signature(fixed_provider(
                    token,
                    Err(RequestIntegrityError::SigningFailed),
                ))
                .await,
                Err(RequestIntegrityError::InvalidSession)
            ));
        }
    }

    #[tokio::test]
    async fn preserves_signer_errors_and_rejects_empty_signatures() {
        for (signature, expected) in [
            (
                Err(RequestIntegrityError::SigningFailed),
                RequestIntegrityError::SigningFailed,
            ),
            (
                Err(RequestIntegrityError::Unavailable),
                RequestIntegrityError::Unavailable,
            ),
            (Ok(Vec::new()), RequestIntegrityError::SigningFailed),
        ] {
            assert!(matches!(
                prepare_mock_signature(fixed_provider("opaque-token", signature)).await,
                Err(actual) if actual == expected
            ));
        }
    }
}
