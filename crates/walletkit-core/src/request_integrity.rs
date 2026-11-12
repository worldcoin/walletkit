//! Native request-integrity callbacks for authenticated HTTP and WebSocket requests.

use std::{
    sync::{Arc, LazyLock},
    time::Duration,
};

use tokio::sync::Semaphore;

use attested_request::{
    base::CanonicalRequest,
    sign::{SignError, SignedHeaders, Signer},
    Platform,
};

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
    /// A host callback threw an unexpected exception.
    #[error("request integrity callback failed")]
    CallbackFailed,
    /// Preparing or signing exceeded the authentication deadline.
    #[error("request integrity authentication timed out")]
    TimedOut,
}

impl From<uniffi::UnexpectedUniFFICallbackError> for RequestIntegrityError {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::CallbackFailed
    }
}

/// Signs a SHA-256 client-data digest with the key certified by the session token.
///
/// The host captures the key identifier and audience in this object. `WalletKit` never
/// receives private-key material. The callback is invoked on a blocking worker.
/// A running native signing operation cannot be cancelled when authentication times
/// out; its late result is discarded. At most four native signing calls run process-wide;
/// a timed-out call retains its slot until the native callback returns.
#[uniffi::export(with_foreign)]
pub trait RequestDigestSigner: Send + Sync {
    /// Signs exactly 32 bytes and returns the platform's native signature encoding.
    ///
    /// iOS returns an App Attest assertion; Android returns a DER ECDSA signature.
    /// The digest must be forwarded unchanged. Android must sign this precomputed hash,
    /// without hashing it again; iOS passes it directly as App Attest's `clientDataHash`.
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
    /// A valid integrity token for the host-selected audience.
    pub token: String,
    /// Encoding expected from the native signer.
    pub platform: RequestIntegrityPlatform,
    /// A signer capturing the matching hardware key and native signing context.
    pub signer: Arc<dyn RequestDigestSigner>,
}

/// Supplies authentication material before each authenticated request or WebSocket connection.
///
/// The host owns token acquisition, refresh, audience policy, and hardware-key lifecycle.
/// It selects the audience when configuring the provider; `WalletKit` does not decode the
/// token or receive the audience or key identifier. Preparing and signing share a 30-second
/// deadline for each authentication attempt.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait RequestIntegrityProvider: Send + Sync {
    /// Returns a usable token and its matching signer, reusing a cached token when valid.
    ///
    /// # Errors
    /// Returns [`RequestIntegrityError`] if an integrity session is unavailable.
    async fn prepare(&self) -> Result<RequestIntegritySession, RequestIntegrityError>;
}

pub(crate) const AUTHENTICATION_TIMEOUT: Duration = Duration::from_secs(30);

/// Bounds native callbacks even when timed-out callers abandon their results.
pub(crate) static SIGNING_SLOTS: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(4)));

/// Signs the final HTTP request, including its serialized body.
#[cfg(any(feature = "issuers", test))]
pub(crate) async fn sign_http_request(
    provider: Arc<dyn RequestIntegrityProvider>,
    request: &reqwest::Request,
) -> Result<SignedHeaders, RequestIntegrityError> {
    let method = request.method().clone();
    let url = request.url().clone();
    let body = match request.body() {
        Some(body) => body
            .as_bytes()
            .ok_or(RequestIntegrityError::SigningFailed)?
            .to_vec(),
        None => Vec::new(),
    };
    sign_with_limit(provider, SIGNING_SLOTS.clone(), move |session| {
        let host = url.host_str().ok_or(RequestIntegrityError::SigningFailed)?;
        let authority = url
            .port()
            .map_or_else(|| host.to_owned(), |port| format!("{host}:{port}"));
        let canonical = CanonicalRequest::new(
            method.as_str(),
            url.scheme(),
            &authority,
            url.path(),
            url.query(),
            &body,
        )
        .map_err(|_| RequestIntegrityError::SigningFailed)?;
        sign_canonical_request(&canonical, &session)
    })
    .await
}

pub(crate) async fn sign_with_limit(
    provider: Arc<dyn RequestIntegrityProvider>,
    slots: Arc<Semaphore>,
    sign: impl FnOnce(RequestIntegritySession) -> Result<SignedHeaders, RequestIntegrityError>
        + Send
        + 'static,
) -> Result<SignedHeaders, RequestIntegrityError> {
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
        let permit = slots
            .acquire_owned()
            .await
            .map_err(|_| RequestIntegrityError::Unavailable)?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            sign(session)
        })
        .await
        .map_err(|_| RequestIntegrityError::SigningFailed)?
    })
    .await
    .map_err(|_| RequestIntegrityError::TimedOut)?
}

pub(crate) fn sign_canonical_request(
    canonical: &CanonicalRequest<'_>,
    session: &RequestIntegritySession,
) -> Result<SignedHeaders, RequestIntegrityError> {
    attested_request::sign::sign_request(canonical, &session.token, session).map_err(
        |error| match error {
            SignError::Signer(error) => error,
            _ => RequestIntegrityError::SigningFailed,
        },
    )
}

impl Signer for RequestIntegritySession {
    type Error = RequestIntegrityError;

    fn platform(&self) -> Platform {
        match self.platform {
            RequestIntegrityPlatform::Ios => Platform::Ios,
            RequestIntegrityPlatform::Android => Platform::Android,
        }
    }

    fn sign(&self, client_data_hash: &[u8; 32]) -> Result<Vec<u8>, Self::Error> {
        let signature = self.signer.sign_digest(client_data_hash.to_vec())?;
        if signature.is_empty() {
            return Err(RequestIntegrityError::SigningFailed);
        }
        Ok(signature)
    }
}
