//! Native request-integrity callbacks used to authenticate Flamingo connections.

use std::{sync::Arc, time::Duration};

use attested_request::{
    base::CanonicalRequest,
    sign::{SignError, SignedHeaders, Signer},
    Platform,
};
use tokio_tungstenite::tungstenite::handshake::client::Request;

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

pub(super) async fn sign_request(
    provider: Arc<dyn RequestIntegrityProvider>,
    request: Request,
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

        tokio::task::spawn_blocking(move || {
            let uri = request.uri();
            let scheme = match uri.scheme_str() {
                Some("ws" | "http") => "http",
                Some("wss" | "https") => "https",
                _ => return Err(RequestIntegrityError::SigningFailed),
            };
            let authority = uri
                .authority()
                .ok_or(RequestIntegrityError::SigningFailed)?;
            let canonical = CanonicalRequest::new(
                request.method().as_str(),
                scheme,
                authority.as_str(),
                uri.path(),
                uri.query(),
                b"",
            )
            .map_err(|_| RequestIntegrityError::SigningFailed)?;
            attested_request::sign::sign_request(&canonical, &session.token, &session)
                .map_err(|error| match error {
                    SignError::Signer(error) => error,
                    _ => RequestIntegrityError::SigningFailed,
                })
        })
        .await
        .map_err(|_| RequestIntegrityError::SigningFailed)?
    })
    .await
    .map_err(|_| RequestIntegrityError::TimedOut)?
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

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            atomic::{AtomicU8, Ordering},
            Condvar, Mutex,
        },
        time::SystemTime,
    };

    use attested_request::{
        base::CanonicalRequest,
        sign::SignedHeaders,
        signature::SignatureParams,
        test_util::{test_key, SoftwareSigner, TestClaims, TestIssuer},
        token::TokenVerifier,
        Platform, RejectReason, Verifier,
    };
    use tokio_tungstenite::tungstenite::{
        client::IntoClientRequest, handshake::client::Request, http,
    };

    use super::*;

    const AUDIENCE: &str = "flamingo-verifier";
    const TARGET: &str = "/proxy/a%20b/v1/matches?x=%2F&x=one+two";

    fn request(url: &str) -> Request {
        url.into_client_request().unwrap()
    }

    fn received(
        headers: &SignedHeaders,
        method: &str,
        target: &str,
    ) -> http::request::Parts {
        let mut request = http::Request::builder().method(method).uri(target);
        for (name, value) in headers.headers() {
            request = request.header(name, value);
        }
        request.body(()).unwrap().into_parts().0
    }

    struct SoftwareCallback {
        signer: SoftwareSigner,
        runtime_thread: std::thread::ThreadId,
        digests: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl RequestDigestSigner for SoftwareCallback {
        fn sign_digest(
            &self,
            client_data_hash: Vec<u8>,
        ) -> Result<Vec<u8>, RequestIntegrityError> {
            assert_ne!(std::thread::current().id(), self.runtime_thread);
            let digest = client_data_hash.as_slice().try_into().unwrap();
            self.digests.lock().unwrap().push(client_data_hash);
            Ok(self.signer.sign(&digest).unwrap())
        }
    }

    struct RotatingProvider {
        issuer: TestIssuer,
        platform: Platform,
        next_key: AtomicU8,
        runtime_thread: std::thread::ThreadId,
        digests: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl RotatingProvider {
        fn new(platform: Platform) -> Self {
            Self {
                issuer: TestIssuer::new("https://attestation.example"),
                platform,
                next_key: AtomicU8::new(1),
                runtime_thread: std::thread::current().id(),
                digests: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn verifier(&self, scheme: &str, authority: &str) -> Verifier {
            let tokens = TokenVerifier::new(
                [(
                    self.issuer.issuer.clone(),
                    Arc::new(self.issuer.keys()) as _,
                )],
                [AUDIENCE.to_owned()],
            )
            .unwrap();
            Verifier::builder(tokens, authority)
                .scheme(scheme)
                .build()
                .unwrap()
        }
    }

    #[async_trait::async_trait]
    impl RequestIntegrityProvider for RotatingProvider {
        async fn prepare(
            &self,
        ) -> Result<RequestIntegritySession, RequestIntegrityError> {
            let key = self.next_key.fetch_add(1, Ordering::Relaxed);
            let signer =
                SoftwareSigner::new(test_key(&format!("device-{key}")), self.platform);
            let token = self.issuer.mint(&TestClaims::valid(
                AUDIENCE,
                self.platform,
                signer.verifying_key(),
                SystemTime::now(),
            ));
            Ok(RequestIntegritySession {
                token,
                platform: match self.platform {
                    Platform::Ios => RequestIntegrityPlatform::Ios,
                    Platform::Android => RequestIntegrityPlatform::Android,
                },
                signer: Arc::new(SoftwareCallback {
                    signer,
                    runtime_thread: self.runtime_thread,
                    digests: self.digests.clone(),
                }),
            })
        }
    }

    #[tokio::test]
    async fn software_callbacks_verify_for_the_final_websocket_request() {
        for platform in [Platform::Ios, Platform::Android] {
            for (url, scheme, authority) in [
                (
                    format!("wss://Verifier.Example:443{TARGET}"),
                    "https",
                    "verifier.example",
                ),
                (
                    format!("ws://Verifier.Example:80{TARGET}"),
                    "http",
                    "verifier.example",
                ),
                (
                    format!("wss://Verifier.Example:8443{TARGET}"),
                    "https",
                    "verifier.example:8443",
                ),
            ] {
                let provider = Arc::new(RotatingProvider::new(platform));
                let signed =
                    sign_request(provider.clone(), request(&url)).await.unwrap();
                let context = provider
                    .verifier(scheme, authority)
                    .verify(&received(&signed, "GET", TARGET), b"")
                    .await
                    .unwrap();
                assert_eq!(context.device.platform, platform);
                assert_eq!(context.device.audience, AUDIENCE);
                assert_eq!(context.request_binding, signed.request_binding);
                assert_eq!(
                    context.device.key.verifying_key(),
                    test_key("device-1").verifying_key()
                );

                let params = SignatureParams::parse(&signed.signature_input).unwrap();
                let canonical = CanonicalRequest::new(
                    "GET",
                    scheme,
                    authority,
                    "/proxy/a%20b/v1/matches",
                    Some("x=%2F&x=one+two"),
                    b"",
                )
                .unwrap();
                let digest = canonical
                    .signature_base(&params, &signed.integrity_token)
                    .client_data_hash();
                assert_eq!(*provider.digests.lock().unwrap(), [digest.to_vec()]);
            }
        }
    }

    #[tokio::test]
    async fn reconnects_prepare_new_key_bound_sessions_and_fresh_signatures() {
        let provider = Arc::new(RotatingProvider::new(Platform::Android));
        let url = "wss://verifier.example/v1/matches";
        let first = sign_request(provider.clone(), request(url)).await.unwrap();
        let second = sign_request(provider.clone(), request(url)).await.unwrap();
        assert_eq!(provider.next_key.load(Ordering::Relaxed), 3);
        assert_ne!(first.integrity_token, second.integrity_token);
        assert_ne!(first.signature_input, second.signature_input);
        assert_ne!(first.request_binding, second.request_binding);
        let verifier = provider.verifier("https", "verifier.example");
        for headers in [&first, &second] {
            verifier
                .verify(&received(headers, "GET", "/v1/matches"), b"")
                .await
                .unwrap();
        }
        let mut mixed = received(&second, "GET", "/v1/matches");
        mixed
            .headers
            .insert("integrity-token", first.integrity_token.parse().unwrap());
        assert_eq!(
            verifier.verify(&mixed, b"").await.unwrap_err().reason,
            RejectReason::SignatureInvalid
        );
    }

    #[tokio::test]
    async fn signatures_reject_changes_to_covered_request_components() {
        let provider = Arc::new(RotatingProvider::new(Platform::Android));
        let signed = sign_request(
            provider.clone(),
            request(&format!("wss://verifier.example{TARGET}")),
        )
        .await
        .unwrap();
        let verifier = provider.verifier("https", "verifier.example");
        for (method, target, body) in [
            ("POST", TARGET, b"".as_slice()),
            (
                "GET",
                "/proxy/a%20b/v1/other?x=%2F&x=one+two",
                b"".as_slice(),
            ),
            (
                "GET",
                "/proxy/a%20b/v1/matches?x=%2f&x=one+two",
                b"".as_slice(),
            ),
            ("GET", TARGET, b"changed".as_slice()),
        ] {
            assert_eq!(
                verifier
                    .verify(&received(&signed, method, target), body)
                    .await
                    .unwrap_err()
                    .reason,
                RejectReason::SignatureInvalid
            );
        }
        for (scheme, authority) in
            [("wss", "verifier.example"), ("https", "other.example")]
        {
            assert_eq!(
                provider
                    .verifier(scheme, authority)
                    .verify(&received(&signed, "GET", TARGET), b"")
                    .await
                    .unwrap_err()
                    .reason,
                RejectReason::SignatureInvalid
            );
        }
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
            sign_request(
                Arc::new(FailingProvider),
                request("wss://verifier.example/v1/matches")
            )
            .await,
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
            sign_request(
                Arc::new(PendingProvider),
                request("wss://verifier.example/v1/matches")
            )
            .await,
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
                sign_request(
                    fixed_provider(token, Err(RequestIntegrityError::SigningFailed),),
                    request("wss://verifier.example/v1/matches")
                )
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
                sign_request(fixed_provider("opaque-token", signature),
                    request("wss://verifier.example/v1/matches")).await,
                Err(actual) if actual == expected
            ));
        }
    }

    struct BlockingSigner {
        release: Arc<(Mutex<bool>, Condvar)>,
        entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        finished: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    }

    impl RequestDigestSigner for BlockingSigner {
        fn sign_digest(&self, _: Vec<u8>) -> Result<Vec<u8>, RequestIntegrityError> {
            self.entered
                .lock()
                .unwrap()
                .take()
                .unwrap()
                .send(())
                .unwrap();
            let (released, condition) = &*self.release;
            let _guard = condition
                .wait_while(released.lock().unwrap(), |ready| !*ready)
                .unwrap();
            self.finished
                .lock()
                .unwrap()
                .take()
                .unwrap()
                .send(())
                .unwrap();
            Ok(vec![1])
        }
    }

    #[tokio::test(start_paused = true)]
    async fn discards_a_native_signature_that_finishes_after_the_deadline() {
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
        let provider = Arc::new(FixedProvider(RequestIntegritySession {
            token: "opaque-token".to_owned(),
            platform: RequestIntegrityPlatform::Android,
            signer: Arc::new(BlockingSigner {
                release: release.clone(),
                entered: Mutex::new(Some(entered_tx)),
                finished: Mutex::new(Some(finished_tx)),
            }),
        }));
        let signing = tokio::spawn(sign_request(
            provider,
            request("wss://verifier.example/v1/matches"),
        ));
        entered_rx.await.unwrap();
        tokio::time::advance(AUTHENTICATION_TIMEOUT).await;
        let result = signing.await.unwrap();
        *release.0.lock().unwrap() = true;
        release.1.notify_one();
        finished_rx.await.unwrap();
        assert_eq!(result, Err(RequestIntegrityError::TimedOut));
    }
}
