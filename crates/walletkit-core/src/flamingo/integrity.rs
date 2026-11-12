//! Request-integrity signing for Flamingo WebSocket handshakes.

use std::sync::Arc;

use attested_request::{base::CanonicalRequest, sign::SignedHeaders};
use tokio::sync::Semaphore;
use tokio_tungstenite::tungstenite::handshake::client::Request;

use crate::request_integrity::{
    sign_canonical_request, sign_with_limit, SIGNING_SLOTS,
};
pub use crate::request_integrity::{
    RequestDigestSigner, RequestIntegrityError, RequestIntegrityPlatform,
    RequestIntegrityProvider, RequestIntegritySession,
};

pub(super) async fn sign_request(
    provider: Arc<dyn RequestIntegrityProvider>,
    request: Request,
) -> Result<SignedHeaders, RequestIntegrityError> {
    sign_request_with_limit(provider, request, SIGNING_SLOTS.clone()).await
}

async fn sign_request_with_limit(
    provider: Arc<dyn RequestIntegrityProvider>,
    request: Request,
    slots: Arc<Semaphore>,
) -> Result<SignedHeaders, RequestIntegrityError> {
    sign_with_limit(provider, slots, move |session| {
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
        sign_canonical_request(&canonical, &session)
    })
    .await
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            atomic::{AtomicU8, Ordering},
            Condvar, Mutex,
        },
        time::{Duration, SystemTime},
    };

    use attested_request::{
        base::CanonicalRequest,
        sign::{SignedHeaders, Signer},
        signature::SignatureParams,
        test_util::{test_key, SoftwareSigner, TestClaims, TestIssuer},
        token::TokenVerifier,
        Platform, RejectReason, Verifier,
    };
    use tokio_tungstenite::tungstenite::{
        client::IntoClientRequest, handshake::client::Request, http,
    };

    use super::*;
    use crate::request_integrity::AUTHENTICATION_TIMEOUT;

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

    /// Verifies the exact upgrade emitted by the matcher, including encoded path and query values.
    #[tokio::test]
    #[allow(clippy::result_large_err)] // Tungstenite fixes the handshake callback's error type.
    async fn matcher_upgrade_verifies_after_crossing_the_network() {
        use super::super::{FlamingoError, FlamingoMatcher, MatchClient};
        use tokio::net::TcpListener;
        use tokio_tungstenite::accept_hdr_async;

        for platform in [Platform::Ios, Platform::Android] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let authority = listener.local_addr().unwrap().to_string();
            let (sent, received) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let socket =
                    accept_hdr_async(stream, move |upgrade: &Request, response| {
                        sent.send(upgrade.clone()).unwrap();
                        Ok(response)
                    })
                    .await
                    .unwrap();
                drop(socket);
            });
            let provider = Arc::new(RotatingProvider::new(platform));
            let mut matcher = FlamingoMatcher::new(&format!(
                "http://{authority}/proxy/a%20b/?x=%2F&x=one+two"
            ))
            .unwrap();
            matcher.integrity_provider = Some(provider.clone());
            let matcher = matcher.dangerously_skip_measurements().unwrap();
            let result = tokio::time::timeout(Duration::from_secs(5), async {
                matcher
                    .client()
                    .await
                    .unwrap()
                    .connect(Duration::from_secs(60))
                    .await
            })
            .await
            .unwrap();
            assert!(matches!(result, Err(FlamingoError::Transport { .. })));
            let upgrade = received.await.unwrap();
            server.await.unwrap();
            let (mut parts, ()) = upgrade.into_parts();
            assert_eq!(parts.uri.path_and_query().unwrap().as_str(), TARGET);
            let verifier = provider.verifier("http", &authority);
            verifier.verify(&parts, b"").await.unwrap();
            parts.uri = "/tampered/v1/matches?x=%2F&x=one+two".parse().unwrap();
            assert_eq!(
                verifier.verify(&parts, b"").await.unwrap_err().reason,
                RejectReason::SignatureInvalid
            );
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
    async fn software_callbacks_verify_the_final_http_method_url_and_body() {
        use crate::request_integrity::sign_http_request;

        let body = br#"{"challenge":{"nested":true},"value":"a b"}"#;
        for platform in [Platform::Ios, Platform::Android] {
            for (url, scheme, authority) in [
                (
                    format!("https://Verifier.Example:443{TARGET}"),
                    "https",
                    "verifier.example",
                ),
                (
                    format!("http://Verifier.Example:8080{TARGET}"),
                    "http",
                    "verifier.example:8080",
                ),
                (format!("https://[::1]:8443{TARGET}"), "https", "[::1]:8443"),
            ] {
                let request = reqwest::Client::new()
                    .post(url)
                    .body(body.to_vec())
                    .build()
                    .unwrap();
                let provider = Arc::new(RotatingProvider::new(platform));
                let signed =
                    sign_http_request(provider.clone(), &request).await.unwrap();
                let verifier = provider.verifier(scheme, authority);
                verifier
                    .verify(&received(&signed, "POST", TARGET), body)
                    .await
                    .unwrap();
                for (method, target, payload) in [
                    ("GET", TARGET, body.as_slice()),
                    (
                        "POST",
                        "/proxy/a%20b/v1/matches?x=%2f&x=one+two",
                        body.as_slice(),
                    ),
                    ("POST", TARGET, b"changed".as_slice()),
                ] {
                    assert_eq!(
                        verifier
                            .verify(&received(&signed, method, target), payload)
                            .await
                            .unwrap_err()
                            .reason,
                        RejectReason::SignatureInvalid,
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn rejects_http_streaming_bodies_before_preparing_a_session() {
        let stream = futures_util::stream::once(async {
            Ok::<_, std::io::Error>(b"payload".as_slice())
        });
        let request = reqwest::Client::new()
            .post("https://verifier.example/challenge")
            .body(reqwest::Body::wrap_stream(stream))
            .build()
            .unwrap();
        assert_eq!(
            crate::request_integrity::sign_http_request(
                Arc::new(FailingProvider(RequestIntegrityError::Unavailable)),
                &request,
            )
            .await,
            Err(RequestIntegrityError::SigningFailed),
        );
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

    /// Returns a selected typed error from the provider callback.
    struct FailingProvider(RequestIntegrityError);

    #[async_trait::async_trait]
    impl RequestIntegrityProvider for FailingProvider {
        async fn prepare(
            &self,
        ) -> Result<RequestIntegritySession, RequestIntegrityError> {
            Err(self.0)
        }
    }

    #[tokio::test]
    async fn preserves_provider_failure() {
        assert!(matches!(
            sign_request(
                Arc::new(FailingProvider(RequestIntegrityError::Unavailable)),
                request("wss://verifier.example/v1/matches")
            )
            .await,
            Err(RequestIntegrityError::Unavailable)
        ));
    }

    /// Unexpected native diagnostics are hidden and preserve the same classification at either callback.
    #[tokio::test]
    async fn unexpected_callback_failures_are_neutral_and_do_not_expose_details() {
        let error = RequestIntegrityError::from(
            uniffi::UnexpectedUniFFICallbackError::new("private native diagnostic"),
        );
        assert_eq!(error, RequestIntegrityError::CallbackFailed);
        assert_eq!(error.to_string(), "request integrity callback failed");
        for provider in [
            Arc::new(FailingProvider(error)) as Arc<dyn RequestIntegrityProvider>,
            fixed_provider("opaque-token", Err(error)),
        ] {
            assert_eq!(
                sign_request(provider, request("wss://verifier.example/v1/matches"))
                    .await,
                Err(RequestIntegrityError::CallbackFailed),
            );
        }
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
        let slots = Arc::new(Semaphore::new(1));
        let signing = tokio::spawn(sign_request_with_limit(
            provider,
            request("wss://verifier.example/v1/matches"),
            slots.clone(),
        ));
        entered_rx.await.unwrap();
        tokio::time::advance(AUTHENTICATION_TIMEOUT).await;
        let result = signing.await.unwrap();
        let queued = tokio::spawn(sign_request_with_limit(
            fixed_provider("opaque-token", Ok(vec![1])),
            request("wss://verifier.example/v1/matches"),
            slots.clone(),
        ));
        tokio::task::yield_now().await;
        tokio::time::advance(AUTHENTICATION_TIMEOUT).await;
        let queued_result = queued.await.unwrap();
        *release.0.lock().unwrap() = true;
        release.1.notify_one();
        finished_rx.await.unwrap();
        assert_eq!(result, Err(RequestIntegrityError::TimedOut));
        assert_eq!(queued_result, Err(RequestIntegrityError::TimedOut));
        // The native worker releases its slot after returning, which can follow the signal.
        tokio::time::resume();
        assert!(sign_request_with_limit(
            fixed_provider("opaque-token", Ok(vec![1])),
            request("wss://verifier.example/v1/matches"),
            slots,
        )
        .await
        .is_ok());
    }
}
