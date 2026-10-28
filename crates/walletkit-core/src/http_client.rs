//! The configuration shared by every HTTP client that `WalletKit` builds itself.

/// Starts building an HTTP client that trusts the bundled Mozilla roots instead of reqwest's
/// platform verifier, which panics on Android unless initialized through JNI.
#[cfg(not(target_arch = "wasm32"))]
pub fn builder() -> reqwest::ClientBuilder {
    let roots = webpki_root_certs::TLS_SERVER_ROOT_CERTS
        .iter()
        .map(|cert| reqwest::Certificate::from_der(cert).expect("bundled root is DER"));
    reqwest::Client::builder()
        .tls_certs_only(roots)
        .user_agent(concat!(
            env!("CARGO_PKG_NAME"),
            "/",
            env!("CARGO_PKG_VERSION")
        ))
}

/// Starts building an HTTP client. Browsers verify TLS themselves.
#[cfg(target_arch = "wasm32")]
pub fn builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn bundled_roots_initialize_tls_backend() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        assert!(builder().build().is_ok());
    }

    #[tokio::test]
    #[ignore = "requires access to the public Worldchain Sepolia RPC"]
    async fn bundled_roots_verify_public_tls() {
        let response = builder()
            .build()
            .unwrap()
            .get("https://rpc.worldchain-sepolia.worldcoin.org")
            .timeout(Duration::from_secs(5))
            .send()
            .await;

        assert!(response.is_ok(), "{response:?}");
    }
}
