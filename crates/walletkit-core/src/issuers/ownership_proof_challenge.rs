//! Attested challenges for `PoP` World ID v4 ownership proofs.

use std::{sync::Arc, time::Duration};

use serde::Deserialize;

use crate::{
    error::WalletKitError,
    request_integrity::{sign_http_request, RequestIntegrityProvider},
    Environment, FieldElement, UserAgentBuilder,
};

/// The issuer operation authorized by an ownership proof.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Deserialize, strum::Display, uniffi::Enum,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum OwnershipProofChallengeType {
    /// Enroll with an issuer.
    Enrollment,
    /// Migrate a TEE device identity.
    TeediMigration,
}

/// The challenge returned by the issuer, preserving its wire representation.
#[derive(Debug, Deserialize, uniffi::Record)]
pub struct OwnershipProofChallenge {
    /// Opaque handle to submit with the proof.
    pub challenge_id: String,
    /// Validated hex field element; parse with `FieldElement::try_from_hex_string`.
    pub nonce: String,
    /// The operation this challenge authorizes.
    pub challenge_type: OwnershipProofChallengeType,
    /// Advisory RFC 3339 expiry supplied by the server.
    pub expires_at: String,
}

/// Fetches a v4 challenge using a host-provided attestation token and hardware signer.
/// The provider must be configured for the challenge service's audience.
///
/// # Errors
/// Returns [`WalletKitError`] on signing, network, HTTP, or response-validation failure.
#[uniffi::export(async_runtime = "tokio")]
pub async fn fetch_ownership_proof_challenge(
    environment: &Environment,
    challenge_type: OwnershipProofChallengeType,
    integrity_provider: Arc<dyn RequestIntegrityProvider>,
    user_agent_builder: &UserAgentBuilder,
) -> Result<OwnershipProofChallenge, WalletKitError> {
    let base_url = match environment {
        Environment::Staging => "https://app.stage.orb.worldcoin.org",
        Environment::Production => "https://app.orb.worldcoin.org",
    };
    fetch_challenge(
        base_url,
        challenge_type,
        integrity_provider,
        user_agent_builder,
    )
    .await
}

async fn fetch_challenge(
    base_url: &str,
    challenge_type: OwnershipProofChallengeType,
    integrity_provider: Arc<dyn RequestIntegrityProvider>,
    user_agent_builder: &UserAgentBuilder,
) -> Result<OwnershipProofChallenge, WalletKitError> {
    let client = crate::http_client::builder()
        .user_agent(user_agent_builder.build().to_string())
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .build()?;
    let url = format!("{base_url}/api/v4/zkp/challenge/{challenge_type}");
    let mut request = client.post(&url).build()?;
    let signed = sign_http_request(integrity_provider, &request)
        .await
        .map_err(|error| WalletKitError::Generic {
            error: error.to_string(),
        })?;
    for (name, value) in signed.headers() {
        let mut value =
            reqwest::header::HeaderValue::from_str(value).map_err(|_| {
                WalletKitError::Generic {
                    error: "invalid request integrity header".into(),
                }
            })?;
        value.set_sensitive(true);
        request
            .headers_mut()
            .insert(reqwest::header::HeaderName::from_static(name), value);
    }
    let response = client.execute(request).await?;
    if response.status() != reqwest::StatusCode::CREATED {
        return Err(WalletKitError::NetworkError {
            url,
            status: Some(response.status().as_u16()),
            error: "ownership challenge request rejected".into(),
        });
    }
    let challenge: OwnershipProofChallenge =
        serde_json::from_slice(&response.bytes().await?).map_err(|_| {
            WalletKitError::ResponseValidation("invalid challenge response".into())
        })?;
    if challenge.challenge_type != challenge_type {
        return Err(WalletKitError::ResponseValidation(
            "unexpected challenge type".into(),
        ));
    }
    FieldElement::try_from_hex_string(&challenge.nonce).map_err(|_| {
        WalletKitError::ResponseValidation("invalid challenge nonce".into())
    })?;
    Ok(challenge)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request_integrity::{
        RequestDigestSigner, RequestIntegrityError, RequestIntegrityPlatform,
        RequestIntegritySession,
    };
    use mockito::{Matcher, Server};

    const NONCE: &str =
        "0x0000000000000000000000000000000000000000000000000000000000000001";
    const RESPONSE: &str = r#"{
        "challenge_id": "opaque-id",
        "nonce": "0x0000000000000000000000000000000000000000000000000000000000000001",
        "challenge_type": "enrollment",
        "expires_at": "2030-01-01T00:00:00Z"
    }"#;

    #[tokio::test]
    async fn sends_signed_empty_post_for_each_challenge_type() {
        let mut server = Server::new_async().await;
        for (kind, wire_name) in [
            (OwnershipProofChallengeType::Enrollment, "enrollment"),
            (
                OwnershipProofChallengeType::TeediMigration,
                "teedi_migration",
            ),
        ] {
            let mock = server
                .mock(
                    "POST",
                    format!("/api/v4/zkp/challenge/{wire_name}").as_str(),
                )
                .match_body("")
                .match_header("user-agent", "walletkit-test/1")
                .match_header("integrity-token", "test-token")
                .match_header("signature", Matcher::Regex(".+".into()))
                .match_header("signature-input", Matcher::Regex(".+".into()))
                .with_status(201)
                .with_body(RESPONSE.replace("enrollment", wire_name))
                .create_async()
                .await;
            let challenge = fetch_challenge(
                &server.url(),
                kind,
                Arc::new(TestIntegrity),
                &UserAgentBuilder::new().with_segment("walletkit-test", "1"),
            )
            .await
            .unwrap();
            assert_eq!(challenge.challenge_type, kind);
            assert_eq!(challenge.nonce, NONCE);
            assert_eq!(challenge.challenge_id, "opaque-id");
            assert_eq!(challenge.expires_at, "2030-01-01T00:00:00Z");
            mock.assert_async().await;
        }
    }

    #[tokio::test]
    async fn rejects_bad_responses_and_http_errors_without_retry_or_redirect() {
        let mut server = Server::new_async().await;
        let redirect = server
            .mock("POST", "/redirect")
            .expect(0)
            .create_async()
            .await;
        for (status, body) in [
            (201, "{".to_owned()),
            (201, RESPONSE.replace(NONCE, "invalid")),
            (201, RESPONSE.replace("enrollment", "teedi_migration")),
            (307, String::new()),
            (401, String::new()),
            (503, String::new()),
        ] {
            let mock = server
                .mock("POST", "/api/v4/zkp/challenge/enrollment")
                .with_status(status)
                .with_body(body)
                .with_header("location", "/redirect")
                .expect(1)
                .create_async()
                .await;
            let error = fetch_challenge(
                &server.url(),
                OwnershipProofChallengeType::Enrollment,
                Arc::new(TestIntegrity),
                &UserAgentBuilder::new(),
            )
            .await
            .unwrap_err();
            match error {
                WalletKitError::ResponseValidation(_) => assert_eq!(status, 201),
                WalletKitError::NetworkError { status: actual, .. } => {
                    assert_eq!(actual, Some(u16::try_from(status).unwrap()))
                }
                other => panic!("unexpected error: {other:?}"),
            }
            mock.assert_async().await;
            mock.remove_async().await;
        }
        redirect.assert_async().await;
    }

    struct TestIntegrity;

    #[async_trait::async_trait]
    impl RequestIntegrityProvider for TestIntegrity {
        async fn prepare(
            &self,
        ) -> Result<RequestIntegritySession, RequestIntegrityError> {
            Ok(RequestIntegritySession {
                token: "test-token".into(),
                platform: RequestIntegrityPlatform::Android,
                signer: Arc::new(Self),
            })
        }
    }

    impl RequestDigestSigner for TestIntegrity {
        fn sign_digest(
            &self,
            digest: Vec<u8>,
        ) -> Result<Vec<u8>, RequestIntegrityError> {
            assert_eq!(digest.len(), 32);
            Ok(vec![1])
        }
    }
}
