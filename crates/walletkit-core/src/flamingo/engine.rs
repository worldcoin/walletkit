//! Engine Provider trust and Engine selection (WIP-201 §3.5.2, §3.5.3 and §3.5.4).

use std::time::Duration;

use world_id_flamingo::{
    release_manifest::Pipeline, EngineProviderMetadata, ReleaseManifest,
};

use super::FlamingoError;

/// The largest response slot count `WalletKit` accepts before sending biometrics.
///
/// A response reveals at most `log2(count)` bits about the Engine's run time; WIP-201 §3.5.4
/// recommends Authenticators accept at most 8 slots.
pub const MAX_RESPONSE_SLOTS: usize = 8;

/// One Engine configuration a Relying Party accepts.
///
/// The RP offers these tuples in order of preference. `WalletKit` runs the first one whose release
/// manifest the trusted Engine Provider signed and the assigned enclave attests.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FlamingoEngineConfiguration {
    /// `SHA-256` of the release manifest's JWS Payload, 32 bytes.
    pub release_hash: Vec<u8>,
    /// Pipeline identifier defined by the release manifest, nonzero.
    pub pipeline_id: u16,
    /// Matching strictness level defined by the release manifest.
    pub match_strictness: u8,
}

/// The release manifests of one Engine Provider that `WalletKit` trusts.
///
/// Built from the provider's metadata file (`<iss>/.well-known/world-id-engine.json`). The host
/// decides which provider to trust and how to obtain its metadata, for example by fetching it from
/// the pinned `iss` or bundling it with the app. Only listed manifests that name `iss` and whose
/// signature verifies under an `active` release key of the same metadata are kept. Removing a
/// manifest or retiring or revoking its key takes effect with the next metadata the host supplies.
#[derive(Debug, uniffi::Object)]
pub struct FlamingoEngineProvider {
    iss: String,
    manifests: Vec<ReleaseManifest>,
}

#[uniffi::export]
impl FlamingoEngineProvider {
    /// Parses the metadata file of the Engine Provider `iss`, the `https` URL it was fetched for,
    /// and verifies its listed release manifests.
    ///
    /// # Errors
    ///
    /// Returns [`FlamingoError::Configuration`] if the metadata is not a version 1 metadata file,
    /// or if none of its listed manifests names `iss` and verifies under one of its active release
    /// keys.
    #[uniffi::constructor]
    pub fn from_metadata(
        iss: &str,
        metadata_json: &[u8],
    ) -> Result<Self, FlamingoError> {
        let metadata =
            EngineProviderMetadata::parse(metadata_json).map_err(|error| {
                FlamingoError::Configuration(format!(
                    "Engine Provider metadata: {error}"
                ))
            })?;
        let manifests = metadata.verified_manifests(iss);
        if manifests.is_empty() {
            return Err(FlamingoError::Configuration(format!(
                "Engine Provider {iss} has no release manifest that verifies under an active key"
            )));
        }
        Ok(Self {
            iss: iss.to_string(),
            manifests,
        })
    }

    /// The Engine Provider's issuer URL.
    #[must_use]
    pub fn iss(&self) -> String {
        self.iss.clone()
    }
}

impl FlamingoEngineProvider {
    /// Bounds an exchange using the latest response slot among trusted, eligible offers.
    /// The client fixes its timeout when connecting, before the host assigns a release.
    pub(super) fn request_timeout(
        &self,
        offer: &[EngineConfiguration],
        pipeline_inputs: usize,
    ) -> Duration {
        let latest_slot = offer
            .iter()
            .filter_map(|configuration| {
                self.eligible_pipeline(configuration, pipeline_inputs)
                    .and_then(|pipeline| pipeline.response_slots.last())
            })
            .max()
            .unwrap_or_default();
        // Cover the host's five-second margin plus client-to-host transport.
        Duration::from_millis(latest_slot.saturating_add(10_000).max(60_000))
    }

    /// Chooses the first offered configuration of `attested_release` this provider signed.
    ///
    /// A configuration qualifies when it names `attested_release`, a verified release manifest has
    /// that `release_hash`, and the manifest defines its `pipeline_id` and `match_strictness`. The
    /// pipeline must take `pipeline_inputs` inputs and have at most [`MAX_RESPONSE_SLOTS`] response
    /// slots.
    ///
    /// # Errors
    ///
    /// Returns [`FlamingoError::NoSupportedEngine`] if no offered configuration qualifies.
    pub(super) fn select(
        &self,
        offer: &[EngineConfiguration],
        pipeline_inputs: usize,
        attested_release: [u8; 32],
    ) -> Result<EngineConfiguration, FlamingoError> {
        offer
            .iter()
            .find(|configuration| {
                configuration.release_hash == attested_release
                    && self
                        .eligible_pipeline(configuration, pipeline_inputs)
                        .is_some()
            })
            .copied()
            .ok_or(FlamingoError::NoSupportedEngine)
    }

    fn eligible_pipeline(
        &self,
        configuration: &EngineConfiguration,
        pipeline_inputs: usize,
    ) -> Option<&Pipeline> {
        let manifest = self
            .manifests
            .iter()
            .find(|manifest| manifest.release_hash() == configuration.release_hash)?;
        let pipeline = manifest.pipeline(configuration.pipeline_id)?;
        (manifest.has_match_strictness(configuration.match_strictness)
            && pipeline.inputs.len() == pipeline_inputs
            && pipeline.response_slots.0.len() <= MAX_RESPONSE_SLOTS)
            .then_some(pipeline)
    }
}

/// A parsed [`FlamingoEngineConfiguration`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineConfiguration {
    pub release_hash: [u8; 32],
    pub pipeline_id: u16,
    pub match_strictness: u8,
}

impl TryFrom<&FlamingoEngineConfiguration> for EngineConfiguration {
    type Error = FlamingoError;

    fn try_from(value: &FlamingoEngineConfiguration) -> Result<Self, Self::Error> {
        let release_hash = <[u8; 32]>::try_from(value.release_hash.as_slice())
            .map_err(|_| {
                FlamingoError::invalid_shape("release_hash", "must be 32 bytes")
            })?;
        if value.pipeline_id == 0 {
            return Err(FlamingoError::invalid_shape(
                "pipeline_id",
                "must be nonzero",
            ));
        }
        Ok(Self {
            release_hash,
            pipeline_id: value.pipeline_id,
            match_strictness: value.match_strictness,
        })
    }
}

impl From<EngineConfiguration> for FlamingoEngineConfiguration {
    fn from(value: EngineConfiguration) -> Self {
        Self {
            release_hash: value.release_hash.to_vec(),
            pipeline_id: value.pipeline_id,
            match_strictness: value.match_strictness,
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
    use serde_json::json;
    use sha2::{Digest as _, Sha256};

    use super::{
        EngineConfiguration, FlamingoEngineProvider, FlamingoError, MAX_RESPONSE_SLOTS,
    };

    pub const ISS: &str = "https://engines.example.com";
    pub const ENGINE_HASH: [u8; 48] = [0x11; 48];
    const OTHER_ENGINE_HASH: [u8; 48] = [0x22; 48];

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7; 32].into()).unwrap()
    }

    pub fn jwk(kid: &str, status: &str) -> serde_json::Value {
        let point = signing_key().verifying_key().to_encoded_point(false);
        json!({
            "jwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
                "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
                "kid": kid,
            },
            "status": status,
        })
    }

    /// A manifest of [`ISS`] for `engine_hash` with pipeline 1, which takes one input, and
    /// strictness levels 1 and 2, signed as `kid`, and its `release_hash`.
    pub fn manifest(
        engine_hash: [u8; 48],
        slots: usize,
        kid: &str,
    ) -> (String, [u8; 32]) {
        manifest_with_last_slot(ISS, engine_hash, slots, kid, 800)
    }

    pub fn manifest_with_last_slot(
        iss: &str,
        engine_hash: [u8; 48],
        slots: usize,
        kid: &str,
        last_slot: u64,
    ) -> (String, [u8; 32]) {
        let header =
            json!({ "alg": "ES256", "kid": kid, "typ": "world-id-engine-manifest" });
        let payload = json!({
            "iss": iss,
            "engine_hash": hex::encode(engine_hash),
            "version": 1,
            "match_strictness_levels": [1, 2],
            "pipelines": [{
                "pipeline_id": 1,
                "inputs": [{ "role": "live_frame", "media_types": ["image/jpeg"] }],
                "response_slots": (1..=slots)
                    .map(|slot| last_slot * u64::try_from(slot).unwrap() / u64::try_from(slots).unwrap())
                    .collect::<Vec<_>>(),
            }],
        })
        .to_string();
        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(&payload)
        );
        let signature: Signature = signing_key().sign(signing_input.as_bytes());
        let compact = format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        );
        (compact, Sha256::digest(payload).into())
    }

    pub fn metadata(manifests: &[&str], keys: &[serde_json::Value]) -> Vec<u8> {
        json!({
            "version": 1,
            "release_keys": keys,
            "manifests": manifests,
        })
        .to_string()
        .into_bytes()
    }

    /// A provider with one verified manifest for [`ENGINE_HASH`], and its `release_hash`.
    pub fn provider() -> (FlamingoEngineProvider, [u8; 32]) {
        let (manifest, release_hash) = manifest(ENGINE_HASH, 4, "release-1");
        let provider = FlamingoEngineProvider::from_metadata(
            ISS,
            &metadata(&[&manifest], &[jwk("release-1", "active")]),
        )
        .unwrap();
        (provider, release_hash)
    }

    fn provider_of(manifests: &[&str]) -> FlamingoEngineProvider {
        FlamingoEngineProvider::from_metadata(
            ISS,
            &metadata(manifests, &[jwk("release-1", "active")]),
        )
        .unwrap()
    }

    const fn configuration(
        release_hash: [u8; 32],
        match_strictness: u8,
    ) -> EngineConfiguration {
        EngineConfiguration {
            release_hash,
            pipeline_id: 1,
            match_strictness,
        }
    }

    #[test]
    fn selects_the_first_offered_configuration_of_the_attested_release() {
        let (manifest_a, release_a) = manifest(ENGINE_HASH, 4, "release-1");
        let (manifest_b, release_b) = manifest(OTHER_ENGINE_HASH, 4, "release-1");
        let provider = provider_of(&[&manifest_a, &manifest_b]);
        let offer = [
            configuration(release_a, 1),
            configuration(release_b, 1),
            configuration(release_a, 2),
        ];

        assert_eq!(provider.select(&offer, 1, release_a).unwrap(), offer[0]);
        assert_eq!(provider.select(&offer, 1, release_b).unwrap(), offer[1]);
        assert!(matches!(
            provider.select(&offer, 1, [0x33; 32]),
            Err(FlamingoError::NoSupportedEngine)
        ));
    }

    #[test]
    fn distinguishes_releases_of_the_same_engine() {
        let (a, release_a) = manifest(ENGINE_HASH, 4, "release-1");
        let (b, release_b) = manifest(ENGINE_HASH, 2, "release-1");
        let provider = provider_of(&[&a, &b]);
        assert_ne!(release_a, release_b);
        let offer = [configuration(release_a, 1), configuration(release_b, 2)];
        assert_eq!(provider.select(&offer, 1, release_b).unwrap(), offer[1]);
        assert!(provider.select(&offer[..1], 1, release_b).is_err());
    }

    #[test]
    fn deadline_covers_trusted_offered_slots_and_transport() {
        let (a, release_a) = manifest(ENGINE_HASH, 4, "release-1");
        let (b, release_b) =
            manifest_with_last_slot(ISS, ENGINE_HASH, 4, "release-1", 120_000);
        let (c, release_c) =
            manifest_with_last_slot(ISS, ENGINE_HASH, 9, "release-1", 240_000);
        let provider = provider_of(&[&a, &b, &c]);
        assert_eq!(
            provider.request_timeout(&[configuration(release_a, 1)], 1),
            std::time::Duration::from_secs(60)
        );
        assert_eq!(
            provider.request_timeout(
                &[configuration(release_a, 1), configuration(release_b, 1)],
                1
            ),
            std::time::Duration::from_secs(130)
        );
        for (invalid, pipeline_inputs) in [
            (configuration(release_c, 1), 1),
            (configuration(release_b, 3), 1),
            (configuration([0xff; 32], 1), 1),
            (configuration(release_b, 1), 2),
        ] {
            assert_eq!(
                provider.request_timeout(&[invalid], pipeline_inputs),
                std::time::Duration::from_secs(60)
            );
        }
    }

    #[test]
    fn skips_configurations_the_manifest_does_not_define() {
        let (provider, release_hash) = provider();
        for (offered, pipeline_inputs) in [
            (configuration([0x33; 32], 1), 1),
            (configuration(release_hash, 3), 1),
            (
                EngineConfiguration {
                    pipeline_id: 2,
                    ..configuration(release_hash, 1)
                },
                1,
            ),
            (configuration(release_hash, 1), 2),
        ] {
            assert!(matches!(
                provider.select(&[offered], pipeline_inputs, release_hash),
                Err(FlamingoError::NoSupportedEngine)
            ));
        }
    }

    #[test]
    fn refuses_a_pipeline_with_more_response_slots_than_accepted() {
        for (slots, accepted) in
            [(MAX_RESPONSE_SLOTS, true), (MAX_RESPONSE_SLOTS + 1, false)]
        {
            let (manifest, release_hash) = manifest(ENGINE_HASH, slots, "release-1");
            let provider = provider_of(&[&manifest]);
            let selected =
                provider.select(&[configuration(release_hash, 1)], 1, release_hash);
            assert_eq!(selected.is_ok(), accepted, "{slots} slots");
        }
    }

    #[test]
    fn keeps_only_listed_manifests_of_the_issuer_signed_by_an_active_key() {
        let (active, release_active) = manifest(ENGINE_HASH, 4, "release-1");
        let (_, release_removed) = manifest(OTHER_ENGINE_HASH, 4, "release-1");
        let (retired_key, release_retired_key) =
            manifest(OTHER_ENGINE_HASH, 2, "release-0");
        let (revoked_key, release_revoked_key) =
            manifest(OTHER_ENGINE_HASH, 3, "release-revoked");
        let (other_issuer, release_other_issuer) = manifest_with_last_slot(
            "https://other.example.com",
            OTHER_ENGINE_HASH,
            4,
            "release-1",
            800,
        );
        let provider = FlamingoEngineProvider::from_metadata(
            ISS,
            &metadata(
                &[&active, &retired_key, &revoked_key, &other_issuer],
                &[
                    jwk("release-1", "active"),
                    jwk("release-0", "retired"),
                    jwk("release-revoked", "revoked"),
                ],
            ),
        )
        .unwrap();
        assert_eq!(provider.iss(), ISS);

        assert!(provider
            .select(&[configuration(release_active, 1)], 1, release_active)
            .is_ok());
        for release_hash in [
            release_removed,
            release_retired_key,
            release_revoked_key,
            release_other_issuer,
        ] {
            assert!(matches!(
                provider.select(&[configuration(release_hash, 1)], 1, release_hash),
                Err(FlamingoError::NoSupportedEngine)
            ));
        }
    }

    #[test]
    fn rejects_metadata_without_a_verified_manifest_of_the_issuer() {
        let (manifest, _) = manifest(ENGINE_HASH, 4, "release-1");
        for (iss, metadata) in [
            (ISS, b"not json".to_vec()),
            (ISS, metadata(&[&manifest], &[])),
            (ISS, metadata(&[], &[jwk("release-1", "active")])),
            (ISS, metadata(&[&manifest], &[jwk("release-2", "active")])),
            (
                "https://other.example.com",
                metadata(&[&manifest], &[jwk("release-1", "active")]),
            ),
        ] {
            assert!(matches!(
                FlamingoEngineProvider::from_metadata(iss, &metadata),
                Err(FlamingoError::Configuration(_))
            ));
        }
    }
}
