//! Engine Provider trust and Engine selection (WIP-201 §3.5.2, §3.5.3 and §3.5.4).

use world_id_flamingo::{EngineMetadata, ReleaseManifest};

use super::FlamingoError;

/// The largest response slot count `WalletKit` accepts before sending biometrics.
///
/// A response reveals at most `log2(count)` bits about the Engine's run time; WIP-201 §3.5.4
/// recommends Authenticators accept at most 8 slots.
pub const MAX_RESPONSE_SLOTS: u32 = 8;

/// One Engine configuration a Relying Party accepts.
///
/// The RP offers these tuples in order of preference. `WalletKit` runs the first one whose release
/// manifest the trusted Engine Provider signed and the Verifier has loaded.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FlamingoEngineConfiguration {
    /// `SHA-256` of the release manifest's JWS Payload, 32 bytes.
    pub release_hash: Vec<u8>,
    /// Engine-defined pipeline, nonzero.
    pub pipeline: u16,
    /// Matching strictness level defined by the release manifest.
    pub match_strictness: u8,
}

/// The release manifests of one Engine Provider that `WalletKit` trusts.
///
/// Built from the provider's metadata file (`/.well-known/world-id-engine.json`). The host decides
/// which provider to trust and how to obtain its metadata, for example by fetching it from a
/// pinned domain or bundling it with the app. Only manifests marked `active` whose signature
/// verifies under an `active` release key of the same metadata are kept, so marking a key or a
/// manifest `revoked` takes effect with the next metadata the host supplies.
#[derive(Debug, uniffi::Object)]
pub struct FlamingoEngineProvider {
    provider_id: String,
    manifests: Vec<ReleaseManifest>,
}

#[uniffi::export]
impl FlamingoEngineProvider {
    /// Parses an Engine Provider metadata file and verifies its active release manifests.
    ///
    /// # Errors
    ///
    /// Returns [`FlamingoError::Configuration`] if the metadata is not a version 1 metadata file,
    /// or if none of its active manifests verifies under one of its active release keys.
    #[uniffi::constructor]
    pub fn from_metadata(metadata_json: &[u8]) -> Result<Self, FlamingoError> {
        let metadata = EngineMetadata::parse(metadata_json).map_err(|error| {
            FlamingoError::Configuration(format!("Engine Provider metadata: {error}"))
        })?;
        let manifests = metadata.active_manifests();
        if manifests.is_empty() {
            return Err(FlamingoError::Configuration(format!(
                "Engine Provider {} has no active release manifest that verifies",
                metadata.provider_id
            )));
        }
        Ok(Self {
            provider_id: metadata.provider_id,
            manifests,
        })
    }

    /// The provider's stable identifier.
    #[must_use]
    pub fn provider_id(&self) -> String {
        self.provider_id.clone()
    }
}

impl FlamingoEngineProvider {
    /// Chooses the first offered configuration this provider signed and the Verifier loaded.
    ///
    /// A configuration qualifies when a verified release manifest has its `release_hash`, defines
    /// its `pipeline` and `match_strictness`, has at most [`MAX_RESPONSE_SLOTS`] response slots for
    /// that pipeline, and names an Engine bundle among `loaded_engines`. The Verifier's list is not
    /// attested: a wrong list only makes the request fail.
    ///
    /// # Errors
    ///
    /// Returns [`FlamingoError::NoSupportedEngine`] if no offered configuration qualifies.
    pub(super) fn select(
        &self,
        offer: &[EngineConfiguration],
        loaded_engines: &[[u8; 32]],
    ) -> Result<SelectedEngine, FlamingoError> {
        offer
            .iter()
            .find_map(|configuration| {
                let manifest = self.manifests.iter().find(|manifest| {
                    manifest.release_hash() == configuration.release_hash
                })?;
                let pipeline = manifest.pipeline(configuration.pipeline)?;
                let engine_hash = manifest.payload().engine_hash()?;
                (manifest.defines_strictness(configuration.match_strictness)
                    && pipeline.response_slots.count <= MAX_RESPONSE_SLOTS
                    && loaded_engines.contains(&engine_hash))
                .then_some(SelectedEngine {
                    configuration: *configuration,
                    engine_hash,
                })
            })
            .ok_or(FlamingoError::NoSupportedEngine)
    }
}

/// A parsed [`FlamingoEngineConfiguration`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineConfiguration {
    pub release_hash: [u8; 32],
    pub pipeline: u16,
    pub match_strictness: u8,
}

impl TryFrom<&FlamingoEngineConfiguration> for EngineConfiguration {
    type Error = FlamingoError;

    fn try_from(value: &FlamingoEngineConfiguration) -> Result<Self, Self::Error> {
        let release_hash = <[u8; 32]>::try_from(value.release_hash.as_slice())
            .map_err(|_| {
                FlamingoError::invalid_shape("release_hash", "must be 32 bytes")
            })?;
        if value.pipeline == 0 {
            return Err(FlamingoError::invalid_shape("pipeline", "must be nonzero"));
        }
        Ok(Self {
            release_hash,
            pipeline: value.pipeline,
            match_strictness: value.match_strictness,
        })
    }
}

impl From<EngineConfiguration> for FlamingoEngineConfiguration {
    fn from(value: EngineConfiguration) -> Self {
        Self {
            release_hash: value.release_hash.to_vec(),
            pipeline: value.pipeline,
            match_strictness: value.match_strictness,
        }
    }
}

/// The configuration chosen for one session, with the Engine bundle that runs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectedEngine {
    pub configuration: EngineConfiguration,
    // TODO: Select by `release_hash` alone once the Verifier names loaded releases and requests
    // carry `release_hash` (https://github.com/worldcoin/flamingo/pull/139).
    pub engine_hash: [u8; 32],
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

    pub const ENGINE_HASH: [u8; 32] = [0x11; 32];
    const OTHER_ENGINE_HASH: [u8; 32] = [0x22; 32];

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7; 32].into()).unwrap()
    }

    fn jwk(kid: &str, status: &str) -> serde_json::Value {
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

    /// A manifest for `engine_hash` with pipeline 1 and strictness levels 1 and 2, signed as
    /// `kid`, and its `release_hash`.
    pub fn manifest(
        engine_hash: [u8; 32],
        slots: u32,
        kid: &str,
    ) -> (String, [u8; 32]) {
        let header =
            json!({ "alg": "ES256", "kid": kid, "typ": "world-id-engine-manifest" });
        let payload = json!({
            "engine_hash": hex::encode(engine_hash),
            "version": "test",
            "pipelines": [{
                "pipeline": 1,
                "description": "credential image, live capture, challenge",
                "response_slots": { "min": 100, "max": 800, "count": slots },
                "max_request_bytes": 8_000_000,
            }],
            "match_strictness_levels": [
                { "match_strictness": 1, "description": "low" },
                { "match_strictness": 2, "description": "high" },
            ],
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

    pub fn metadata(manifests: &[(&str, &str)], keys: &[serde_json::Value]) -> Vec<u8> {
        json!({
            "version": 1,
            "provider_id": "test-provider",
            "release_keys": keys,
            "manifests": manifests
                .iter()
                .map(|(manifest, status)| json!({ "manifest": manifest, "status": status }))
                .collect::<Vec<_>>(),
        })
        .to_string()
        .into_bytes()
    }

    /// A provider with one active manifest for [`ENGINE_HASH`], and its `release_hash`.
    pub fn provider() -> (FlamingoEngineProvider, [u8; 32]) {
        let (manifest, release_hash) = manifest(ENGINE_HASH, 4, "release-1");
        let provider = FlamingoEngineProvider::from_metadata(&metadata(
            &[(&manifest, "active")],
            &[jwk("release-1", "active")],
        ))
        .unwrap();
        (provider, release_hash)
    }

    const fn configuration(
        release_hash: [u8; 32],
        match_strictness: u8,
    ) -> EngineConfiguration {
        EngineConfiguration {
            release_hash,
            pipeline: 1,
            match_strictness,
        }
    }

    #[test]
    fn selects_the_first_offered_configuration_the_verifier_loaded() {
        let (manifest_a, release_a) = manifest(ENGINE_HASH, 4, "release-1");
        let (manifest_b, release_b) = manifest(OTHER_ENGINE_HASH, 4, "release-1");
        let provider = FlamingoEngineProvider::from_metadata(&metadata(
            &[(&manifest_a, "active"), (&manifest_b, "active")],
            &[jwk("release-1", "active")],
        ))
        .unwrap();
        let offer = [configuration(release_a, 2), configuration(release_b, 1)];

        let both = provider
            .select(&offer, &[OTHER_ENGINE_HASH, ENGINE_HASH])
            .unwrap();
        assert_eq!(both.configuration, offer[0]);
        assert_eq!(both.engine_hash, ENGINE_HASH);

        let fallback = provider.select(&offer, &[OTHER_ENGINE_HASH]).unwrap();
        assert_eq!(fallback.configuration, offer[1]);
        assert_eq!(fallback.engine_hash, OTHER_ENGINE_HASH);
    }

    #[test]
    fn skips_configurations_the_manifest_does_not_define() {
        let (provider, release_hash) = provider();
        for offered in [
            configuration([0x33; 32], 1),
            configuration(release_hash, 3),
            EngineConfiguration {
                pipeline: 2,
                ..configuration(release_hash, 1)
            },
        ] {
            assert!(matches!(
                provider.select(&[offered], &[ENGINE_HASH]),
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
            let provider = FlamingoEngineProvider::from_metadata(&metadata(
                &[(&manifest, "active")],
                &[jwk("release-1", "active")],
            ))
            .unwrap();
            let selected =
                provider.select(&[configuration(release_hash, 1)], &[ENGINE_HASH]);
            assert_eq!(selected.is_ok(), accepted, "{slots} slots");
        }
    }

    #[test]
    fn keeps_only_active_manifests_signed_by_an_active_key() {
        let (active, release_active) = manifest(ENGINE_HASH, 4, "release-1");
        let (revoked, release_revoked) = manifest(OTHER_ENGINE_HASH, 4, "release-1");
        let (retired_key, release_retired_key) =
            manifest(OTHER_ENGINE_HASH, 2, "release-0");
        let provider = FlamingoEngineProvider::from_metadata(&metadata(
            &[
                (&active, "active"),
                (&revoked, "revoked"),
                (&retired_key, "active"),
            ],
            &[jwk("release-1", "active"), jwk("release-0", "retired")],
        ))
        .unwrap();
        let loaded = [ENGINE_HASH, OTHER_ENGINE_HASH];

        assert!(provider
            .select(&[configuration(release_active, 1)], &loaded)
            .is_ok());
        for release_hash in [release_revoked, release_retired_key] {
            assert!(matches!(
                provider.select(&[configuration(release_hash, 1)], &loaded),
                Err(FlamingoError::NoSupportedEngine)
            ));
        }
    }

    #[test]
    fn rejects_metadata_without_a_verified_manifest() {
        let (manifest, _) = manifest(ENGINE_HASH, 4, "release-1");
        for metadata in [
            b"not json".to_vec(),
            metadata(&[(&manifest, "active")], &[]),
            metadata(&[(&manifest, "revoked")], &[jwk("release-1", "active")]),
            metadata(&[(&manifest, "active")], &[jwk("release-2", "active")]),
        ] {
            assert!(matches!(
                FlamingoEngineProvider::from_metadata(&metadata),
                Err(FlamingoError::Configuration(_))
            ));
        }
    }
}
