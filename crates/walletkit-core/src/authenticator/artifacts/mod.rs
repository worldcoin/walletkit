//! Artifact sources & traits for loading/caching & managing ZK Artifacts

use world_id_core::artifacts::ZkArtifactSource;

/// Frozen R1CS hash of the WIP-103 ownership circuit, hex-encoded.
///
/// Changing this is a protocol change — proofs come from shipped binaries that
/// cannot be recalled, so the verifier must accept the new hash before any
/// client producing it ships.
pub const OWNERSHIP_CIRCUIT_R1CS_HASH: &str =
    "f2982dc89f49f4830ffa7fb535734afe7997db017cf8ef6f28cd3ef7ce6a0312";

/// A blanket implementation interface that allows the ZK Artifact source implementations to be
/// used by methods exposed to walletkit consumers.
#[uniffi::export]
pub trait WalletKitZkArtifactSource: ZkArtifactSource + Send {}
impl<T> WalletKitZkArtifactSource for T where T: ZkArtifactSource + Send {}

#[cfg(all(not(target_arch = "wasm32"), feature = "embed-zkeys"))]
pub mod caching;

/// Sources backed by ZK artifacts embedded in the binary.
#[cfg(feature = "embed-zkeys")]
pub mod embedded;

#[cfg(all(test, feature = "embed-zkeys", not(target_arch = "wasm32")))]
mod tests {
    use super::{
        embedded::EmbeddedZkArtifacts, ZkArtifactSource, OWNERSHIP_CIRCUIT_R1CS_HASH,
    };

    const PROTOCOL_CHANGE_HINT: &str = "\
The WIP-103 ownership circuit changed. Every proof from every shipped client \
will be rejected by a verifier still on the old circuit, and shipped clients \
cannot be rolled back. Do not update the constant to make this pass: confirm \
the Ownership Proof Verifier Service accepts the new hash first, then update \
OWNERSHIP_CIRCUIT_R1CS_HASH in the same change.";

    #[test]
    fn ownership_verifier_matches_frozen_circuit_hash() {
        let verifier = EmbeddedZkArtifacts::new()
            .ownership_verifier()
            .expect("embedded ownership verifier should load");
        let scheme = verifier
            .whir_for_witness
            .as_ref()
            .expect("verifier should carry a WHIR scheme");

        assert_eq!(
            hex::encode(scheme.r1cs_hash),
            OWNERSHIP_CIRCUIT_R1CS_HASH,
            "{PROTOCOL_CHANGE_HINT}"
        );
    }

    #[test]
    fn ownership_prover_and_verifier_share_a_circuit() {
        let artifacts = EmbeddedZkArtifacts::new();
        let prover = artifacts
            .ownership_prover()
            .expect("embedded ownership prover should load");
        let verifier = artifacts
            .ownership_verifier()
            .expect("embedded ownership verifier should load");
        let verifier_scheme = verifier
            .whir_for_witness
            .as_ref()
            .expect("verifier should carry a WHIR scheme");

        assert_eq!(
            prover.whir_for_witness.r1cs_hash, verifier_scheme.r1cs_hash,
            "embedded prover and verifier were built from different circuits; \
             proofs generated locally would fail local verification"
        );
    }
}
