//! Artifact sources & traits for loading/caching & managing ZK Artifacts

use world_id_core::artifacts::ZkArtifactSource;

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
