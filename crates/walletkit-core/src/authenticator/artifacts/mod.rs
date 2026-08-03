use world_id_core::artifacts::ZkArtifactSource;

/// A blanket implementation interface that allows the ZK Artifact source implementations to be
/// used by methods exposed to walletkit consumers.
#[uniffi::export]
pub trait WalletKitZkArtifactSource: ZkArtifactSource + Send {}
impl<T> WalletKitZkArtifactSource for T where T: ZkArtifactSource + Send {}

#[cfg(not(target_arch = "wasm32"))]
pub mod caching;
pub mod embedded;
