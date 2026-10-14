//! Registering a new authenticator through an existing Admin Authenticator, as defined in
//! [WIP-109](https://github.com/worldcoin/world-id-protocol/blob/main/docs/WIPs/wip-109.md).
//!
//! A **Requesting Authenticator** (the new one) drives a [`RegistrationRequester`]: it publishes
//! an encrypted request on the message-bridge and shows a [`PairingUri`], then the
//! [`PairingCode`] once the request was taken. An **Approving Authenticator** (an existing Admin
//! Authenticator) fetches the request with [`PendingRegistration::receive`] before code entry.
//! Authentication with the code yields an [`IncomingRegistration`] that still requires account
//! checks and explicit consent before [`CheckedRegistration::approve`] inserts the new
//! authenticator on-chain and answers with a sealed [`RegistrationResult`].
//!
//! The result may carry the account's credential vault as a [`PlaintextVault`], the only vault
//! format `WalletKit` shares or imports.
//!
//! The wire format and cryptography come from [`world_id_core::registration`].
//!
//! # Blocking key derivation
//!
//! [`RegistrationRequester::new`] and [`PendingRegistration::authenticate`] derive the transport
//! key from the pairing code with Argon2id (64 MiB, three passes, four lanes), synchronously. In
//! a browser this blocks the thread it runs on, so call them from a Web Worker rather than the
//! main thread.

mod approver;
mod bridge;
mod deadline;
mod requester;
mod vault;

pub use approver::{
    Approval, ApprovalOutcome, ApproverError, CheckedRegistration, Delivery,
    IncomingRegistration, PendingRegistration, RegistrationPlan, UserVerification,
    DEFAULT_RESPONSE_DEADLINE, MIN_TRACKING_TIME,
};
pub use bridge::{
    BridgeClient, BridgeError, DeliveryOutcome, PublishOutcome, ResponseState,
};
pub use requester::{
    RegistrationRequester, RequestedClass, RequesterError, RequesterStatus,
};
pub use vault::{PlaintextVault, UnsupportedVaultFormat, PLAINTEXT_VAULT_FORMAT};
pub use world_id_core::registration::{
    AuthenticatorName, BridgeDomain, EncryptedPayload, KnownAuthenticator, PairingCode,
    PairingUri, RegistrationErrorData, RegistrationErrorReason, RegistrationRequest,
    RegistrationResult, RequestId, Vault, MAX_VAULT_SIZE,
};

#[cfg(test)]
mod fixtures;

#[cfg(test)]
mod tests {
    use std::{future::Future, sync::Arc};

    use world_id_core::{
        artifacts::ZkArtifactSource, primitives::Config, Authenticator,
    };

    use super::*;

    fn assert_send_static<F: Future + Send + 'static>(_future: F) {}

    /// `UniFFI` exports async functions only if their futures are `Send`, so every flow future
    /// must be `Send + 'static` when built from owned values. The closures are never called:
    /// type-checking them is the test.
    #[test]
    fn flow_futures_are_send_and_static() {
        let _ = |mut requester: RegistrationRequester| {
            assert_send_static(async move { requester.publish().await });
        };
        let _ = |mut requester: RegistrationRequester| {
            assert_send_static(async move { requester.poll().await });
        };
        let _ = |requester: RegistrationRequester,
                 seed: Vec<u8>,
                 result: RegistrationResult,
                 config: Config,
                 zk_artifact_source: Arc<dyn ZkArtifactSource>| {
            assert_send_static(async move {
                requester
                    .verify(&seed, &result, config, zk_artifact_source)
                    .await
            });
        };
        let _ = |uri: PairingUri, allowed_bridges: Vec<BridgeClient>| {
            assert_send_static(async move {
                PendingRegistration::receive(&uri, &allowed_bridges).await
            });
        };
        let _ = |mut pending: PendingRegistration, code: PairingCode| {
            assert_send_static(async move { pending.authenticate(&code).await });
        };
        let _ = |incoming: IncomingRegistration, approver: Arc<Authenticator>| {
            assert_send_static(async move { incoming.check(&approver).await });
        };
        let _ = |incoming: IncomingRegistration| {
            assert_send_static(incoming.reject_name());
        };
        let _ = |checked: CheckedRegistration| {
            assert_send_static(checked.reject());
        };
        let _ = |checked: CheckedRegistration| {
            assert_send_static(checked.user_verification_failed());
        };
        let _ = |checked: CheckedRegistration,
                 approver: Arc<Authenticator>,
                 approval: Approval| {
            assert_send_static(async move {
                checked
                    .approve(
                        &approver,
                        approval,
                        UserVerification::platform_check_succeeded(),
                    )
                    .await
            });
        };
    }
}
