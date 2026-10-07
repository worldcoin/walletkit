//! Host request-integrity providers, whose preparation completes asynchronously.
//!
//! `prepare` registers a completion handle and passes its ID to the host, which must
//! complete it exactly once from any thread. The matcher's deadline drops a pending
//! preparation; its handle is then released and a late completion is ignored.

use super::registry::{self, NativeObject};
use std::sync::{Arc, Mutex};
use tokio::sync::oneshot;
use walletkit_core::flamingo::{
    RequestDigestSigner, RequestIntegrityError, RequestIntegrityPlatform,
    RequestIntegrityProvider, RequestIntegritySession,
};

/// A host session: token, signature encoding, and the signer bound to the token's key.
pub type Prepared = Result<
    (
        String,
        RequestIntegrityPlatform,
        Arc<dyn RequestDigestSigner>,
    ),
    RequestIntegrityError,
>;

struct Completion(Mutex<Option<oneshot::Sender<Prepared>>>);

impl NativeObject for Completion {}

/// Completes the preparation identified by `id`. Unknown or expired IDs are ignored.
pub fn complete(id: u64, result: Prepared) {
    let Ok(completion) = registry::get::<Completion>(id) else {
        return;
    };
    registry::release_typed::<Completion>(id);
    let sender = completion
        .0
        .lock()
        .ok()
        .and_then(|mut sender| sender.take());
    if let Some(sender) = sender {
        let _ = sender.send(result);
    }
}

/// A provider that starts host preparation with a completion ID.
pub struct HostProvider<F> {
    start: F,
}

impl<F> HostProvider<F>
where
    F: Fn(u64) -> Result<(), RequestIntegrityError> + Send + Sync,
{
    /// Wraps a function that hands a completion ID to the host.
    pub const fn new(start: F) -> Self {
        Self { start }
    }
}

struct Pending(u64);

impl Drop for Pending {
    fn drop(&mut self) {
        registry::release_typed::<Completion>(self.0);
    }
}

#[async_trait::async_trait]
impl<F> RequestIntegrityProvider for HostProvider<F>
where
    F: Fn(u64) -> Result<(), RequestIntegrityError> + Send + Sync,
{
    async fn prepare(&self) -> Result<RequestIntegritySession, RequestIntegrityError> {
        let (sender, receiver) = oneshot::channel();
        let id = registry::insert(Arc::new(Completion(Mutex::new(Some(sender)))))
            .map_err(|_| RequestIntegrityError::Unavailable)?;
        let _pending = Pending(id);
        (self.start)(id)?;
        let (token, platform, signer) = receiver
            .await
            .map_err(|_| RequestIntegrityError::CallbackFailed)??;
        Ok(RequestIntegritySession {
            token,
            platform,
            signer,
        })
    }
}
