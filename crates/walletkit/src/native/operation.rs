//! Cancellable execution of async domain operations.
//!
//! Async operations are blocking native functions. The SDKs call them on their bounded
//! workers, passing an [`Operation`] created beforehand so that the caller can cancel it
//! from another thread. The function drives the future on the shared runtime until it
//! completes or is cancelled. Cancellation drops the future at its next yield point; it
//! cannot interrupt synchronous work or undo committed effects.

use super::{
    error::{NativeError, Result},
    registry::NativeObject,
};
use futures_util::future::{AbortHandle, AbortRegistration, Abortable};
use std::{
    future::Future,
    sync::{Arc, Mutex, OnceLock},
};

static RUNTIME: OnceLock<std::result::Result<tokio::runtime::Runtime, String>> =
    OnceLock::new();

/// A cancellation token for one async call, held in the handle registry.
pub struct OperationState {
    cancel: AbortHandle,
    registration: Mutex<Option<AbortRegistration>>,
}

impl NativeObject for OperationState {}

impl OperationState {
    /// Creates a token that has not started.
    pub fn new() -> Self {
        let (cancel, registration) = AbortHandle::new_pair();
        Self {
            cancel,
            registration: Mutex::new(Some(registration)),
        }
    }

    /// Cancels the operation, before or during execution.
    pub fn cancel(&self) {
        self.cancel.abort();
    }
}

/// The operation argument of an async native function.
pub struct Operation(pub Arc<OperationState>);

impl Operation {
    /// Runs `future` to completion on the shared runtime, or until cancelled.
    ///
    /// Each operation runs once. Calls from a runtime thread, such as a host callback that
    /// re-enters `WalletKit`, fail with `ReentrantCall` instead of deadlocking.
    pub fn run<T>(&self, future: impl Future<Output = Result<T>>) -> Result<T> {
        let registration = self
            .0
            .registration
            .lock()
            .map_err(|_| NativeError::bridge("PoisonedOperation"))?
            .take()
            .ok_or_else(|| NativeError::bridge("OperationAlreadyStarted"))?;
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(NativeError::bridge("ReentrantCall"));
        }
        // Boxed so that large domain futures do not live on small host worker stacks.
        let future = Box::pin(Abortable::new(future, registration));
        runtime()?
            .block_on(future)
            .map_err(|_| NativeError::cancelled())?
    }
}

fn runtime() -> Result<&'static tokio::runtime::Runtime> {
    RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_name("walletkit-runtime")
                .enable_all()
                .build()
                .map_err(|error| error.to_string())
        })
        .as_ref()
        .map_err(|_| NativeError::bridge("RuntimeUnavailable"))
}
