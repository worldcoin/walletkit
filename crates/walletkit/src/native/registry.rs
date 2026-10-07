//! Process-local handles. IDs are monotonic and never reused; zero is never valid.
//!
//! Removing a handle never invalidates an `Arc` that a running call already resolved.

use super::error::{NativeError, Result};
use std::{
    any::Any,
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, MutexGuard, OnceLock,
    },
};

/// A Rust object that hosts reference through a handle.
pub trait NativeObject: Send + Sync + 'static {}

type Objects = HashMap<u64, Box<dyn Any + Send + Sync>>;

static NEXT: AtomicU64 = AtomicU64::new(1);
static OBJECTS: OnceLock<Mutex<Objects>> = OnceLock::new();

fn objects() -> Result<MutexGuard<'static, Objects>> {
    OBJECTS
        .get_or_init(Mutex::default)
        .lock()
        .map_err(|_| NativeError::bridge("PoisonedRegistry"))
}

/// Registers `object` and returns its new handle.
pub fn insert<T: NativeObject + ?Sized>(object: Arc<T>) -> Result<u64> {
    let id = NEXT
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
        .map_err(|_| NativeError::bridge("HandleExhausted"))?;
    objects()?.insert(id, Box::new(object));
    Ok(id)
}

/// Resolves a handle to its object, failing for released handles and other types.
pub fn get<T: NativeObject + ?Sized>(id: u64) -> Result<Arc<T>> {
    objects()?
        .get(&id)
        .and_then(|object| object.downcast_ref::<Arc<T>>())
        .cloned()
        .ok_or_else(|| NativeError::bridge("InvalidHandle"))
}

/// Releases a handle of any type. Idempotent.
pub fn release(id: u64) {
    let object = objects().ok().and_then(|mut objects| objects.remove(&id));
    // Host destructors may re-enter WalletKit; never run them under the registry lock.
    drop(object);
}

/// Releases `id` only if it holds a `T`, so a mistyped handle cannot free another object.
pub fn release_typed<T: NativeObject + ?Sized>(id: u64) {
    let object = objects().ok().and_then(|mut objects| {
        if objects.get(&id).is_some_and(|object| object.is::<Arc<T>>()) {
            objects.remove(&id)
        } else {
            None
        }
    });
    drop(object);
}
