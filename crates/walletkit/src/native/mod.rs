//! Typed native bindings for the maintained Kotlin and Swift SDKs.
//!
//! Every SDK method has one plain Rust function in [`ops`]. The `jni` feature exports it
//! directly to Kotlin through `#[jni_export]`; the `c` feature wraps it in a C function
//! declared in the cbindgen-generated `walletkit_coreFFI.h` for Swift and other C hosts.
//!
//! - Resources are process-local handles in [`registry`], never pointers.
//! - Scalars, strings, bytes, and handles cross as JNI or C primitives; records, lists,
//!   maps, and errors use the binary encoding in [`codec`] and [`values`].
//! - Async domain operations are blocking functions that the SDKs run on bounded workers,
//!   cancellable through an [`operation::Operation`].

#[cfg(feature = "c")]
pub mod c;
pub mod codec;
pub mod error;
pub mod integrity;
#[cfg(feature = "jni")]
pub mod jni;
pub mod operation;
pub mod ops;
pub mod registry;
pub mod values;
