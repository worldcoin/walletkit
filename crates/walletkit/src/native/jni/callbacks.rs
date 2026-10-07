//! Kotlin callback interfaces, called directly through method IDs from `JNI_OnLoad`.
//!
//! Rust-owned threads attach once, as daemons, and stay attached, so a callback costs one
//! JNI call rather than an attach and detach. Each callback runs in its own local frame.
//! Host exceptions never cross with their message: a `StorageException` keeps its
//! variant through `NativeBridge.callbackError`, and anything else becomes a fixed code.

use super::{classes, non_null, Classes, Failure, FromJni};
use crate::native::{codec, integrity, values::Ordinal};
use jni::{
    objects::{GlobalRef, JByteArray, JMethodID, JObject},
    signature::{Primitive, ReturnType},
    sys::{jobject, jvalue},
    JNIEnv,
};
use std::sync::Arc;
use walletkit_core::{
    flamingo::{
        RequestDigestSigner, RequestIntegrityError, RequestIntegrityPlatform,
        RequestIntegrityProvider,
    },
    logger::{LogLevel, Logger},
    storage::{
        ActivityChangedListener, AtomicBlobStore, DeviceKeystore, StorageError,
        StorageResult, VaultChangedListener,
    },
};
use zeroize::Zeroizing;

/// A Kotlin callback object, retained until Rust drops its last reference.
struct Java(GlobalRef);

impl Java {
    fn new(env: &mut JNIEnv, object: &JObject) -> Result<Self, Failure> {
        non_null(object)?;
        Ok(Self(env.new_global_ref(object)?))
    }
}

macro_rules! from_jni {
    ($($trait:ident => $adapter:ident),* $(,)?) => {$(
        struct $adapter(Java);

        impl<'local> FromJni<'local> for Arc<dyn $trait> {
            type Raw = JObject<'local>;
            fn from_jni(env: &mut JNIEnv<'local>, raw: Self::Raw) -> Result<Self, Failure> {
                Ok(Arc::new($adapter(Java::new(env, &raw)?)))
            }
        }
    )*};
}

from_jni! {
    DeviceKeystore => JavaKeystore,
    AtomicBlobStore => JavaBlobStore,
    Logger => JavaLogger,
    VaultChangedListener => JavaVaultListener,
    ActivityChangedListener => JavaActivityListener,
}

impl<'local> FromJni<'local> for Arc<dyn RequestIntegrityProvider> {
    type Raw = JObject<'local>;
    fn from_jni(env: &mut JNIEnv<'local>, raw: Self::Raw) -> Result<Self, Failure> {
        let provider = Java::new(env, &raw)?;
        Ok(Arc::new(integrity::HostProvider::new(move |completion| {
            prepare(&provider, completion)
        })))
    }
}

impl DeviceKeystore for JavaKeystore {
    fn seal(
        &self,
        associated_data: Vec<u8>,
        plaintext: Vec<u8>,
    ) -> StorageResult<Vec<u8>> {
        let plaintext = Zeroizing::new(plaintext);
        storage_call(|env, classes| {
            let associated_data = env.byte_array_from_slice(&associated_data)?;
            let input = env.byte_array_from_slice(&plaintext)?;
            let result = call_bytes(
                env,
                &self.0 .0,
                classes.keystore_seal,
                &[associated_data.as_raw(), input.as_raw()],
                false,
            );
            // JNI calls are not allowed while an exception is pending: set it aside to
            // zero the Java copy of the plaintext, then rethrow it.
            let pending = take_pending(env)?;
            let _ = env.set_byte_array_region(&input, 0, &vec![0; plaintext.len()]);
            if let Some(throwable) = pending {
                env.throw(throwable)?;
            }
            result
        })
        .and_then(required)
    }

    fn open_sealed(
        &self,
        associated_data: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> StorageResult<Vec<u8>> {
        storage_call(|env, classes| {
            let associated_data = env.byte_array_from_slice(&associated_data)?;
            let ciphertext = env.byte_array_from_slice(&ciphertext)?;
            call_bytes(
                env,
                &self.0 .0,
                classes.keystore_open_sealed,
                &[associated_data.as_raw(), ciphertext.as_raw()],
                true,
            )
        })
        .and_then(required)
    }
}

impl AtomicBlobStore for JavaBlobStore {
    fn read(&self, path: String) -> StorageResult<Option<Vec<u8>>> {
        storage_call(|env, classes| {
            let path = env.new_string(path)?;
            call_bytes(env, &self.0 .0, classes.blob_read, &[path.as_raw()], false)
        })
    }

    fn write_atomic(&self, path: String, bytes: Vec<u8>) -> StorageResult<()> {
        storage_call(|env, classes| {
            let path = env.new_string(path)?;
            let bytes = env.byte_array_from_slice(&bytes)?;
            call_void(
                env,
                &self.0 .0,
                classes.blob_write_atomic,
                &[path.as_raw(), bytes.as_raw()],
            )
        })
    }

    fn delete(&self, path: String) -> StorageResult<()> {
        storage_call(|env, classes| {
            let path = env.new_string(path)?;
            call_void(env, &self.0 .0, classes.blob_delete, &[path.as_raw()])
        })
    }
}

impl Logger for JavaLogger {
    fn log(&self, level: LogLevel, message: String) {
        notify("Logger", |env, classes| {
            let message = env.new_string(message)?;
            // SAFETY: the method ID was resolved for this signature in `JNI_OnLoad`.
            unsafe {
                env.call_static_method_unchecked(
                    &classes.bridge,
                    classes.log,
                    ReturnType::Primitive(Primitive::Void),
                    &[
                        jvalue {
                            l: self.0 .0.as_raw(),
                        },
                        jvalue {
                            i: level.ordinal().into(),
                        },
                        jvalue {
                            l: message.as_raw(),
                        },
                    ],
                )
            }?;
            Ok(())
        });
    }
}

impl VaultChangedListener for JavaVaultListener {
    fn on_vault_changed(&self) {
        notify("VaultChangedListener", |env, classes| {
            call_void(env, &self.0 .0, classes.vault_changed, &[])
        });
    }
}

impl ActivityChangedListener for JavaActivityListener {
    fn on_activity_changed(&self) {
        notify("ActivityChangedListener", |env, classes| {
            call_void(env, &self.0 .0, classes.activity_changed, &[])
        });
    }
}

/// Starts Kotlin `NativeBridge.prepareIntegrity`, which completes `completion` through
/// `integrityPrepared` or `integrityFailed` once the provider's coroutine finishes.
fn prepare(provider: &Java, completion: u64) -> Result<(), RequestIntegrityError> {
    attached(|env, classes| {
        // SAFETY: the method ID was resolved for this signature in `JNI_OnLoad`.
        unsafe {
            env.call_static_method_unchecked(
                &classes.bridge,
                classes.prepare_integrity,
                ReturnType::Primitive(Primitive::Void),
                &[
                    jvalue {
                        l: provider.0.as_raw(),
                    },
                    jvalue {
                        j: completion.cast_signed(),
                    },
                ],
            )
        }?;
        Ok(())
    })
    .map_err(|_| RequestIntegrityError::CallbackFailed)
}

struct JavaSigner(Java);

impl RequestDigestSigner for JavaSigner {
    fn sign_digest(
        &self,
        client_data_hash: Vec<u8>,
    ) -> Result<Vec<u8>, RequestIntegrityError> {
        attached(|env, classes| {
            let digest = env.byte_array_from_slice(&client_data_hash)?;
            call_bytes(
                env,
                &self.0 .0,
                classes.sign_digest,
                &[digest.as_raw()],
                false,
            )
        })
        .ok()
        .flatten()
        .ok_or(RequestIntegrityError::SigningFailed)
    }
}

/// Completes a pending integrity preparation with the provider's session. Invalid input
/// still completes it, with `InvalidSession`, so the matcher does not wait for its deadline.
#[walletkit_jni_macros::jni_export]
fn integrity_prepared(
    completion: u64,
    token: Option<String>,
    platform: u32,
    signer: Signer,
) {
    let platform = RequestIntegrityPlatform::from_ordinal(platform.into());
    let result = match (token, platform, signer.0) {
        (Some(token), Some(platform), Some(signer)) => Ok((
            token,
            platform,
            Arc::new(signer) as Arc<dyn RequestDigestSigner>,
        )),
        _ => Err(RequestIntegrityError::InvalidSession),
    };
    integrity::complete(completion, result);
}

/// Completes a pending integrity preparation with the ordinal of a provider failure;
/// unknown ordinals report `CallbackFailed`.
#[walletkit_jni_macros::jni_export]
fn integrity_failed(completion: u64, error: u32) {
    let error = RequestIntegrityError::from_ordinal(error.into())
        .unwrap_or(RequestIntegrityError::CallbackFailed);
    integrity::complete(completion, Err(error));
}

/// A nullable Kotlin `RequestDigestSigner` argument.
struct Signer(Option<JavaSigner>);

impl<'local> FromJni<'local> for Signer {
    type Raw = JObject<'local>;
    fn from_jni(env: &mut JNIEnv<'local>, raw: Self::Raw) -> Result<Self, Failure> {
        if raw.is_null() {
            return Ok(Self(None));
        }
        Ok(Self(Some(JavaSigner(Java::new(env, &raw)?))))
    }
}

/// Runs `call` on the current thread, attached to the JVM as a daemon, in its own frame.
fn attached<T>(
    call: impl FnOnce(&mut JNIEnv, &Classes) -> jni::errors::Result<T>,
) -> Result<T, HostFailure> {
    let classes = classes().map_err(|_| HostFailure::Jvm)?;
    let mut env = classes
        .vm
        .attach_current_thread_as_daemon()
        .map_err(|_| HostFailure::Jvm)?;
    // A JVM thread may call back into WalletKit with its own exception pending; leave it.
    if env.exception_check().unwrap_or(true) {
        return Err(HostFailure::Jvm);
    }
    env.with_local_frame(8, |env| -> jni::errors::Result<_> {
        Ok(match call(env, classes) {
            Ok(value) => Ok(value),
            Err(_) if env.exception_check()? => {
                let throwable = env.exception_occurred();
                env.exception_clear()?;
                Err(HostFailure::Exception(
                    throwable
                        .and_then(|throwable| env.new_global_ref(throwable))
                        .ok(),
                ))
            }
            Err(_) => Err(HostFailure::Jvm),
        })
    })
    .unwrap_or(Err(HostFailure::Jvm))
}

enum HostFailure {
    /// The JVM was unavailable or rejected a JNI call.
    Jvm,
    /// The host threw; the exception is cleared.
    Exception(Option<GlobalRef>),
}

fn storage_call<T>(
    call: impl FnOnce(&mut JNIEnv, &Classes) -> jni::errors::Result<T>,
) -> StorageResult<T> {
    attached(call).map_err(|failure| match failure {
        HostFailure::Jvm => StorageError::Callback("JvmUnavailable".into()),
        HostFailure::Exception(throwable) => throwable
            .and_then(|throwable| storage_error(&throwable))
            .unwrap_or_else(|| StorageError::Callback("HostFailure".into())),
    })
}

/// Converts a host `StorageException` back into its `StorageError` variant.
fn storage_error(throwable: &GlobalRef) -> Option<StorageError> {
    attached(|env, classes| {
        // SAFETY: the method ID was resolved for this signature in `JNI_OnLoad`.
        let encoded = unsafe {
            env.call_static_method_unchecked(
                &classes.bridge,
                classes.callback_error,
                ReturnType::Array,
                &[jvalue {
                    l: throwable.as_raw(),
                }],
            )
        }?
        .l()?;
        if encoded.is_null() {
            return Ok(None);
        }
        env.convert_byte_array(JByteArray::from(encoded)).map(Some)
    })
    .ok()
    .flatten()
    .and_then(|bytes| codec::decode(&bytes).ok())
}

/// Delivers a notification. Its producer cannot handle errors, so failures are reported
/// without host details: through the `WalletKit` log, or stderr when the logger failed.
fn notify(
    callback: &'static str,
    call: impl FnOnce(&mut JNIEnv, &Classes) -> jni::errors::Result<()>,
) {
    if attached(call).is_ok() {
        return;
    }
    if callback == "Logger" {
        eprintln!("WalletKit: host Logger callback failed");
    } else {
        tracing::warn!(callback, "WalletKit host notification callback failed");
    }
}

/// Takes a pending exception so that cleanup JNI calls can run before it is rethrown.
fn take_pending<'local>(
    env: &mut JNIEnv<'local>,
) -> jni::errors::Result<Option<jni::objects::JThrowable<'local>>> {
    if !env.exception_check()? {
        return Ok(None);
    }
    let throwable = env.exception_occurred()?;
    env.exception_clear()?;
    Ok(Some(throwable))
}

/// A keystore must return bytes; an empty result would be persisted as a sealed value.
fn required(bytes: Option<Vec<u8>>) -> StorageResult<Vec<u8>> {
    bytes.ok_or_else(|| StorageError::Callback("MissingResult".into()))
}

/// Calls a method returning `byte[]`. With `clear`, the returned Java array, such as
/// opened plaintext, is zeroed once copied.
fn call_bytes(
    env: &mut JNIEnv,
    target: &GlobalRef,
    method: JMethodID,
    arguments: &[jobject],
    clear: bool,
) -> jni::errors::Result<Option<Vec<u8>>> {
    let arguments: Vec<jvalue> = arguments.iter().map(|&l| jvalue { l }).collect();
    // SAFETY: the method ID was resolved on the declaring interface in `JNI_OnLoad` and
    // `target` implements that interface.
    let result = unsafe {
        env.call_method_unchecked(target, method, ReturnType::Array, &arguments)
    }?
    .l()?;
    if result.is_null() {
        return Ok(None);
    }
    let array = JByteArray::from(result);
    let bytes = env.convert_byte_array(&array)?;
    if clear {
        env.set_byte_array_region(&array, 0, &vec![0; bytes.len()])?;
    }
    Ok(Some(bytes))
}

fn call_void(
    env: &mut JNIEnv,
    target: &GlobalRef,
    method: JMethodID,
    arguments: &[jobject],
) -> jni::errors::Result<()> {
    let arguments: Vec<jvalue> = arguments.iter().map(|&l| jvalue { l }).collect();
    // SAFETY: as in `call_bytes`.
    unsafe {
        env.call_method_unchecked(
            target,
            method,
            ReturnType::Primitive(Primitive::Void),
            &arguments,
        )
    }?;
    Ok(())
}
