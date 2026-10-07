//! Runtime for `#[jni_export]` functions: argument and result conversion, exceptions, and
//! the class, method, and field IDs resolved once in `JNI_OnLoad`.
//!
//! All type knowledge lives in the [`FromJni`] and [`IntoJni`] impls here; the macro
//! only writes glue. Kotlin passes resources as their `NativeHandle`, whose JNI local
//! reference keeps the owner reachable for the whole call.

mod callbacks;

use super::{
    codec::{self, Binary, Decode, Encode},
    error::NativeError,
    operation::{Operation, OperationState},
    registry::{self, NativeObject},
    values::Ordinal,
};
use jni::{
    errors::Error as JniError,
    objects::{
        GlobalRef, JByteArray, JFieldID, JMethodID, JObject, JStaticMethodID, JString,
        JThrowable,
    },
    signature::{Primitive, ReturnType},
    sys::{self, jboolean, jfloat, jint, jlong, jobject, jvalue},
    JNIEnv, JavaVM,
};
use std::{
    ffi::c_void,
    panic::AssertUnwindSafe,
    sync::{Arc, OnceLock},
};
use walletkit_core::Uint256;
use zeroize::Zeroizing;

/// Why a JNI call did not produce a value.
pub enum Failure {
    /// A domain or bridge error, thrown as the SDK's typed exception.
    Native(NativeError),
    /// A Java exception is already pending.
    Pending,
    /// The JNI environment rejected an operation; thrown as `IllegalStateException`.
    Jni(&'static str),
}

impl From<NativeError> for Failure {
    fn from(error: NativeError) -> Self {
        Self::Native(error)
    }
}

impl From<JniError> for Failure {
    fn from(error: JniError) -> Self {
        match error {
            JniError::JavaException => Self::Pending,
            _ => Self::Jni("WalletKit JNI call failed"),
        }
    }
}

/// Runs a generated entry point, converting failures and panics into Java exceptions.
pub fn boundary<'local, R: Null>(
    env: &mut JNIEnv<'local>,
    body: impl FnOnce(&mut JNIEnv<'local>) -> Result<R, Failure>,
) -> R {
    let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| body(&mut *env)))
        .unwrap_or(Err(Failure::Jni("WalletKit panicked")));
    match outcome {
        Ok(value) => value,
        Err(failure) => {
            throw(env, failure);
            R::null()
        }
    }
}

fn throw(env: &mut JNIEnv, failure: Failure) {
    if env.exception_check().unwrap_or(true) {
        return;
    }
    let message = match failure {
        Failure::Pending => "WalletKit JNI call failed",
        Failure::Jni(message) => message,
        Failure::Native(error) => match throw_native(env, error) {
            Ok(()) => return,
            Err(_) if env.exception_check().unwrap_or(true) => return,
            Err(_) => "WalletKit error conversion failed",
        },
    };
    let _ = env.throw_new("java/lang/IllegalStateException", message);
}

/// Throws the exception that Kotlin `NativeBridge.nativeError` decodes from the error.
fn throw_native(env: &mut JNIEnv, error: NativeError) -> Result<(), Failure> {
    let classes = classes()?;
    let details = env.byte_array_from_slice(&error.encode())?;
    // SAFETY: the method ID was resolved for this signature in `JNI_OnLoad`.
    let throwable = unsafe {
        env.call_static_method_unchecked(
            &classes.bridge,
            classes.native_error,
            ReturnType::Object,
            &[jvalue {
                l: details.as_raw(),
            }],
        )
    }?
    .l()?;
    env.throw(JThrowable::from(throwable))?;
    Ok(())
}

/// Converts a JNI argument into the Rust parameter type.
pub trait FromJni<'local>: Sized {
    /// The JNI parameter type.
    type Raw;
    /// Converts or fails with a pending exception or typed error.
    fn from_jni(env: &mut JNIEnv<'local>, raw: Self::Raw) -> Result<Self, Failure>;
}

/// Converts a Rust result into the JNI return type.
pub trait IntoJni<'local> {
    /// The JNI return type.
    type Raw: Null;
    /// Converts or fails with a pending exception or typed error.
    fn into_jni(self, env: &mut JNIEnv<'local>) -> Result<Self::Raw, Failure>;
}

/// The value returned to Java when an exception is pending; Java ignores it.
pub trait Null {
    /// Returns the placeholder.
    fn null() -> Self;
}

macro_rules! null {
    ($($ty:ty => $value:expr),* $(,)?) => {$(
        impl Null for $ty {
            fn null() -> Self {
                $value
            }
        }
    )*};
}
null!(
    () => (),
    jlong => 0,
    jint => 0,
    jboolean => 0,
    jfloat => 0.0,
    jobject => std::ptr::null_mut(),
);

impl FromJni<'_> for u64 {
    type Raw = jlong;
    fn from_jni(_: &mut JNIEnv, raw: jlong) -> Result<Self, Failure> {
        Ok(raw.cast_unsigned())
    }
}

impl FromJni<'_> for u32 {
    type Raw = jint;
    fn from_jni(_: &mut JNIEnv, raw: jint) -> Result<Self, Failure> {
        Ok(raw.cast_unsigned())
    }
}

impl FromJni<'_> for bool {
    type Raw = jboolean;
    fn from_jni(_: &mut JNIEnv, raw: jboolean) -> Result<Self, Failure> {
        Ok(raw != 0)
    }
}

/// A nullable `java.lang.Long`, used for Kotlin `ULong?` arguments.
impl<'local> FromJni<'local> for Option<u64> {
    type Raw = JObject<'local>;
    fn from_jni(env: &mut JNIEnv<'local>, raw: Self::Raw) -> Result<Self, Failure> {
        if raw.is_null() {
            return Ok(None);
        }
        // SAFETY: Kotlin declares this parameter as `Long?`; the ID belongs to `Long`.
        let value = unsafe {
            env.call_method_unchecked(
                &raw,
                classes()?.long_value,
                ReturnType::Primitive(Primitive::Long),
                &[],
            )
        }?
        .j()?;
        Ok(Some(value.cast_unsigned()))
    }
}

/// An enumeration ordinal.
impl<T: Ordinal> FromJni<'_> for T {
    type Raw = jint;
    fn from_jni(_: &mut JNIEnv, raw: jint) -> Result<Self, Failure> {
        Self::from_ordinal(raw.into())
            .ok_or_else(|| NativeError::invalid_input().into())
    }
}

/// An enumeration ordinal, or -1 for `None`.
impl<T: Ordinal> FromJni<'_> for Option<T> {
    type Raw = jint;
    fn from_jni(env: &mut JNIEnv, raw: jint) -> Result<Self, Failure> {
        if raw == -1 {
            return Ok(None);
        }
        T::from_jni(env, raw).map(Some)
    }
}

/// A Java string. Unpaired surrogates are rejected rather than replaced, as the C ABI
/// rejects invalid UTF-8.
impl<'local> FromJni<'local> for String {
    type Raw = JString<'local>;
    fn from_jni(env: &mut JNIEnv<'local>, raw: Self::Raw) -> Result<Self, Failure> {
        non_null(&raw)?;
        // SAFETY: the JNI signature declares `java.lang.String`.
        let modified_utf8 = unsafe { env.get_string_unchecked(&raw) }?;
        let value = cesu8::from_java_cesu8(modified_utf8.to_bytes())
            .map_err(|_| NativeError::invalid_input())?;
        Ok(value.into_owned())
    }
}

/// Secret bytes, such as seeds, zeroed when dropped on any path.
impl<'local> FromJni<'local> for Zeroizing<Vec<u8>> {
    type Raw = JByteArray<'local>;
    fn from_jni(env: &mut JNIEnv<'local>, raw: Self::Raw) -> Result<Self, Failure> {
        Vec::from_jni(env, raw).map(Self::new)
    }
}

impl<'local> FromJni<'local> for Option<String> {
    type Raw = JString<'local>;
    fn from_jni(env: &mut JNIEnv<'local>, raw: Self::Raw) -> Result<Self, Failure> {
        if raw.is_null() {
            return Ok(None);
        }
        String::from_jni(env, raw).map(Some)
    }
}

impl<'local> FromJni<'local> for Vec<u8> {
    type Raw = JByteArray<'local>;
    fn from_jni(env: &mut JNIEnv<'local>, raw: Self::Raw) -> Result<Self, Failure> {
        non_null(&raw)?;
        Ok(env.convert_byte_array(raw)?)
    }
}

impl<'local> FromJni<'local> for Option<Vec<u8>> {
    type Raw = JByteArray<'local>;
    fn from_jni(env: &mut JNIEnv<'local>, raw: Self::Raw) -> Result<Self, Failure> {
        if raw.is_null() {
            return Ok(None);
        }
        Vec::from_jni(env, raw).map(Some)
    }
}

/// Exactly 32 big-endian bytes.
impl<'local> FromJni<'local> for Uint256 {
    type Raw = JByteArray<'local>;
    fn from_jni(env: &mut JNIEnv<'local>, raw: Self::Raw) -> Result<Self, Failure> {
        let bytes: [u8; 32] = Vec::from_jni(env, raw)?
            .try_into()
            .map_err(|_| NativeError::invalid_input())?;
        Ok(super::values::uint256(bytes))
    }
}

/// A record, list, or map in the binary encoding.
impl<'local, T: Decode> FromJni<'local> for Binary<T> {
    type Raw = JByteArray<'local>;
    fn from_jni(env: &mut JNIEnv<'local>, raw: Self::Raw) -> Result<Self, Failure> {
        let bytes = Zeroizing::new(Vec::from_jni(env, raw)?);
        Ok(Self(codec::decode(&bytes)?))
    }
}

/// A Kotlin `NativeHandle`. A closed handle throws `IllegalStateException`.
impl<'local, T: NativeObject + ?Sized> FromJni<'local> for Arc<T> {
    type Raw = JObject<'local>;
    fn from_jni(env: &mut JNIEnv<'local>, raw: Self::Raw) -> Result<Self, Failure> {
        non_null(&raw)?;
        let id = env
            .get_field_unchecked(
                &raw,
                classes()?.handle_id,
                ReturnType::Primitive(Primitive::Long),
            )?
            .j()?;
        if id == 0 {
            env.throw_new(
                "java/lang/IllegalStateException",
                "WalletKit resource is closed",
            )?;
            return Err(Failure::Pending);
        }
        Ok(registry::get(id.cast_unsigned())?)
    }
}

/// The ID returned by `NativeBridge.operationNew`.
impl FromJni<'_> for Operation {
    type Raw = jlong;
    fn from_jni(_: &mut JNIEnv, raw: jlong) -> Result<Self, Failure> {
        Ok(Self(registry::get::<OperationState>(raw.cast_unsigned())?))
    }
}

fn non_null(object: &JObject) -> Result<(), Failure> {
    if object.is_null() {
        Err(Failure::Jni("Unexpected null WalletKit argument"))
    } else {
        Ok(())
    }
}

impl IntoJni<'_> for () {
    type Raw = ();
    fn into_jni(self, _: &mut JNIEnv) -> Result<(), Failure> {
        Ok(())
    }
}

impl IntoJni<'_> for u64 {
    type Raw = jlong;
    fn into_jni(self, _: &mut JNIEnv) -> Result<jlong, Failure> {
        Ok(self.cast_signed())
    }
}

impl IntoJni<'_> for u32 {
    type Raw = jint;
    fn into_jni(self, _: &mut JNIEnv) -> Result<jint, Failure> {
        Ok(self.cast_signed())
    }
}

impl IntoJni<'_> for u8 {
    type Raw = jint;
    fn into_jni(self, _: &mut JNIEnv) -> Result<jint, Failure> {
        Ok(self.into())
    }
}

impl IntoJni<'_> for bool {
    type Raw = jboolean;
    fn into_jni(self, _: &mut JNIEnv) -> Result<jboolean, Failure> {
        Ok(self.into())
    }
}

impl IntoJni<'_> for f32 {
    type Raw = Self;
    fn into_jni(self, _: &mut JNIEnv) -> Result<Self, Failure> {
        Ok(self)
    }
}

/// An enumeration ordinal.
impl<T: Ordinal> IntoJni<'_> for T {
    type Raw = jint;
    fn into_jni(self, _: &mut JNIEnv) -> Result<jint, Failure> {
        Ok(self.ordinal().into())
    }
}

impl IntoJni<'_> for String {
    type Raw = jobject;
    fn into_jni(self, env: &mut JNIEnv) -> Result<jobject, Failure> {
        Ok(env.new_string(self)?.into_raw())
    }
}

impl IntoJni<'_> for Option<String> {
    type Raw = jobject;
    fn into_jni(self, env: &mut JNIEnv) -> Result<jobject, Failure> {
        self.map_or(Ok(std::ptr::null_mut()), |value| value.into_jni(env))
    }
}

/// Bytes, zeroed in Rust once copied into the Java array.
impl IntoJni<'_> for Vec<u8> {
    type Raw = jobject;
    fn into_jni(self, env: &mut JNIEnv) -> Result<jobject, Failure> {
        let bytes = Zeroizing::new(self);
        Ok(env.byte_array_from_slice(&bytes)?.into_raw())
    }
}

/// Exactly 32 big-endian bytes.
impl IntoJni<'_> for Uint256 {
    type Raw = jobject;
    fn into_jni(self, env: &mut JNIEnv) -> Result<jobject, Failure> {
        Ok(env
            .byte_array_from_slice(&self.0.to_be_bytes::<32>())?
            .into_raw())
    }
}

/// Transfers a new handle to Kotlin, which wraps it in a `NativeHandle`.
impl<T: NativeObject + ?Sized> IntoJni<'_> for Arc<T> {
    type Raw = jlong;
    fn into_jni(self, _: &mut JNIEnv) -> Result<jlong, Failure> {
        Ok(registry::insert(self)?.cast_signed())
    }
}

/// A new handle, or 0 for `None`.
impl<T: NativeObject + ?Sized> IntoJni<'_> for Option<Arc<T>> {
    type Raw = jlong;
    fn into_jni(self, env: &mut JNIEnv) -> Result<jlong, Failure> {
        self.map_or(Ok(0), |object| object.into_jni(env))
    }
}

/// A record, list, or map in the binary encoding. Handles inside it are released if the
/// array cannot be created. Encoded records carry no secrets, so unlike byte results they
/// are not zeroed: at the release optimization level that would double the cost of a list.
impl<T: Encode> IntoJni<'_> for Binary<T> {
    type Raw = jobject;
    fn into_jni(self, env: &mut JNIEnv) -> Result<jobject, Failure> {
        let encoded = codec::encode(self.0)?;
        let array = env.byte_array_from_slice(encoded.bytes())?;
        encoded.claim();
        Ok(array.into_raw())
    }
}

struct Classes {
    vm: JavaVM,
    bridge: GlobalRef,
    // Interface method and field IDs stay valid while their classes are loaded.
    _retained: [GlobalRef; 7],
    native_error: JStaticMethodID,
    callback_error: JStaticMethodID,
    log: JStaticMethodID,
    prepare_integrity: JStaticMethodID,
    handle_id: JFieldID,
    long_value: JMethodID,
    keystore_seal: JMethodID,
    keystore_open_sealed: JMethodID,
    blob_read: JMethodID,
    blob_write_atomic: JMethodID,
    blob_delete: JMethodID,
    vault_changed: JMethodID,
    activity_changed: JMethodID,
    sign_digest: JMethodID,
}

static CLASSES: OnceLock<Classes> = OnceLock::new();

fn classes() -> Result<&'static Classes, Failure> {
    CLASSES
        .get()
        .ok_or(Failure::Jni("WalletKit JNI_OnLoad did not run"))
}

impl Classes {
    fn load(env: &mut JNIEnv) -> jni::errors::Result<Self> {
        let bridge = env.find_class("org/world/walletkit/NativeBridge")?;
        let handle = env.find_class("org/world/walletkit/NativeHandle")?;
        let long = env.find_class("java/lang/Long")?;
        let keystore = env.find_class("org/world/walletkit/DeviceKeystore")?;
        let blob_store = env.find_class("org/world/walletkit/AtomicBlobStore")?;
        let vault = env.find_class("org/world/walletkit/VaultChangedListener")?;
        let activity = env.find_class("org/world/walletkit/ActivityChangedListener")?;
        let signer = env.find_class("org/world/walletkit/RequestDigestSigner")?;
        Ok(Self {
            native_error: env.get_static_method_id(
                &bridge,
                "nativeError",
                "([B)Ljava/lang/Throwable;",
            )?,
            callback_error: env.get_static_method_id(
                &bridge,
                "callbackError",
                "(Ljava/lang/Throwable;)[B",
            )?,
            log: env.get_static_method_id(
                &bridge,
                "log",
                "(Lorg/world/walletkit/Logger;ILjava/lang/String;)V",
            )?,
            prepare_integrity: env.get_static_method_id(
                &bridge,
                "prepareIntegrity",
                "(Lorg/world/walletkit/RequestIntegrityProvider;J)V",
            )?,
            handle_id: env.get_field_id(&handle, "id", "J")?,
            long_value: env.get_method_id(&long, "longValue", "()J")?,
            keystore_seal: env.get_method_id(&keystore, "seal", "([B[B)[B")?,
            keystore_open_sealed: env.get_method_id(
                &keystore,
                "openSealed",
                "([B[B)[B",
            )?,
            blob_read: env.get_method_id(
                &blob_store,
                "read",
                "(Ljava/lang/String;)[B",
            )?,
            blob_write_atomic: env.get_method_id(
                &blob_store,
                "writeAtomic",
                "(Ljava/lang/String;[B)V",
            )?,
            blob_delete: env.get_method_id(
                &blob_store,
                "delete",
                "(Ljava/lang/String;)V",
            )?,
            vault_changed: env.get_method_id(&vault, "onVaultChanged", "()V")?,
            activity_changed: env.get_method_id(
                &activity,
                "onActivityChanged",
                "()V",
            )?,
            sign_digest: env.get_method_id(&signer, "signDigest", "([B)[B")?,
            vm: env.get_java_vm()?,
            bridge: env.new_global_ref(bridge)?,
            _retained: [
                env.new_global_ref(handle)?,
                env.new_global_ref(long)?,
                env.new_global_ref(keystore)?,
                env.new_global_ref(blob_store)?,
                env.new_global_ref(vault)?,
                env.new_global_ref(activity)?,
                env.new_global_ref(signer)?,
            ],
        })
    }
}

/// Resolves the classes and member IDs used by the entry points. Failing here makes
/// `System.loadLibrary` throw instead of failing later on first use.
#[no_mangle]
pub extern "system" fn JNI_OnLoad(vm: *mut sys::JavaVM, _: *mut c_void) -> jint {
    // SAFETY: the JVM passes a valid VM pointer to `JNI_OnLoad`.
    let Ok(vm) = (unsafe { JavaVM::from_raw(vm) }) else {
        return sys::JNI_ERR;
    };
    let Ok(mut env) = vm.get_env() else {
        return sys::JNI_ERR;
    };
    Classes::load(&mut env).map_or(sys::JNI_ERR, |classes| {
        // The JVM binds a native library to a single class loader, so this runs once.
        let _ = CLASSES.set(classes);
        sys::JNI_VERSION_1_6
    })
}
