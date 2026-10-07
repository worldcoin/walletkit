//! C functions for credential issuers and recovery bindings.

use super::{
    complete, complete_unit, ordinal, AuthenticatorHandle, Buffer, ByteSlice,
    CredentialHandle, Handle, OperationHandle, RecoveryBindingManagerHandle,
    TfhNfcIssuerHandle, UserAgentBuilderHandle,
};
use crate::native::ops;

/// `TfhNfcIssuer.create`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_tfh_nfc_issuer_new(
    environment: u8,
    user_agent: ByteSlice,
    out: *mut TfhNfcIssuerHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::issuers::tfh_nfc_issuer_new(
                ordinal(environment)?,
                user_agent.string()?,
            ))
        })
    }
}

/// `TfhNfcIssuer.refreshNfcCredential`.
///
/// Blocks until the operation completes or `operation` is cancelled.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_tfh_nfc_issuer_refresh_nfc_credential(
    operation: OperationHandle,
    issuer: TfhNfcIssuerHandle,
    request_body: ByteSlice,
    headers: ByteSlice,
    out: *mut CredentialHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::issuers::tfh_nfc_issuer_refresh_nfc_credential(
                operation.operation()?,
                issuer.get()?,
                request_body.string()?,
                headers.decode()?,
            )
        })
    }
}

/// `RecoveryBindingManager.create`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_recovery_binding_manager_new(
    environment: u8,
    user_agent_builder: UserAgentBuilderHandle,
    out: *mut RecoveryBindingManagerHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::issuers::recovery_binding_manager_new(
                ordinal(environment)?,
                user_agent_builder.get()?,
            )
        })
    }
}

/// `RecoveryBindingManager.newWithBaseUrl`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_recovery_binding_manager_new_with_base_url(
    base_url: ByteSlice,
    user_agent_builder: UserAgentBuilderHandle,
    out: *mut RecoveryBindingManagerHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::issuers::recovery_binding_manager_new_with_base_url(
                base_url.string()?,
                user_agent_builder.get()?,
            )
        })
    }
}

/// `RecoveryBindingManager.bindRecoveryAgent`.
///
/// Blocks until the operation completes or `operation` is cancelled.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_recovery_binding_manager_bind_recovery_agent(
    operation: OperationHandle,
    manager: RecoveryBindingManagerHandle,
    authenticator: AuthenticatorHandle,
    sub: ByteSlice,
    recovery_agent_address: ByteSlice,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete_unit(out_error, || {
            ops::issuers::recovery_binding_manager_bind_recovery_agent(
                operation.operation()?,
                manager.get()?,
                authenticator.get()?,
                sub.string()?,
                recovery_agent_address.string()?,
            )
        })
    }
}

/// `RecoveryBindingManager.unbindRecoveryAgent`.
///
/// Blocks until the operation completes or `operation` is cancelled.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_recovery_binding_manager_unbind_recovery_agent(
    operation: OperationHandle,
    manager: RecoveryBindingManagerHandle,
    authenticator: AuthenticatorHandle,
    sub: ByteSlice,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete_unit(out_error, || {
            ops::issuers::recovery_binding_manager_unbind_recovery_agent(
                operation.operation()?,
                manager.get()?,
                authenticator.get()?,
                sub.string()?,
            )
        })
    }
}

/// `RecoveryBindingManager.getRecoveryBinding`.
///
/// Writes the binary encoding to `out`.
///
/// Blocks until the operation completes or `operation` is cancelled.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_recovery_binding_manager_get_recovery_binding(
    operation: OperationHandle,
    manager: RecoveryBindingManagerHandle,
    leaf_index: u64,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::issuers::recovery_binding_manager_get_recovery_binding(
                operation.operation()?,
                manager.get()?,
                leaf_index,
            )
        })
    }
}
