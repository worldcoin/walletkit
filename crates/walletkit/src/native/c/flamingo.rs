//! C functions for Flamingo face matching.

use super::{
    callbacks, complete, Buffer, ByteSlice, FlamingoMatcherHandle, Handle,
    OperationHandle, VerifiedMatchTokenHandle,
};
use crate::native::ops;

/// `VerifiedMatchToken.matchCoefficient`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_verified_match_token_match_coefficient(
    token: VerifiedMatchTokenHandle,
    out: *mut f32,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::flamingo::verified_match_token_match_coefficient(
                token.get()?,
            ))
        })
    }
}

/// `FlamingoMatcher.create`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_flamingo_matcher_new(
    host_url: ByteSlice,
    out: *mut FlamingoMatcherHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::flamingo::flamingo_matcher_new(host_url.string()?)
        })
    }
}

/// `FlamingoMatcher.newAttested`.
///
/// Consumes the callback tables, including on failure.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_flamingo_matcher_new_attested(
    host_url: ByteSlice,
    integrity_provider: callbacks::RequestIntegrityProviderCallbacks,
    out: *mut FlamingoMatcherHandle,
    out_error: *mut Buffer,
) -> bool {
    let integrity_provider = callbacks::integrity_provider(integrity_provider);
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::flamingo::flamingo_matcher_new_attested(
                host_url.string()?,
                integrity_provider,
            )
        })
    }
}

/// `FlamingoMatcher.withMeasurements`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_flamingo_matcher_with_measurements(
    matcher: FlamingoMatcherHandle,
    measurements: ByteSlice,
    out: *mut FlamingoMatcherHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::flamingo::flamingo_matcher_with_measurements(
                matcher.get()?,
                measurements.decode()?,
            )
        })
    }
}

/// `FlamingoMatcher.dangerouslySkipMeasurements`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_flamingo_matcher_dangerously_skip_measurements(
    matcher: FlamingoMatcherHandle,
    out: *mut FlamingoMatcherHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::flamingo::flamingo_matcher_dangerously_skip_measurements(
                matcher.get()?,
            )
        })
    }
}

/// `FlamingoMatcher.withHeaders`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_flamingo_matcher_with_headers(
    matcher: FlamingoMatcherHandle,
    headers: ByteSlice,
    out: *mut FlamingoMatcherHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::flamingo::flamingo_matcher_with_headers(
                matcher.get()?,
                headers.decode()?,
            )
        })
    }
}

/// `FlamingoMatcher.performMatch`.
///
/// Writes the binary encoding to `out`.
///
/// Blocks until the operation completes or `operation` is cancelled.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_flamingo_matcher_perform_match(
    operation: OperationHandle,
    matcher: FlamingoMatcherHandle,
    request: ByteSlice,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::flamingo::flamingo_matcher_perform_match(
                operation.operation()?,
                matcher.get()?,
                request.decode()?,
            )
        })
    }
}
