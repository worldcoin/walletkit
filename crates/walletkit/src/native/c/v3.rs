//! C functions for legacy World ID v3.

use super::{
    complete, optional_bytes, optional_string, ordinal, AddressBookHandle, Buffer,
    ByteSlice, Handle, MerkleTreeProofHandle, OperationHandle, ProofContextHandle,
    ProofOutputHandle, Uint256, WorldIdHandle,
};
use crate::native::ops;
use zeroize::Zeroizing;

/// `AddressBook.create`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_address_book_new(
    out: *mut AddressBookHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe { complete(out, out_error, || Ok(ops::v3::address_book_new())) }
}

/// `AddressBook.generateProofContext`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_address_book_generate_proof_context(
    address_book: AddressBookHandle,
    address_to_verify: ByteSlice,
    timestamp: u64,
    out: *mut ProofContextHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::v3::address_book_generate_proof_context(
                address_book.get()?,
                address_to_verify.string()?,
                timestamp,
            )
        })
    }
}

/// `WorldId.create`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_world_id_new(
    secret: ByteSlice,
    environment: u8,
    out: *mut WorldIdHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::v3::world_id_new(
                Zeroizing::new(secret.to_vec()?),
                ordinal(environment)?,
            ))
        })
    }
}

/// `WorldId.generateNullifierHash`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_world_id_generate_nullifier_hash(
    world_id: WorldIdHandle,
    context: ProofContextHandle,
    out: *mut Uint256,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::v3::world_id_generate_nullifier_hash(
                world_id.get()?,
                context.get()?,
            ))
        })
    }
}

/// `WorldId.getIdentityCommitment`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_world_id_get_identity_commitment(
    world_id: WorldIdHandle,
    credential_type: u8,
    out: *mut Uint256,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::v3::world_id_get_identity_commitment(
                world_id.get()?,
                ordinal(credential_type)?,
            ))
        })
    }
}

/// `WorldId.generateProof`.
///
/// Blocks until the operation completes or `operation` is cancelled.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_world_id_generate_proof(
    operation: OperationHandle,
    world_id: WorldIdHandle,
    context: ProofContextHandle,
    out: *mut ProofOutputHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::v3::world_id_generate_proof(
                operation.operation()?,
                world_id.get()?,
                context.get()?,
            )
        })
    }
}

/// `WorldId.isEqualTo`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_world_id_is_equal_to(
    world_id: WorldIdHandle,
    other: WorldIdHandle,
    out: *mut bool,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::v3::world_id_is_equal_to(world_id.get()?, other.get()?))
        })
    }
}

/// `ProofContext.create`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_proof_context_new(
    app_id: ByteSlice,
    action: *const ByteSlice,
    signal: *const ByteSlice,
    credential_type: u8,
    out: *mut ProofContextHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::v3::proof_context_new(
                app_id.string()?,
                optional_string(action)?,
                optional_string(signal)?,
                ordinal(credential_type)?,
            ))
        })
    }
}

/// `ProofContext.newFromBytes`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_proof_context_new_from_bytes(
    app_id: ByteSlice,
    action: *const ByteSlice,
    signal: *const ByteSlice,
    credential_type: u8,
    out: *mut ProofContextHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::v3::proof_context_new_from_bytes(
                app_id.string()?,
                optional_bytes(action)?,
                optional_bytes(signal)?,
                ordinal(credential_type)?,
            ))
        })
    }
}

/// `ProofContext.newFromSignalHash`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_proof_context_new_from_signal_hash(
    app_id: ByteSlice,
    action: *const ByteSlice,
    credential_type: u8,
    signal_hash: Uint256,
    out: *mut ProofContextHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::v3::proof_context_new_from_signal_hash(
                app_id.string()?,
                optional_bytes(action)?,
                ordinal(credential_type)?,
                signal_hash.into(),
            )
        })
    }
}

/// `ProofContext.getExternalNullifier`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_proof_context_get_external_nullifier(
    context: ProofContextHandle,
    out: *mut Uint256,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::v3::proof_context_get_external_nullifier(
                context.get()?,
            ))
        })
    }
}

/// `ProofContext.getSignalHash`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_proof_context_get_signal_hash(
    context: ProofContextHandle,
    out: *mut Uint256,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::v3::proof_context_get_signal_hash(context.get()?))
        })
    }
}

/// `ProofContext.getCredentialType`.
///
/// Writes the ordinal to `out`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_proof_context_get_credential_type(
    context: ProofContextHandle,
    out: *mut u8,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::v3::proof_context_get_credential_type(context.get()?))
        })
    }
}

/// `ProofContext.legacyNewFromPreImageExternalNullifier`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_proof_context_legacy_new_from_pre_image_external_nullifier(
    external_nullifier: ByteSlice,
    credential_type: u8,
    signal: *const ByteSlice,
    require_mined_proof: bool,
    out: *mut ProofContextHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(
                ops::v3::proof_context_legacy_new_from_pre_image_external_nullifier(
                    external_nullifier.to_vec()?,
                    ordinal(credential_type)?,
                    optional_bytes(signal)?,
                    require_mined_proof,
                ),
            )
        })
    }
}

/// `ProofContext.legacyNewFromRawExternalNullifier`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_proof_context_legacy_new_from_raw_external_nullifier(
    external_nullifier: Uint256,
    credential_type: u8,
    signal: *const ByteSlice,
    require_mined_proof: bool,
    out: *mut ProofContextHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::v3::proof_context_legacy_new_from_raw_external_nullifier(
                external_nullifier.into(),
                ordinal(credential_type)?,
                optional_bytes(signal)?,
                require_mined_proof,
            )
        })
    }
}

/// `ProofOutput.toJson`.
///
/// Writes the UTF-8 string to `out`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_proof_output_to_json(
    output: ProofOutputHandle,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::v3::proof_output_to_json(output.get()?)
        })
    }
}

/// `ProofOutput.getNullifierHash`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_proof_output_get_nullifier_hash(
    output: ProofOutputHandle,
    out: *mut Uint256,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::v3::proof_output_get_nullifier_hash(output.get()?))
        })
    }
}

/// `ProofOutput.getMerkleRoot`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_proof_output_get_merkle_root(
    output: ProofOutputHandle,
    out: *mut Uint256,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::v3::proof_output_get_merkle_root(output.get()?))
        })
    }
}

/// `ProofOutput.getProofAsString`.
///
/// Writes the UTF-8 string to `out`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_proof_output_get_proof_as_string(
    output: ProofOutputHandle,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::v3::proof_output_get_proof_as_string(output.get()?))
        })
    }
}

/// `ProofOutput.getCredentialType`.
///
/// Writes the ordinal to `out`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_proof_output_get_credential_type(
    output: ProofOutputHandle,
    out: *mut u8,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::v3::proof_output_get_credential_type(output.get()?))
        })
    }
}

/// `MerkleTreeProof.fromIdentityCommitment`.
///
/// Blocks until the operation completes or `operation` is cancelled.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_merkle_tree_proof_from_identity_commitment(
    operation: OperationHandle,
    identity_commitment: Uint256,
    sequencer_host: ByteSlice,
    require_mined_proof: bool,
    out: *mut MerkleTreeProofHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::v3::merkle_tree_proof_from_identity_commitment(
                operation.operation()?,
                identity_commitment.into(),
                sequencer_host.string()?,
                require_mined_proof,
            )
        })
    }
}

/// `MerkleTreeProof.fromJsonProof`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_merkle_tree_proof_from_json_proof(
    json_proof: ByteSlice,
    merkle_root: ByteSlice,
    out: *mut MerkleTreeProofHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::v3::merkle_tree_proof_from_json_proof(
                json_proof.string()?,
                merkle_root.string()?,
            )
        })
    }
}
