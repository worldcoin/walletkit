//! C functions for field elements, credentials, proof requests and responses, user
//! agents, environments, and logging.

use super::{
    callbacks, complete, complete_unit, optional_ordinal, ordinal, Buffer, ByteSlice,
    CredentialHandle, FieldElementHandle, Handle, OwnershipProofHandle,
    ProofRequestHandle, ProofResponseHandle, UserAgentBuilderHandle, UserAgentHandle,
};
use crate::native::ops;

/// `FieldElement.fromBytes`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_field_element_from_bytes(
    bytes: ByteSlice,
    out: *mut FieldElementHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::identity::field_element_from_bytes(bytes.to_vec()?)
        })
    }
}

/// `FieldElement.fromU64`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_field_element_from_u64(
    value: u64,
    out: *mut FieldElementHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::identity::field_element_from_u64(value))
        })
    }
}

/// `FieldElement.toBytes`.
///
/// Writes the bytes to `out`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_field_element_to_bytes(
    element: FieldElementHandle,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::identity::field_element_to_bytes(element.get()?))
        })
    }
}

/// `FieldElement.tryFromHexString`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_field_element_try_from_hex_string(
    hex_string: ByteSlice,
    out: *mut FieldElementHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::identity::field_element_try_from_hex_string(hex_string.string()?)
        })
    }
}

/// `FieldElement.toHexString`.
///
/// Writes the UTF-8 string to `out`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_field_element_to_hex_string(
    element: FieldElementHandle,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::identity::field_element_to_hex_string(element.get()?))
        })
    }
}

/// `Credential.fromBytes`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_credential_from_bytes(
    bytes: ByteSlice,
    out: *mut CredentialHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::identity::credential_from_bytes(bytes.to_vec()?)
        })
    }
}

/// `Credential.sub`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_credential_sub(
    credential: CredentialHandle,
    out: *mut FieldElementHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::identity::credential_sub(credential.get()?))
        })
    }
}

/// `Credential.issuerSchemaId`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_credential_issuer_schema_id(
    credential: CredentialHandle,
    out: *mut u64,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::identity::credential_issuer_schema_id(
                credential.get()?,
            ))
        })
    }
}

/// `Credential.expiresAt`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_credential_expires_at(
    credential: CredentialHandle,
    out: *mut u64,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::identity::credential_expires_at(credential.get()?))
        })
    }
}

/// `Credential.associatedDataCommitment`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_credential_associated_data_commitment(
    credential: CredentialHandle,
    out: *mut FieldElementHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::identity::credential_associated_data_commitment(
                credential.get()?,
            ))
        })
    }
}

/// `Credential.claims`.
///
/// Writes the binary encoding to `out`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_credential_claims(
    credential: CredentialHandle,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::identity::credential_claims(credential.get()?))
        })
    }
}

/// `Credential.claimsHex`.
///
/// Writes the binary encoding to `out`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_credential_claims_hex(
    credential: CredentialHandle,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::identity::credential_claims_hex(credential.get()?))
        })
    }
}

/// `ProofRequest.fromJson`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_proof_request_from_json(
    json: ByteSlice,
    out: *mut ProofRequestHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::identity::proof_request_from_json(json.string()?)
        })
    }
}

/// `ProofRequest.toJson`.
///
/// Writes the UTF-8 string to `out`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_proof_request_to_json(
    request: ProofRequestHandle,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::identity::proof_request_to_json(request.get()?)
        })
    }
}

/// `ProofRequest.id`.
///
/// Writes the UTF-8 string to `out`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_proof_request_id(
    request: ProofRequestHandle,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::identity::proof_request_id(request.get()?))
        })
    }
}

/// `ProofRequest.version`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_proof_request_version(
    request: ProofRequestHandle,
    out: *mut u8,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::identity::proof_request_version(request.get()?))
        })
    }
}

/// `ProofResponse.toJson`.
///
/// Writes the UTF-8 string to `out`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_proof_response_to_json(
    response: ProofResponseHandle,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::identity::proof_response_to_json(response.get()?)
        })
    }
}

/// `ProofResponse.id`.
///
/// Writes the UTF-8 string to `out`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_proof_response_id(
    response: ProofResponseHandle,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::identity::proof_response_id(response.get()?))
        })
    }
}

/// `ProofResponse.version`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_proof_response_version(
    response: ProofResponseHandle,
    out: *mut u8,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::identity::proof_response_version(response.get()?))
        })
    }
}

/// `ProofResponse.error`.
///
/// Writes the UTF-8 string to `out`, or a null buffer when absent.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_proof_response_error(
    response: ProofResponseHandle,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::identity::proof_response_error(response.get()?))
        })
    }
}

/// `OwnershipProof.encode`.
///
/// Writes the bytes to `out`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_ownership_proof_encode(
    proof: OwnershipProofHandle,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::identity::ownership_proof_encode(proof.get()?)
        })
    }
}

/// `OwnershipProof.encodeB64`.
///
/// Writes the UTF-8 string to `out`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_ownership_proof_encode_b64(
    proof: OwnershipProofHandle,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::identity::ownership_proof_encode_b64(proof.get()?)
        })
    }
}

/// `OwnershipProof.merkleRoot`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_ownership_proof_merkle_root(
    proof: OwnershipProofHandle,
    out: *mut FieldElementHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::identity::ownership_proof_merkle_root(proof.get()?))
        })
    }
}

/// `UserAgent.headerValue`.
///
/// Writes the UTF-8 string to `out`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_user_agent_header_value(
    user_agent: UserAgentHandle,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::identity::user_agent_header_value(user_agent.get()?))
        })
    }
}

/// `UserAgentBuilder.create`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_user_agent_builder_new(
    out: *mut UserAgentBuilderHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::identity::user_agent_builder_new())
        })
    }
}

/// `UserAgentBuilder.withSegment`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_user_agent_builder_with_segment(
    builder: UserAgentBuilderHandle,
    name: ByteSlice,
    version: ByteSlice,
    out: *mut UserAgentBuilderHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::identity::user_agent_builder_with_segment(
                builder.get()?,
                name.string()?,
                version.string()?,
            ))
        })
    }
}

/// `UserAgentBuilder.withAppSegmentForClient`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_user_agent_builder_with_app_segment_for_client(
    builder: UserAgentBuilderHandle,
    app_version: ByteSlice,
    client_name: ByteSlice,
    out: *mut UserAgentBuilderHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(
                ops::identity::user_agent_builder_with_app_segment_for_client(
                    builder.get()?,
                    app_version.string()?,
                    client_name.string()?,
                ),
            )
        })
    }
}

/// `UserAgentBuilder.withWalletkitSegment`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_user_agent_builder_with_walletkit_segment(
    builder: UserAgentBuilderHandle,
    out: *mut UserAgentBuilderHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::identity::user_agent_builder_with_walletkit_segment(
                builder.get()?,
            ))
        })
    }
}

/// `UserAgentBuilder.withClientSegment`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_user_agent_builder_with_client_segment(
    builder: UserAgentBuilderHandle,
    client_name: ByteSlice,
    os_version: ByteSlice,
    out: *mut UserAgentBuilderHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::identity::user_agent_builder_with_client_segment(
                builder.get()?,
                client_name.string()?,
                os_version.string()?,
            ))
        })
    }
}

/// `UserAgentBuilder.build`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_user_agent_builder_build(
    builder: UserAgentBuilderHandle,
    out: *mut UserAgentHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::identity::user_agent_builder_build(builder.get()?))
        })
    }
}

/// `WalletKit.emitLog`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_emit_log(
    level: u8,
    message: ByteSlice,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete_unit(out_error, || {
            ops::identity::emit_log(ordinal(level)?, message.string()?);
            Ok(())
        })
    }
}

/// `WalletKit.initLogging`.
///
/// Consumes the callback tables, including on failure.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_init_logging(
    logger: callbacks::LoggerCallbacks,
    level: i32,
    out_error: *mut Buffer,
) -> bool {
    let logger = callbacks::logger(logger);
    // SAFETY: forwarded from the caller.
    unsafe {
        complete_unit(out_error, || {
            ops::identity::init_logging(logger, optional_ordinal(level)?);
            Ok(())
        })
    }
}

/// `WalletKit.sanitizeHexSecrets`.
///
/// Writes the UTF-8 string to `out`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_sanitize_hex_secrets(
    input: ByteSlice,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::identity::sanitize_hex_secrets(input.string()?))
        })
    }
}

/// `Environment.pohRecoveryAgentAddress`.
///
/// Writes the UTF-8 string to `out`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_environment_poh_recovery_agent_address(
    environment: u8,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::identity::environment_poh_recovery_agent_address(
                ordinal(environment)?,
            ))
        })
    }
}

/// `Environment.worldIdVerifierAddress`.
///
/// Writes the UTF-8 string to `out`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_environment_world_id_verifier_address(
    environment: u8,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::identity::environment_world_id_verifier_address(
                ordinal(environment)?,
            ))
        })
    }
}
