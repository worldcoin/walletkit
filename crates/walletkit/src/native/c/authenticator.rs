//! C functions for authenticators and proving artifacts.

use super::{
    complete, complete_unit, optional_ordinal, optional_string, optional_u64, ordinal,
    AuthenticatorHandle, Buffer, ByteSlice, CredentialStoreHandle, FieldElementHandle,
    Handle, InitializingAuthenticatorHandle, OperationHandle, OwnershipProofHandle,
    ProofRequestHandle, ProofResponseHandle, Uint256, ZkArtifactSourceHandle,
};
#[cfg(feature = "embed-zkeys")]
use super::{CachingZkArtifactsHandle, EmbeddedZkArtifactsHandle, StoragePathsHandle};
use crate::native::ops;
use zeroize::Zeroizing;

/// `WalletKit.validateAuthenticatorPubkey`.
///
/// Writes the UTF-8 string to `out`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_validate_authenticator_pubkey(
    authenticator_pubkey: ByteSlice,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::authenticator::validate_authenticator_pubkey(
                authenticator_pubkey.string()?,
            )
        })
    }
}

/// `WalletKit.recoveryDataFromSeed`.
///
/// Writes the binary encoding to `out`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_recovery_data_from_seed(
    seed: ByteSlice,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::authenticator::recovery_data_from_seed(Zeroizing::new(seed.to_vec()?))
        })
    }
}

/// `Authenticator.initStorage`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_authenticator_init_storage(
    authenticator: AuthenticatorHandle,
    now: u64,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete_unit(out_error, || {
            ops::authenticator::authenticator_init_storage(authenticator.get()?, now)
        })
    }
}

/// `Authenticator.destroyStorage`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_authenticator_destroy_storage(
    authenticator: AuthenticatorHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete_unit(out_error, || {
            ops::authenticator::authenticator_destroy_storage(authenticator.get()?)
        })
    }
}

/// `Authenticator.packedAccountData`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_authenticator_packed_account_data(
    authenticator: AuthenticatorHandle,
    out: *mut Uint256,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::authenticator::authenticator_packed_account_data(
                authenticator.get()?,
            ))
        })
    }
}

/// `Authenticator.leafIndex`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_authenticator_leaf_index(
    authenticator: AuthenticatorHandle,
    out: *mut u64,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::authenticator::authenticator_leaf_index(
                authenticator.get()?,
            ))
        })
    }
}

/// `Authenticator.onchainAddress`.
///
/// Writes the UTF-8 string to `out`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_authenticator_onchain_address(
    authenticator: AuthenticatorHandle,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::authenticator::authenticator_onchain_address(
                authenticator.get()?,
            ))
        })
    }
}

/// `Authenticator.getPackedAccountDataRemote`.
///
/// Blocks until the operation completes or `operation` is cancelled.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_authenticator_get_packed_account_data_remote(
    operation: OperationHandle,
    authenticator: AuthenticatorHandle,
    out: *mut Uint256,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::authenticator::authenticator_get_packed_account_data_remote(
                operation.operation()?,
                authenticator.get()?,
            )
        })
    }
}

/// `Authenticator.generateCredentialBlindingFactorRemote`.
///
/// Blocks until the operation completes or `operation` is cancelled.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_authenticator_generate_credential_blinding_factor_remote(
    operation: OperationHandle,
    authenticator: AuthenticatorHandle,
    issuer_schema_id: u64,
    out: *mut FieldElementHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::authenticator::authenticator_generate_credential_blinding_factor_remote(
                operation.operation()?,
                authenticator.get()?,
                issuer_schema_id,
            )
        })
    }
}

/// `Authenticator.computeCredentialSub`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_authenticator_compute_credential_sub(
    authenticator: AuthenticatorHandle,
    blinding_factor: FieldElementHandle,
    out: *mut FieldElementHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::authenticator::authenticator_compute_credential_sub(
                authenticator.get()?,
                blinding_factor.get()?,
            ))
        })
    }
}

/// `Authenticator.dangerSignChallenge`.
///
/// Writes the bytes to `out`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_authenticator_danger_sign_challenge(
    authenticator: AuthenticatorHandle,
    challenge: ByteSlice,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::authenticator::authenticator_danger_sign_challenge(
                authenticator.get()?,
                challenge.to_vec()?,
            )
        })
    }
}

/// `Authenticator.dangerSignInitiateRecoveryAgentUpdate`.
///
/// Writes the binary encoding to `out`.
///
/// Blocks until the operation completes or `operation` is cancelled.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_authenticator_danger_sign_initiate_recovery_agent_update(
    operation: OperationHandle,
    authenticator: AuthenticatorHandle,
    new_recovery_agent: ByteSlice,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::authenticator::authenticator_danger_sign_initiate_recovery_agent_update(
                operation.operation()?,
                authenticator.get()?,
                new_recovery_agent.string()?,
            )
        })
    }
}

/// `Authenticator.updateRecoveryAgent`.
///
/// Writes the UTF-8 string to `out`.
///
/// Blocks until the operation completes or `operation` is cancelled.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_authenticator_update_recovery_agent(
    operation: OperationHandle,
    authenticator: AuthenticatorHandle,
    new_recovery_agent: ByteSlice,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::authenticator::authenticator_update_recovery_agent(
                operation.operation()?,
                authenticator.get()?,
                new_recovery_agent.string()?,
            )
        })
    }
}

/// `Authenticator.revertRecoveryAgentUpdate`.
///
/// Writes the UTF-8 string to `out`.
///
/// Blocks until the operation completes or `operation` is cancelled.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_authenticator_revert_recovery_agent_update(
    operation: OperationHandle,
    authenticator: AuthenticatorHandle,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::authenticator::authenticator_revert_recovery_agent_update(
                operation.operation()?,
                authenticator.get()?,
            )
        })
    }
}

/// `Authenticator.insertAuthenticator`.
///
/// Writes the UTF-8 string to `out`.
///
/// Blocks until the operation completes or `operation` is cancelled.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_authenticator_insert_authenticator(
    operation: OperationHandle,
    authenticator: AuthenticatorHandle,
    new_authenticator_pubkey: ByteSlice,
    new_authenticator_address: ByteSlice,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::authenticator::authenticator_insert_authenticator(
                operation.operation()?,
                authenticator.get()?,
                new_authenticator_pubkey.string()?,
                new_authenticator_address.string()?,
            )
        })
    }
}

/// `Authenticator.hasAuthenticatorPubkey`.
///
/// Blocks until the operation completes or `operation` is cancelled.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_authenticator_has_authenticator_pubkey(
    operation: OperationHandle,
    authenticator: AuthenticatorHandle,
    authenticator_pubkey: ByteSlice,
    out: *mut bool,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::authenticator::authenticator_has_authenticator_pubkey(
                operation.operation()?,
                authenticator.get()?,
                authenticator_pubkey.string()?,
            )
        })
    }
}

/// `Authenticator.getAuthenticatorPubkeys`.
///
/// Writes the binary encoding to `out`.
///
/// Blocks until the operation completes or `operation` is cancelled.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_authenticator_get_authenticator_pubkeys(
    operation: OperationHandle,
    authenticator: AuthenticatorHandle,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::authenticator::authenticator_get_authenticator_pubkeys(
                operation.operation()?,
                authenticator.get()?,
            )
        })
    }
}

/// `Authenticator.removeAuthenticator`.
///
/// Writes the UTF-8 string to `out`.
///
/// Blocks until the operation completes or `operation` is cancelled.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_authenticator_remove_authenticator(
    operation: OperationHandle,
    authenticator: AuthenticatorHandle,
    authenticator_address: ByteSlice,
    pubkey_id: u32,
    expected_authenticator_pubkey: ByteSlice,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::authenticator::authenticator_remove_authenticator(
                operation.operation()?,
                authenticator.get()?,
                authenticator_address.string()?,
                pubkey_id,
                expected_authenticator_pubkey.string()?,
            )
        })
    }
}

/// `Authenticator.pollStatus`.
///
/// Writes the binary encoding to `out`.
///
/// Blocks until the operation completes or `operation` is cancelled.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_authenticator_poll_status(
    operation: OperationHandle,
    authenticator: AuthenticatorHandle,
    request_id: ByteSlice,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::authenticator::authenticator_poll_status(
                operation.operation()?,
                authenticator.get()?,
                request_id.string()?,
            )
        })
    }
}

/// `Authenticator.generateProof`.
///
/// Blocks until the operation completes or `operation` is cancelled.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_authenticator_generate_proof(
    operation: OperationHandle,
    authenticator: AuthenticatorHandle,
    proof_request: ProofRequestHandle,
    now: *const u64,
    out: *mut ProofResponseHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::authenticator::authenticator_generate_proof(
                operation.operation()?,
                authenticator.get()?,
                proof_request.get()?,
                optional_u64(now),
            )
        })
    }
}

/// `Authenticator.proveCredentialSub`.
///
/// Blocks until the operation completes or `operation` is cancelled.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_authenticator_prove_credential_sub(
    operation: OperationHandle,
    authenticator: AuthenticatorHandle,
    nonce: FieldElementHandle,
    context: FieldElementHandle,
    blinding_factor: FieldElementHandle,
    sub: FieldElementHandle,
    out: *mut OwnershipProofHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::authenticator::authenticator_prove_credential_sub(
                operation.operation()?,
                authenticator.get()?,
                nonce.get()?,
                context.get()?,
                blinding_factor.get()?,
                sub.get()?,
            )
        })
    }
}

/// `Authenticator.initWithDefaults`.
///
/// Blocks until the operation completes or `operation` is cancelled.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_authenticator_init_with_defaults(
    operation: OperationHandle,
    seed: ByteSlice,
    rpc_url: *const ByteSlice,
    environment: u8,
    region: i32,
    artifacts: ZkArtifactSourceHandle,
    store: CredentialStoreHandle,
    out: *mut AuthenticatorHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::authenticator::authenticator_init_with_defaults(
                operation.operation()?,
                Zeroizing::new(seed.to_vec()?),
                optional_string(rpc_url)?,
                ordinal(environment)?,
                optional_ordinal(region)?,
                artifacts.get()?,
                store.get()?,
            )
        })
    }
}

/// `Authenticator.initWithOhttpDefaults`.
///
/// Blocks until the operation completes or `operation` is cancelled.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_authenticator_init_with_ohttp_defaults(
    operation: OperationHandle,
    seed: ByteSlice,
    rpc_url: *const ByteSlice,
    environment: u8,
    region: i32,
    artifacts: ZkArtifactSourceHandle,
    store: CredentialStoreHandle,
    out: *mut AuthenticatorHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::authenticator::authenticator_init_with_ohttp_defaults(
                operation.operation()?,
                Zeroizing::new(seed.to_vec()?),
                optional_string(rpc_url)?,
                ordinal(environment)?,
                optional_ordinal(region)?,
                artifacts.get()?,
                store.get()?,
            )
        })
    }
}

/// `Authenticator.initialize`.
///
/// Blocks until the operation completes or `operation` is cancelled.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_authenticator_init(
    operation: OperationHandle,
    seed: ByteSlice,
    config: ByteSlice,
    artifacts: ZkArtifactSourceHandle,
    store: CredentialStoreHandle,
    out: *mut AuthenticatorHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::authenticator::authenticator_init(
                operation.operation()?,
                Zeroizing::new(seed.to_vec()?),
                config.string()?,
                artifacts.get()?,
                store.get()?,
            )
        })
    }
}

/// `InitializingAuthenticator.registerWithDefaults`.
///
/// Blocks until the operation completes or `operation` is cancelled.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_initializing_authenticator_register_with_defaults(
    operation: OperationHandle,
    seed: ByteSlice,
    rpc_url: *const ByteSlice,
    environment: u8,
    region: i32,
    recovery_address: *const ByteSlice,
    out: *mut InitializingAuthenticatorHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::authenticator::initializing_authenticator_register_with_defaults(
                operation.operation()?,
                Zeroizing::new(seed.to_vec()?),
                optional_string(rpc_url)?,
                ordinal(environment)?,
                optional_ordinal(region)?,
                optional_string(recovery_address)?,
            )
        })
    }
}

/// `InitializingAuthenticator.registerWithOhttpDefaults`.
///
/// Blocks until the operation completes or `operation` is cancelled.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_initializing_authenticator_register_with_ohttp_defaults(
    operation: OperationHandle,
    seed: ByteSlice,
    rpc_url: *const ByteSlice,
    environment: u8,
    region: i32,
    recovery_address: *const ByteSlice,
    out: *mut InitializingAuthenticatorHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::authenticator::initializing_authenticator_register_with_ohttp_defaults(
                operation.operation()?,
                Zeroizing::new(seed.to_vec()?),
                optional_string(rpc_url)?,
                ordinal(environment)?,
                optional_ordinal(region)?,
                optional_string(recovery_address)?,
            )
        })
    }
}

/// `InitializingAuthenticator.register`.
///
/// Blocks until the operation completes or `operation` is cancelled.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_initializing_authenticator_register(
    operation: OperationHandle,
    seed: ByteSlice,
    config: ByteSlice,
    recovery_address: *const ByteSlice,
    out: *mut InitializingAuthenticatorHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::authenticator::initializing_authenticator_register(
                operation.operation()?,
                Zeroizing::new(seed.to_vec()?),
                config.string()?,
                optional_string(recovery_address)?,
            )
        })
    }
}

/// `InitializingAuthenticator.pollStatus`.
///
/// Writes the binary encoding to `out`.
///
/// Blocks until the operation completes or `operation` is cancelled.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[no_mangle]
pub unsafe extern "C" fn walletkit_initializing_authenticator_poll_status(
    operation: OperationHandle,
    authenticator: InitializingAuthenticatorHandle,
    out: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            ops::authenticator::initializing_authenticator_poll_status(
                operation.operation()?,
                authenticator.get()?,
            )
        })
    }
}

/// `EmbeddedZkArtifacts.create`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[cfg(feature = "embed-zkeys")]
#[no_mangle]
pub unsafe extern "C" fn walletkit_embedded_zk_artifacts_new(
    out: *mut EmbeddedZkArtifactsHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::authenticator::embedded_zk_artifacts_new())
        })
    }
}

/// `EmbeddedZkArtifacts.asZkArtifactSource`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[cfg(feature = "embed-zkeys")]
#[no_mangle]
pub unsafe extern "C" fn walletkit_embedded_zk_artifacts_as_zk_artifact_source(
    artifacts: EmbeddedZkArtifactsHandle,
    out: *mut ZkArtifactSourceHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(
                ops::authenticator::embedded_zk_artifacts_as_zk_artifact_source(
                    artifacts.get()?,
                ),
            )
        })
    }
}

/// `CachingZkArtifacts.create`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[cfg(feature = "embed-zkeys")]
#[no_mangle]
pub unsafe extern "C" fn walletkit_caching_zk_artifacts_new(
    storage_paths: StoragePathsHandle,
    out: *mut CachingZkArtifactsHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(ops::authenticator::caching_zk_artifacts_new(
                storage_paths.get()?,
            ))
        })
    }
}

/// `CachingZkArtifacts.asZkArtifactSource`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[cfg(feature = "embed-zkeys")]
#[no_mangle]
pub unsafe extern "C" fn walletkit_caching_zk_artifacts_as_zk_artifact_source(
    artifacts: CachingZkArtifactsHandle,
    out: *mut ZkArtifactSourceHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete(out, out_error, || {
            Ok(
                ops::authenticator::caching_zk_artifacts_as_zk_artifact_source(
                    artifacts.get()?,
                ),
            )
        })
    }
}

/// `CachingZkArtifacts.preload`.
///
/// # Safety
/// Arguments must follow the conventions in [`super`].
#[cfg(feature = "embed-zkeys")]
#[no_mangle]
pub unsafe extern "C" fn walletkit_caching_zk_artifacts_preload(
    artifacts: CachingZkArtifactsHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe {
        complete_unit(out_error, || {
            ops::authenticator::caching_zk_artifacts_preload(artifacts.get()?)
        })
    }
}
