package org.world.walletkit

class Authenticator internal constructor(
    internal val handle: NativeHandle,
) : AutoCloseable {
    override fun close() = handle.close()

    fun initStorage(now: ULong): Unit = NativeBridge.authenticatorInitStorage(handle, now.toLong())

    /** Deletes the key envelope, vault, and cache. The store becomes uninitialized. Use only for logout or account deletion. */
    fun destroyStorage(): Unit = NativeBridge.authenticatorDestroyStorage(handle)

    fun packedAccountData(): Uint256 = Uint256.fromBytes(NativeBridge.authenticatorPackedAccountData(handle))

    fun leafIndex(): ULong = NativeBridge.authenticatorLeafIndex(handle).toULong()

    fun onchainAddress(): String = NativeBridge.authenticatorOnchainAddress(handle)

    suspend fun getPackedAccountDataRemote(): Uint256 =
        NativeCalls.async { operation -> Uint256.fromBytes(NativeBridge.authenticatorGetPackedAccountDataRemote(operation, handle)) }

    suspend fun generateCredentialBlindingFactorRemote(issuerSchemaId: ULong): FieldElement =
        NativeCalls.async { operation ->
            FieldElement(
                NativeHandle(NativeBridge.authenticatorGenerateCredentialBlindingFactorRemote(operation, handle, issuerSchemaId.toLong())),
            )
        }

    fun computeCredentialSub(blindingFactor: FieldElement): FieldElement =
        FieldElement(NativeHandle(NativeBridge.authenticatorComputeCredentialSub(handle, blindingFactor.handle)))

    /** Signs with the on-chain key and reveals the user’s identity/leaf index. Use only to prove ownership to the trusted recovery agent. */
    fun dangerSignChallenge(challenge: ByteArray): ByteArray = NativeBridge.authenticatorDangerSignChallenge(handle, challenge)

    /** Signs a recovery-agent update. Only use with an explicitly authorized, validated recovery-agent address. */
    suspend fun dangerSignInitiateRecoveryAgentUpdate(newRecoveryAgent: String): RecoveryUpdateSignature =
        NativeCalls.async { operation ->
            NativeReader.decode(NativeBridge.authenticatorDangerSignInitiateRecoveryAgentUpdate(operation, handle, newRecoveryAgent)) {
                readRecoveryUpdateSignature()
            }
        }

    suspend fun updateRecoveryAgent(newRecoveryAgent: String): String =
        NativeCalls.async { operation -> NativeBridge.authenticatorUpdateRecoveryAgent(operation, handle, newRecoveryAgent) }

    suspend fun revertRecoveryAgentUpdate(): String =
        NativeCalls.async { operation -> NativeBridge.authenticatorRevertRecoveryAgentUpdate(operation, handle) }

    suspend fun insertAuthenticator(
        newAuthenticatorPubkey: String,
        newAuthenticatorAddress: String,
    ): String =
        NativeCalls.async { operation ->
            NativeBridge.authenticatorInsertAuthenticator(operation, handle, newAuthenticatorPubkey, newAuthenticatorAddress)
        }

    suspend fun hasAuthenticatorPubkey(authenticatorPubkey: String): Boolean =
        NativeCalls.async { operation -> NativeBridge.authenticatorHasAuthenticatorPubkey(operation, handle, authenticatorPubkey) }

    suspend fun getAuthenticatorPubkeys(): List<String?> =
        NativeCalls.async { operation ->
            NativeReader.decode(NativeBridge.authenticatorGetAuthenticatorPubkeys(operation, handle)) { list { optional { string() } } }
        }

    suspend fun removeAuthenticator(
        authenticatorAddress: String,
        pubkeyId: UInt,
        expectedAuthenticatorPubkey: String,
    ): String =
        NativeCalls.async { operation ->
            NativeBridge.authenticatorRemoveAuthenticator(
                operation,
                handle,
                authenticatorAddress,
                pubkeyId.toInt(),
                expectedAuthenticatorPubkey,
            )
        }

    suspend fun pollStatus(requestId: String): GatewayRequestStatus =
        NativeCalls.async { operation ->
            NativeReader.decode(NativeBridge.authenticatorPollStatus(operation, handle, requestId)) { readGatewayRequestStatus() }
        }

    suspend fun generateProof(
        proofRequest: ProofRequest,
        now: ULong?,
    ): ProofResponse =
        NativeCalls.async { operation ->
            ProofResponse(NativeHandle(NativeBridge.authenticatorGenerateProof(operation, handle, proofRequest.handle, now?.toLong())))
        }

    suspend fun proveCredentialSub(
        nonce: FieldElement,
        context: FieldElement,
        blindingFactor: FieldElement,
        sub: FieldElement,
    ): OwnershipProof =
        NativeCalls.async { operation ->
            OwnershipProof(
                NativeHandle(
                    NativeBridge.authenticatorProveCredentialSub(
                        operation,
                        handle,
                        nonce.handle,
                        context.handle,
                        blindingFactor.handle,
                        sub.handle,
                    ),
                ),
            )
        }

    companion object {
        suspend fun initWithDefaults(
            seed: ByteArray,
            rpcUrl: String?,
            environment: Environment,
            region: Region?,
            artifacts: WalletKitZkArtifactSource,
            store: CredentialStore,
        ): Authenticator =
            NativeCalls.async { operation ->
                Authenticator(
                    NativeHandle(
                        NativeBridge.authenticatorInitWithDefaults(
                            operation,
                            seed,
                            rpcUrl,
                            environment.ordinal,
                            region?.ordinal ?: -1,
                            artifacts.handle,
                            store.handle,
                        ),
                    ),
                )
            }

        suspend fun initWithOhttpDefaults(
            seed: ByteArray,
            rpcUrl: String?,
            environment: Environment,
            region: Region?,
            artifacts: WalletKitZkArtifactSource,
            store: CredentialStore,
        ): Authenticator =
            NativeCalls.async { operation ->
                Authenticator(
                    NativeHandle(
                        NativeBridge.authenticatorInitWithOhttpDefaults(
                            operation,
                            seed,
                            rpcUrl,
                            environment.ordinal,
                            region?.ordinal ?: -1,
                            artifacts.handle,
                            store.handle,
                        ),
                    ),
                )
            }

        suspend fun initialize(
            seed: ByteArray,
            config: String,
            artifacts: WalletKitZkArtifactSource,
            store: CredentialStore,
        ): Authenticator =
            NativeCalls.async { operation ->
                Authenticator(NativeHandle(NativeBridge.authenticatorInit(operation, seed, config, artifacts.handle, store.handle)))
            }
    }
}
