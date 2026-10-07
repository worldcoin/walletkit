package org.world.walletkit

class WorldId internal constructor(
    internal val handle: NativeHandle,
) : AutoCloseable {
    override fun close() = handle.close()

    fun generateNullifierHash(context: ProofContext): Uint256 =
        Uint256.fromBytes(NativeBridge.worldIdGenerateNullifierHash(handle, context.handle))

    fun getIdentityCommitment(credentialType: CredentialType): Uint256 =
        Uint256.fromBytes(NativeBridge.worldIdGetIdentityCommitment(handle, credentialType.ordinal))

    suspend fun generateProof(context: ProofContext): ProofOutput =
        NativeCalls.async { operation -> ProofOutput(NativeHandle(NativeBridge.worldIdGenerateProof(operation, handle, context.handle))) }

    fun isEqualTo(other: WorldId): Boolean = NativeBridge.worldIdIsEqualTo(handle, other.handle)

    companion object {
        fun create(
            secret: ByteArray,
            environment: Environment,
        ): WorldId = WorldId(NativeHandle(NativeBridge.worldIdNew(secret, environment.ordinal)))
    }
}
