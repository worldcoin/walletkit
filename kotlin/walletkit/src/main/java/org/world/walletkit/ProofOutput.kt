package org.world.walletkit

class ProofOutput internal constructor(
    internal val handle: NativeHandle,
) : AutoCloseable {
    override fun close() = handle.close()

    fun toJson(): String = NativeBridge.proofOutputToJson(handle)

    fun getNullifierHash(): Uint256 = Uint256.fromBytes(NativeBridge.proofOutputGetNullifierHash(handle))

    fun getMerkleRoot(): Uint256 = Uint256.fromBytes(NativeBridge.proofOutputGetMerkleRoot(handle))

    fun getProofAsString(): String = NativeBridge.proofOutputGetProofAsString(handle)

    fun getCredentialType(): CredentialType = CredentialType.entries[NativeBridge.proofOutputGetCredentialType(handle)]
}
