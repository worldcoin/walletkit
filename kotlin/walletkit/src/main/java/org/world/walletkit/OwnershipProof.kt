package org.world.walletkit

class OwnershipProof internal constructor(
    internal val handle: NativeHandle,
) : AutoCloseable {
    override fun close() = handle.close()

    fun encode(): ByteArray = NativeBridge.ownershipProofEncode(handle)

    fun encodeB64(): String = NativeBridge.ownershipProofEncodeB64(handle)

    fun merkleRoot(): FieldElement = FieldElement(NativeHandle(NativeBridge.ownershipProofMerkleRoot(handle)))
}
