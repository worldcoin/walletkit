package org.world.walletkit

class ProofResponse internal constructor(
    internal val handle: NativeHandle,
) : AutoCloseable {
    override fun close() = handle.close()

    fun toJson(): String = NativeBridge.proofResponseToJson(handle)

    fun id(): String = NativeBridge.proofResponseId(handle)

    fun version(): UByte = NativeBridge.proofResponseVersion(handle).toUByte()

    fun error(): String? = NativeBridge.proofResponseError(handle)
}
