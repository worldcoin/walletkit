package org.world.walletkit

class ProofRequest internal constructor(
    internal val handle: NativeHandle,
) : AutoCloseable {
    override fun close() = handle.close()

    fun toJson(): String = NativeBridge.proofRequestToJson(handle)

    fun id(): String = NativeBridge.proofRequestId(handle)

    fun version(): UByte = NativeBridge.proofRequestVersion(handle).toUByte()

    companion object {
        fun fromJson(json: String): ProofRequest = ProofRequest(NativeHandle(NativeBridge.proofRequestFromJson(json)))
    }
}
