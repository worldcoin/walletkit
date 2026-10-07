package org.world.walletkit

class VerifiedMatchToken internal constructor(
    internal val handle: NativeHandle,
) : AutoCloseable {
    override fun close() = handle.close()

    fun matchCoefficient(): Float = NativeBridge.verifiedMatchTokenMatchCoefficient(handle)
}
