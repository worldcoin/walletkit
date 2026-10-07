package org.world.walletkit

class UserAgent internal constructor(
    internal val handle: NativeHandle,
) : AutoCloseable {
    override fun close() = handle.close()

    fun headerValue(): String = NativeBridge.userAgentHeaderValue(handle)
}
