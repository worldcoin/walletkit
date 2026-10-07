package org.world.walletkit

class WalletKitZkArtifactSource internal constructor(
    internal val handle: NativeHandle,
) : AutoCloseable {
    override fun close() = handle.close()
}
