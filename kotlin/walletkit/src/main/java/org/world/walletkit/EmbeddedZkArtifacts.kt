package org.world.walletkit

class EmbeddedZkArtifacts internal constructor(
    internal val handle: NativeHandle,
) : AutoCloseable {
    override fun close() = handle.close()

    fun asZkArtifactSource(): WalletKitZkArtifactSource =
        WalletKitZkArtifactSource(NativeHandle(NativeBridge.embeddedZkArtifactsAsZkArtifactSource(handle)))

    companion object {
        fun create(): EmbeddedZkArtifacts = EmbeddedZkArtifacts(NativeHandle(NativeBridge.embeddedZkArtifactsNew()))
    }
}
