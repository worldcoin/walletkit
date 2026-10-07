package org.world.walletkit

class CachingZkArtifacts internal constructor(
    internal val handle: NativeHandle,
) : AutoCloseable {
    override fun close() = handle.close()

    fun asZkArtifactSource(): WalletKitZkArtifactSource =
        WalletKitZkArtifactSource(NativeHandle(NativeBridge.cachingZkArtifactsAsZkArtifactSource(handle)))

    fun preload(): Unit = NativeBridge.cachingZkArtifactsPreload(handle)

    companion object {
        fun create(storagePaths: StoragePaths): CachingZkArtifacts =
            CachingZkArtifacts(NativeHandle(NativeBridge.cachingZkArtifactsNew(storagePaths.handle)))
    }
}
