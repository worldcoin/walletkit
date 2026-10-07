package org.world.walletkit

class StoragePaths internal constructor(
    internal val handle: NativeHandle,
) : AutoCloseable {
    override fun close() = handle.close()

    fun rootPathString(): String = NativeBridge.storagePathsRootPathString(handle)

    fun worldidDirPathString(): String = NativeBridge.storagePathsWorldidDirPathString(handle)

    fun vaultDbPathString(): String = NativeBridge.storagePathsVaultDbPathString(handle)

    fun cacheDbPathString(): String = NativeBridge.storagePathsCacheDbPathString(handle)

    fun lockPathString(): String = NativeBridge.storagePathsLockPathString(handle)

    fun groth16DirPathString(): String = NativeBridge.storagePathsGroth16DirPathString(handle)

    fun queryZkeyPathString(): String = NativeBridge.storagePathsQueryZkeyPathString(handle)

    fun nullifierZkeyPathString(): String = NativeBridge.storagePathsNullifierZkeyPathString(handle)

    fun queryGraphPathString(): String = NativeBridge.storagePathsQueryGraphPathString(handle)

    fun nullifierGraphPathString(): String = NativeBridge.storagePathsNullifierGraphPathString(handle)

    companion object {
        fun fromRoot(root: String): StoragePaths = StoragePaths(NativeHandle(NativeBridge.storagePathsFromRoot(root)))
    }
}
