package org.world.walletkit.storage

import android.content.Context
import java.io.File
import uniffi.walletkit_core.AtomicBlobStore
import uniffi.walletkit_core.DeviceKeystore
import uniffi.walletkit_core.StoragePaths
import uniffi.walletkit_core.StorageProvider
import uniffi.walletkit_core.StorageException

class AndroidStorageProvider(
    private val rootDir: File,
    private val keystoreImpl: AndroidDeviceKeystore = AndroidDeviceKeystore(),
    private val blobStoreImpl: AndroidAtomicBlobStore =
        AndroidAtomicBlobStore(File(rootDir, "worldid"))
) : StorageProvider {
    private val pathsImpl: StoragePaths = StoragePaths.fromRoot(rootDir.absolutePath)

    init {
        val worldidDir = File(rootDir, "worldid")
        if (!worldidDir.exists() && !worldidDir.mkdirs()) {
            throw StorageException.BlobStore("failed to create storage directory")
        }
    }

    override fun keystore(): DeviceKeystore = keystoreImpl

    override fun blobStore(): AtomicBlobStore = blobStoreImpl

    override fun paths(): StoragePaths = pathsImpl
}

object WalletKitStorage {
    fun defaultProvider(context: Context): AndroidStorageProvider {
        val root = File(context.filesDir, "walletkit")
        return AndroidStorageProvider(root)
    }
}
