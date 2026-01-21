package org.world.walletkit.storage

import java.io.File
import java.io.IOException
import java.util.UUID
import uniffi.walletkit_core.AtomicBlobStore
import uniffi.walletkit_core.StorageException

class AndroidAtomicBlobStore(
    private val baseDir: File
) : AtomicBlobStore {
    override fun read(path: String): ByteArray? {
        val file = File(baseDir, path)
        if (!file.exists()) {
            return null
        }
        return try {
            file.readBytes()
        } catch (error: IOException) {
            throw StorageException.BlobStore("read failed: ${error.message}")
        }
    }

    override fun writeAtomic(path: String, bytes: ByteArray) {
        val file = File(baseDir, path)
        val parent = file.parentFile
        if (parent != null && !parent.exists()) {
            parent.mkdirs()
        }
        val temp = File(
            parent ?: baseDir,
            "${file.name}.tmp-${UUID.randomUUID()}"
        )
        try {
            temp.writeBytes(bytes)
            if (file.exists() && !file.delete()) {
                throw StorageException.BlobStore("failed to remove existing file")
            }
            if (!temp.renameTo(file)) {
                temp.copyTo(file, overwrite = true)
                temp.delete()
            }
        } catch (error: Exception) {
            throw StorageException.BlobStore("write failed: ${error.message}")
        }
    }

    override fun delete(path: String) {
        val file = File(baseDir, path)
        if (!file.exists()) {
            return
        }
        if (!file.delete()) {
            throw StorageException.BlobStore("delete failed")
        }
    }
}
