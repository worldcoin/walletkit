package org.world.walletkit

import uniffi.walletkit_core.AtomicBlobStore
import uniffi.walletkit_core.DeviceKeystore
import uniffi.walletkit_core.StorageException
import uniffi.walletkit_core.StoragePaths
import uniffi.walletkit_core.StorageProvider
import java.io.File
import java.security.SecureRandom
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

fun tempDirectory(): File {
    val dir = File(System.getProperty("java.io.tmpdir"), "walletkit-tests-${UUID.randomUUID()}")
    dir.mkdirs()
    return dir
}

class InMemoryDeviceKeystore : DeviceKeystore {
    private val keyBytes = ByteArray(32).also { SecureRandom().nextBytes(it) }

    override fun seal(
        associatedData: ByteArray,
        plaintext: ByteArray,
    ): ByteArray =
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val key = SecretKeySpec(keyBytes, "AES")
            cipher.init(Cipher.ENCRYPT_MODE, key)
            cipher.updateAAD(associatedData)
            val ciphertext = cipher.doFinal(plaintext)
            val iv = cipher.iv
            val output = ByteArray(1 + iv.size + ciphertext.size)
            output[0] = iv.size.toByte()
            System.arraycopy(iv, 0, output, 1, iv.size)
            System.arraycopy(ciphertext, 0, output, 1 + iv.size, ciphertext.size)
            output
        } catch (error: Exception) {
            throw StorageException.Keystore("keystore seal failed: ${error.message}")
        }

    override fun openSealed(
        associatedData: ByteArray,
        ciphertext: ByteArray,
    ): ByteArray {
        if (ciphertext.isEmpty()) {
            throw StorageException.Keystore("keystore ciphertext is empty")
        }
        val ivLen = ciphertext[0].toInt() and 0xFF
        if (ciphertext.size < 1 + ivLen) {
            throw StorageException.Keystore("keystore ciphertext too short")
        }
        return try {
            val iv = ciphertext.copyOfRange(1, 1 + ivLen)
            val payload = ciphertext.copyOfRange(1 + ivLen, ciphertext.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val key = SecretKeySpec(keyBytes, "AES")
            val spec = GCMParameterSpec(128, iv)
            cipher.init(Cipher.DECRYPT_MODE, key, spec)
            cipher.updateAAD(associatedData)
            cipher.doFinal(payload)
        } catch (error: Exception) {
            throw StorageException.Keystore("keystore open failed: ${error.message}")
        }
    }
}

class FileBlobStore(
    private val baseDir: File,
) : AtomicBlobStore {
    override fun read(path: String): ByteArray? {
        val file = File(baseDir, path)
        return if (file.exists()) file.readBytes() else null
    }

    override fun writeAtomic(
        path: String,
        bytes: ByteArray,
    ) {
        val file = File(baseDir, path)
        file.parentFile?.mkdirs()
        val temp = File(file.parentFile ?: baseDir, "${file.name}.tmp-${UUID.randomUUID()}")
        temp.writeBytes(bytes)
        if (file.exists()) {
            file.delete()
        }
        if (!temp.renameTo(file)) {
            temp.copyTo(file, overwrite = true)
            temp.delete()
        }
    }

    override fun delete(path: String) {
        val file = File(baseDir, path)
        if (file.exists() && !file.delete()) {
            throw StorageException.BlobStore("delete failed")
        }
    }
}

class InMemoryStorageProvider(
    private val root: File,
) : StorageProvider {
    private val keystore = InMemoryDeviceKeystore()
    private val blobStore = FileBlobStore(File(root, "worldid"))
    private val paths = StoragePaths.fromRoot(root.absolutePath)

    override fun keystore(): DeviceKeystore = keystore

    override fun blobStore(): AtomicBlobStore = blobStore

    override fun paths(): StoragePaths = paths
}
