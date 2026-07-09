package org.world.walletkit

import uniffi.walletkit_core.AtomicBlobStore
import uniffi.walletkit_core.Credential
import uniffi.walletkit_core.CredentialStore
import uniffi.walletkit_core.DeviceKeystore
import uniffi.walletkit_core.FieldElement
import uniffi.walletkit_core.StorageException
import uniffi.walletkit_core.StoragePaths
import uniffi.walletkit_core.StorageProvider
import java.io.File
import java.security.SecureRandom
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class AtomicBlobStoreTests {
    @Test
    fun writeReadDelete() {
        val root = tempDirectory()
        val store = FileBlobStore(root)
        val path = "account_keys.bin"
        val payload = byteArrayOf(1, 2, 3, 4)

        store.writeAtomic(path, payload)
        val readBack = store.read(path)
        assertEquals(payload.toList(), readBack?.toList())

        store.delete(path)
        assertNull(store.read(path))

        root.deleteRecursively()
    }
}

class CredentialStoreTests {
    @Test
    fun methodsRequireInit() {
        val root = tempDirectory()
        val provider = InMemoryStorageProvider(root)
        val store = CredentialStore.fromProviderArc(provider)

        assertFailsWith<StorageException.NotInitialized> {
            store.listCredentials(issuerSchemaId = null, now = 100UL)
        }
        assertFailsWith<StorageException.NotInitialized> {
            store.merkleCacheGet(validUntil = 100UL)
        }

        root.deleteRecursively()
    }

    @Test
    fun storeAndCacheFlows() {
        val root = tempDirectory()
        val provider = InMemoryStorageProvider(root)
        val store = CredentialStore.fromProviderArc(provider)

        store.`init`(leafIndex = 42UL, now = 100UL)
        assertNull(store.merkleCacheGet(validUntil = 100UL))

        val credentialId =
            store.storeCredential(
                credential = sampleCredential(),
                blindingFactor = sampleBlindingFactor(),
                expiresAt = 1_800_000_000UL,
                associatedData = byteArrayOf(4, 5, 6),
                now = 100UL,
            )

        val records = store.listCredentials(issuerSchemaId = null, now = 101UL)
        assertEquals(1, records.size)
        val record = records[0]
        assertEquals(credentialId, record.credentialId)
        assertEquals(7UL, record.issuerSchemaId)
        assertEquals(1_800_000_000UL, record.expiresAt)

        val proofBytes = byteArrayOf(9, 9, 9)
        store.merkleCachePut(
            proofBytes = proofBytes,
            now = 100UL,
            ttlSeconds = 60UL,
        )
        val cached =
            store.merkleCacheGet(
                validUntil = 110UL,
            )
        assertContentEquals(proofBytes, assertNotNull(cached))
        val expired = store.merkleCacheGet(validUntil = 161UL)
        assertNull(expired)

        root.deleteRecursively()
    }

    @Test
    fun reopenPersistsVaultAndCache() {
        val root = tempDirectory()
        val keyBytes = randomKeystoreKeyBytes()
        val firstStore =
            CredentialStore.fromProviderArc(
                InMemoryStorageProvider(root, InMemoryDeviceKeystore(keyBytes)),
            )

        firstStore.`init`(leafIndex = 42UL, now = 100UL)
        val credentialId =
            firstStore.storeCredential(
                credential = sampleCredential(),
                blindingFactor = sampleBlindingFactor(),
                expiresAt = 1_800_000_000UL,
                associatedData = null,
                now = 100UL,
            )
        val proofBytes = byteArrayOf(9, 9, 9)
        firstStore.merkleCachePut(
            proofBytes = proofBytes,
            now = 100UL,
            ttlSeconds = 60UL,
        )

        val reopenedStore =
            CredentialStore.fromProviderArc(
                InMemoryStorageProvider(root, InMemoryDeviceKeystore(keyBytes)),
            )
        reopenedStore.`init`(leafIndex = 42UL, now = 101UL)

        val records = reopenedStore.listCredentials(issuerSchemaId = null, now = 102UL)
        assertEquals(1, records.size)
        assertEquals(credentialId, records.single().credentialId)
        assertContentEquals(proofBytes, assertNotNull(reopenedStore.merkleCacheGet(validUntil = 120UL)))

        root.deleteRecursively()
    }
}

class DeviceKeystoreTests {
    @Test
    fun sealAndOpenRoundTrip() {
        val keystore = InMemoryDeviceKeystore()
        val associatedData = "ad".encodeToByteArray()
        val plaintext = "hello".encodeToByteArray()

        val ciphertext = keystore.seal(associatedData, plaintext)
        val opened = keystore.openSealed(associatedData, ciphertext)

        assertTrue(opened.contentEquals(plaintext))
    }

    @Test
    fun associatedDataMismatchFails() {
        val keystore = InMemoryDeviceKeystore()
        val plaintext = "secret".encodeToByteArray()
        val ciphertext = keystore.seal("ad-1".encodeToByteArray(), plaintext)

        assertFails {
            keystore.openSealed("ad-2".encodeToByteArray(), ciphertext)
        }
    }

    @Test
    fun reopenWithSameKeyMaterialCanOpenCiphertext() {
        val keyBytes = randomKeystoreKeyBytes()
        val firstKeystore = InMemoryDeviceKeystore(keyBytes)
        val secondKeystore = InMemoryDeviceKeystore(keyBytes)
        val associatedData = "ad".encodeToByteArray()
        val plaintext = "hello".encodeToByteArray()

        val ciphertext = firstKeystore.seal(associatedData, plaintext)
        val opened = secondKeystore.openSealed(associatedData, ciphertext)

        assertTrue(opened.contentEquals(plaintext))
    }
}

fun tempDirectory(): File {
    val dir = File(System.getProperty("java.io.tmpdir"), "walletkit-tests-${UUID.randomUUID()}")
    dir.mkdirs()
    return dir
}

fun randomKeystoreKeyBytes(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

fun sampleCredential(
    issuerSchemaId: ULong = 7UL,
    expiresAt: ULong = 1_800_000_000UL,
): Credential {
    val credentialJson =
        """
        {"id":13758530325042616850,"version":"V1","issuer_schema_id":$issuerSchemaId,"sub":"0x114edc9e30c245ac8e1f98375f71668a9cd4e9f1e3e9b3385a1801e9d43d731b","genesis_issued_at":1700000000,"expires_at":$expiresAt,"claims":["0x0000000000000000000000000000000000000000000000000000000000000000","0x0000000000000000000000000000000000000000000000000000000000000000","0x0000000000000000000000000000000000000000000000000000000000000000","0x0000000000000000000000000000000000000000000000000000000000000000","0x0000000000000000000000000000000000000000000000000000000000000000","0x0000000000000000000000000000000000000000000000000000000000000000","0x0000000000000000000000000000000000000000000000000000000000000000","0x0000000000000000000000000000000000000000000000000000000000000000","0x0000000000000000000000000000000000000000000000000000000000000000","0x0000000000000000000000000000000000000000000000000000000000000000","0x0000000000000000000000000000000000000000000000000000000000000000","0x0000000000000000000000000000000000000000000000000000000000000000","0x0000000000000000000000000000000000000000000000000000000000000000","0x0000000000000000000000000000000000000000000000000000000000000000","0x0000000000000000000000000000000000000000000000000000000000000000","0x0000000000000000000000000000000000000000000000000000000000000000"],"associated_data_hash":"0x0000000000000000000000000000000000000000000000000000000000000000","signature":null,"issuer":"0100000000000000000000000000000000000000000000000000000000000000"}
        """.trimIndent()
    return Credential.fromBytes(credentialJson.encodeToByteArray())
}

fun sampleBlindingFactor(): FieldElement = FieldElement.fromU64(17UL)

class InMemoryDeviceKeystore(
    keyBytes: ByteArray = randomKeystoreKeyBytes(),
) : DeviceKeystore {
    private val keyBytes = keyBytes.copyOf()

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
    private val keystoreImpl: DeviceKeystore = InMemoryDeviceKeystore(),
) : StorageProvider {
    private val blobStore = FileBlobStore(File(root, "worldid"))
    private val paths = StoragePaths.fromRoot(root.absolutePath)

    override fun keystore(): DeviceKeystore = keystoreImpl

    override fun blobStore(): AtomicBlobStore = blobStore

    override fun paths(): StoragePaths = paths
}
