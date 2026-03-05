package org.world.walletkit

import uniffi.walletkit_core.CredentialStore
import uniffi.walletkit_core.StorageException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

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
    fun initRejectsLeafIndexMismatch() {
        val root = tempDirectory()
        val provider = InMemoryStorageProvider(root)
        val store = CredentialStore.fromProviderArc(provider)

        store.`init`(leafIndex = 42UL, now = 100UL)
        val error =
            assertFailsWith<StorageException.InvalidLeafIndex> {
                store.`init`(leafIndex = 43UL, now = 101UL)
            }
        assertEquals(42UL, error.`expected`)
        assertEquals(43UL, error.`provided`)

        root.deleteRecursively()
    }

    @Test
    fun initIsIdempotentForSameLeafIndex() {
        val root = tempDirectory()
        val provider = InMemoryStorageProvider(root)
        val store = CredentialStore.fromProviderArc(provider)

        store.`init`(leafIndex = 42UL, now = 100UL)
        val credentialId =
            store.storeCredential(
                credential = sampleCredential(),
                blindingFactor = sampleBlindingFactor(),
                expiresAt = 1_800_000_000UL,
                associatedData = null,
                now = 100UL,
            )

        store.`init`(leafIndex = 42UL, now = 101UL)

        val records = store.listCredentials(issuerSchemaId = null, now = 102UL)
        assertEquals(1, records.size)
        assertEquals(credentialId, records.single().credentialId)

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
        assertEquals(proofBytes.toList(), cached?.toList())
        val expired = store.merkleCacheGet(validUntil = 161UL)
        assertNull(expired)

        root.deleteRecursively()
    }

    @Test
    fun storeCredentialReturnsStableDistinctIds() {
        val root = tempDirectory()
        val provider = InMemoryStorageProvider(root)
        val store = CredentialStore.fromProviderArc(provider)

        store.`init`(leafIndex = 42UL, now = 100UL)
        val firstCredentialId =
            store.storeCredential(
                credential = sampleCredential(issuerSchemaId = 7UL, expiresAt = 1_800_000_000UL),
                blindingFactor = sampleBlindingFactor(),
                expiresAt = 1_800_000_000UL,
                associatedData = null,
                now = 100UL,
            )
        val secondCredentialId =
            store.storeCredential(
                credential = sampleCredential(issuerSchemaId = 8UL, expiresAt = 1_900_000_000UL),
                blindingFactor = sampleBlindingFactor(),
                expiresAt = 1_900_000_000UL,
                associatedData = null,
                now = 101UL,
            )

        assertNotEquals(firstCredentialId, secondCredentialId)

        val records = store.listCredentials(issuerSchemaId = null, now = 102UL)
        assertEquals(2, records.size)
        assertEquals(
            setOf(firstCredentialId, secondCredentialId),
            records.map { it.credentialId }.toSet(),
        )

        root.deleteRecursively()
    }

    @Test
    fun listCredentialsFiltersByIssuerSchemaId() {
        val root = tempDirectory()
        val provider = InMemoryStorageProvider(root)
        val store = CredentialStore.fromProviderArc(provider)

        store.`init`(leafIndex = 42UL, now = 100UL)
        store.storeCredential(
            credential = sampleCredential(issuerSchemaId = 7UL),
            blindingFactor = sampleBlindingFactor(),
            expiresAt = 1_800_000_000UL,
            associatedData = null,
            now = 100UL,
        )
        store.storeCredential(
            credential = sampleCredential(issuerSchemaId = 8UL, expiresAt = 1_900_000_000UL),
            blindingFactor = sampleBlindingFactor(),
            expiresAt = 1_900_000_000UL,
            associatedData = null,
            now = 101UL,
        )

        val filtered = store.listCredentials(issuerSchemaId = 7UL, now = 102UL)
        assertEquals(1, filtered.size)
        assertEquals(7UL, filtered.single().issuerSchemaId)

        root.deleteRecursively()
    }

    @Test
    fun expiredCredentialsAreFilteredOut() {
        val root = tempDirectory()
        val provider = InMemoryStorageProvider(root)
        val store = CredentialStore.fromProviderArc(provider)

        store.`init`(leafIndex = 42UL, now = 100UL)
        store.storeCredential(
            credential = sampleCredential(issuerSchemaId = 7UL, expiresAt = 120UL),
            blindingFactor = sampleBlindingFactor(),
            expiresAt = 120UL,
            associatedData = null,
            now = 100UL,
        )
        store.storeCredential(
            credential = sampleCredential(issuerSchemaId = 8UL, expiresAt = 1_800_000_000UL),
            blindingFactor = sampleBlindingFactor(),
            expiresAt = 1_800_000_000UL,
            associatedData = null,
            now = 101UL,
        )

        val records = store.listCredentials(issuerSchemaId = null, now = 121UL)
        assertEquals(1, records.size)
        assertEquals(8UL, records.single().issuerSchemaId)

        root.deleteRecursively()
    }

    @Test
    fun storagePathsMatchWorldIdLayout() {
        val root = tempDirectory()
        val provider = InMemoryStorageProvider(root)
        val store = CredentialStore.fromProviderArc(provider)

        val paths = store.storagePaths()
        assertEquals(root.absolutePath, paths.rootPathString())
        assertTrue(paths.worldidDirPathString().endsWith("/worldid"))
        assertTrue(paths.vaultDbPathString().endsWith("/worldid/account.vault.sqlite"))
        assertTrue(paths.cacheDbPathString().endsWith("/worldid/account.cache.sqlite"))
        assertTrue(paths.lockPathString().endsWith("/worldid/lock"))

        root.deleteRecursively()
    }

    @Test
    fun merkleCachePutRefreshesExistingEntry() {
        val root = tempDirectory()
        val provider = InMemoryStorageProvider(root)
        val store = CredentialStore.fromProviderArc(provider)

        store.`init`(leafIndex = 42UL, now = 100UL)
        val firstProof = byteArrayOf(1, 2, 3)
        val refreshedProof = byteArrayOf(4, 5, 6)
        store.merkleCachePut(
            proofBytes = firstProof,
            now = 100UL,
            ttlSeconds = 10UL,
        )
        store.merkleCachePut(
            proofBytes = refreshedProof,
            now = 101UL,
            ttlSeconds = 60UL,
        )

        val cached = store.merkleCacheGet(validUntil = 120UL)
        assertContentEquals(refreshedProof, cached)

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
        assertContentEquals(proofBytes, reopenedStore.merkleCacheGet(validUntil = 120UL))

        root.deleteRecursively()
    }
}
