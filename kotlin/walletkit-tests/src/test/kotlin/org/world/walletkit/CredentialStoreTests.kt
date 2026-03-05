package org.world.walletkit

import uniffi.walletkit_core.CredentialStore
import uniffi.walletkit_core.StorageException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

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
}
