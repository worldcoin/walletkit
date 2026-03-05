package org.world.walletkit

import uniffi.walletkit_core.CredentialStore
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class CredentialStoreTests {
    @Test
    fun storeAndCacheFlows() {
        val root = tempDirectory()
        val provider = InMemoryStorageProvider(root)
        val store = CredentialStore.fromProviderArc(provider)

        store.`init`(leafIndex = 42UL, now = 100UL)

        val credentialId =
            store.storeCredential(
                credential = sampleCredential(),
                blindingFactor = sampleBlindingFactor(),
                expiresAt = 1_800_000_000UL,
                associatedData = byteArrayOf(4, 5, 6),
                now = 100UL,
            )
        assertEquals(1UL, credentialId)

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
}
