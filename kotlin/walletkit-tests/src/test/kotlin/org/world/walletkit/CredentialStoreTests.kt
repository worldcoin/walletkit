package org.world.walletkit

import uniffi.walletkit_core.CredentialStatus
import uniffi.walletkit_core.CredentialStore
import uniffi.walletkit_core.ProofDisclosureKind
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class CredentialStoreTests {
    @Test
    fun storeAndCacheFlows() {
        val root = tempDirectory()
        val provider = InMemoryStorageProvider(root)
        val store = CredentialStore.fromProviderArc(provider)

        store.`init`(leafIndex = 42UL, now = 100UL)

        val credentialId =
            store.storeCredential(
                issuerSchemaId = 7UL,
                status = CredentialStatus.ACTIVE,
                subjectBlindingFactor = ByteArray(32) { 0x11.toByte() },
                genesisIssuedAt = 1_700_000_000UL,
                expiresAt = 1_800_000_000UL,
                credentialBlob = byteArrayOf(1, 2, 3),
                associatedData = byteArrayOf(4, 5, 6),
                now = 100UL,
            )
        assertEquals(16, credentialId.size)

        val records = store.listCredentials(issuerSchemaId = null, now = 101UL)
        assertEquals(1, records.size)
        val record = records[0]
        assertEquals(7UL, record.issuerSchemaId)
        assertEquals(32, record.subjectBlindingFactor.size)

        val rootHash = ByteArray(32) { 0x22.toByte() }
        val proofBytes = byteArrayOf(9, 9, 9)
        store.merkleCachePut(
            registryKind = 1u.toUByte(),
            root = rootHash,
            proofBytes = proofBytes,
            now = 100UL,
            ttlSeconds = 60UL,
        )
        val cached =
            store.merkleCacheGet(
                registryKind = 1u.toUByte(),
                root = rootHash,
                now = 110UL,
            )
        assertEquals(proofBytes.toList(), cached?.toList())

        val requestId = ByteArray(32) { 0x01.toByte() }
        val nullifier = ByteArray(32) { 0x02.toByte() }
        val first =
            store.beginProofDisclosure(
                requestId = requestId,
                nullifier = nullifier,
                proofBytes = byteArrayOf(7, 7),
                now = 120UL,
                ttlSeconds = 60UL,
            )
        assertEquals(ProofDisclosureKind.FRESH, first.kind)

        val replay =
            store.beginProofDisclosure(
                requestId = requestId,
                nullifier = nullifier,
                proofBytes = byteArrayOf(8, 8),
                now = 130UL,
                ttlSeconds = 60UL,
            )
        assertEquals(ProofDisclosureKind.REPLAY, replay.kind)

        root.deleteRecursively()
    }
}
