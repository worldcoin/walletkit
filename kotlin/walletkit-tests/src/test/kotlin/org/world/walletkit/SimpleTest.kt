package org.world.walletkit

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

private class MemoryStorage :
    DeviceKeystore,
    AtomicBlobStore {
    private val blobs = mutableMapOf<String, ByteArray>()

    override fun seal(
        associatedData: ByteArray,
        plaintext: ByteArray,
    ): ByteArray = associatedData + plaintext

    override fun openSealed(
        associatedData: ByteArray,
        ciphertext: ByteArray,
    ): ByteArray {
        require(ciphertext.take(associatedData.size).toByteArray().contentEquals(associatedData))
        return ciphertext.drop(associatedData.size).toByteArray()
    }

    @Synchronized override fun read(path: String): ByteArray? = blobs[path]?.copyOf()

    @Synchronized override fun writeAtomic(
        path: String,
        bytes: ByteArray,
    ) {
        blobs[path] = bytes.copyOf()
    }

    @Synchronized override fun delete(path: String) {
        blobs.remove(path)
    }
}

class SimpleTest {
    @Test fun fieldElementAndUnsignedIntegerRoundTrip() {
        FieldElement.fromU64(ULong.MAX_VALUE).use { field ->
            assertEquals(32, field.toBytes().size)
            assertContentEquals(ByteArray(8) { -1 }, field.toBytes().takeLast(8).toByteArray())
            FieldElement.fromBytes(field.toBytes()).use { restored -> assertEquals(field.toHexString(), restored.toHexString()) }
        }
        assertContentEquals(ByteArray(32) { -1 }, Uint256.fromHex("f".repeat(64)).toBytes())
        assertFails { Uint256.fromHex("-1") }
        assertFails { FieldElement.fromBytes(ByteArray(32) { -1 }) }
    }

    @Test fun storageCallbacksActivityAndReopen() {
        val root = Files.createTempDirectory("walletkit-native").toFile()
        try {
            StoragePaths.fromRoot(root.path).use { paths ->
                val host = MemoryStorage()
                CredentialStore.newWithComponents(paths, host, host).use { store ->
                    store.initialize(42u, 100u)
                    val changed = CountDownLatch(1)
                    store.setActivityChangedListener { changed.countDown() }
                    val id =
                        store.recordActivity(
                            ActivityEntry(
                                null,
                                ULong.MAX_VALUE,
                                "test",
                                "request",
                                ProtocolVersion.V4,
                                100u,
                                ActivityOutcome.COMPLETED,
                                listOf(ULong.MAX_VALUE),
                                null,
                            ),
                            100u,
                        )
                    assertTrue(changed.await(5, TimeUnit.SECONDS))
                    val activity = store.listActivities(ActivityQuery(), 10u, 0u).single()
                    assertEquals(id, activity.id)
                    assertEquals(ULong.MAX_VALUE, activity.rpId)
                    assertEquals(1uL, store.activityMetadata().totalCount)
                    assertEquals(1, store.listActivities(ActivityQuery().withIssuerSchemaId(ULong.MAX_VALUE), 10u, 0u).size)
                    assertTrue(store.listActivities(ActivityQuery(1u), 10u, 0u).isEmpty())
                }
                CredentialStore.newWithComponents(paths, host, host).use { reopened ->
                    reopened.initialize(42u, 101u)
                    assertEquals(1uL, reopened.activityMetadata().totalCount)
                }
            }
        } finally {
            assertTrue(root.deleteRecursively())
        }
    }

    @Test fun explicitCloseIsIdempotentAndRejectsNewCalls() {
        val field = FieldElement.fromU64(42u)
        field.close()
        field.close()
        assertFails { field.toHexString() }
    }

    @Test fun hostFailureIsTypedAndDoesNotExposeHostMessage() {
        val root = Files.createTempDirectory("walletkit-native-failure").toFile()
        val keystore =
            object : DeviceKeystore {
                override fun seal(
                    associatedData: ByteArray,
                    plaintext: ByteArray,
                ): ByteArray = error("private-host-message")

                override fun openSealed(
                    associatedData: ByteArray,
                    ciphertext: ByteArray,
                ): ByteArray = error("private-host-message")
            }
        try {
            StoragePaths.fromRoot(root.path).use { paths ->
                CredentialStore.newWithComponents(paths, keystore, MemoryStorage()).use { store ->
                    val failure = assertFailsWith<StorageException> { store.initialize(42u, 100u) }
                    assertFalse(failure.toString().contains("private-host-message"))
                }
            }
        } finally {
            assertTrue(root.deleteRecursively())
        }
    }

    @Test fun unpairedSurrogatesAreRejectedInsteadOfReplaced() {
        val failure = assertFailsWith<WalletKitBridgeException> { WalletKit.sanitizeHexSecrets("bad \uD800 surrogate") }
        assertEquals("InvalidInput", failure.code)
        assertEquals("zażółć 🚀", WalletKit.sanitizeHexSecrets("zażółć 🚀"))
    }

    @Test fun legacyIntegerAndEnumBindings() {
        val expected = Uint256.fromHex("2a")
        ProofContext.newFromSignalHash("app_test", null, CredentialType.ORB, expected).use { context ->
            assertEquals(expected, context.getSignalHash())
            assertEquals(CredentialType.ORB, context.getCredentialType())
            assertEquals(32, context.getExternalNullifier().toBytes().size)
        }
    }

    @Test fun measurementMapFailureRetainsDomainError() {
        FlamingoMatcher.create("https://example.invalid").use { matcher ->
            assertFailsWith<FlamingoException.Configuration> { matcher.withMeasurements(mapOf(0u to byteArrayOf(1))) }
        }
    }

    @Test fun asyncFailuresKeepTheirDomainType() =
        runBlocking<Unit> {
            val root = Files.createTempDirectory("walletkit-async-failure").toFile()
            try {
                StoragePaths.fromRoot(root.path).use { paths ->
                    val host = MemoryStorage()
                    CredentialStore.newWithComponents(paths, host, host).use { store ->
                        EmbeddedZkArtifacts.create().use { embedded ->
                            embedded.asZkArtifactSource().use { artifacts ->
                                val failure =
                                    assertFailsWith<WalletKitException> {
                                        Authenticator.initialize(ByteArray(32) { 7 }, "not json", artifacts, store)
                                    }
                                assertEquals("InvalidInput", failure.variant)
                            }
                        }
                    }
                }
            } finally {
                assertTrue(root.deleteRecursively())
            }
        }

    @Test fun cancellationBeforeStartingReleasesTheResult() =
        runBlocking<Unit> {
            val released = CompletableDeferred<Unit>()
            val job =
                launch {
                    currentCoroutineContext().cancel()
                    assertFailsWith<CancellationException> {
                        NativeCalls.async(release = { field: FieldElement ->
                            field.close()
                            released.complete(Unit)
                        }) {
                            FieldElement.fromU64(42u)
                        }
                    }
                }
            job.join()
            withTimeout(5_000) { released.await() }
        }
}
