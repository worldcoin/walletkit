package org.world.walletkit

import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import java.nio.file.Files
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.test.fail

class CallbackTest {
    private class Storage(
        private val sealFailure: Exception? = null,
    ) : DeviceKeystore,
        AtomicBlobStore {
        private val blobs = mutableMapOf<String, ByteArray>()

        override fun seal(
            associatedData: ByteArray,
            plaintext: ByteArray,
        ): ByteArray = sealFailure?.let { throw it } ?: (associatedData + plaintext)

        override fun openSealed(
            associatedData: ByteArray,
            ciphertext: ByteArray,
        ): ByteArray = ciphertext.copyOfRange(associatedData.size, ciphertext.size)

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

    private fun withStore(
        host: Storage = Storage(),
        body: (CredentialStore) -> Unit,
    ) {
        val root = Files.createTempDirectory("walletkit-callbacks").toFile()
        try {
            StoragePaths.fromRoot(root.path).use { paths -> CredentialStore.newWithComponents(paths, host, host).use(body) }
        } finally {
            assertTrue(root.deleteRecursively())
        }
    }

    @Test fun activityRecordsRoundTripThroughBinaryEncoding() =
        withStore { store ->
            store.initialize(42u, 100u)
            val entries =
                listOf(
                    ActivityEntry(
                        null,
                        ULong.MAX_VALUE,
                        "zażółć 🚀",
                        "",
                        ProtocolVersion.V3,
                        null,
                        ActivityOutcome.FAILED,
                        listOf(ULong.MAX_VALUE, 0uL),
                        ActivityFailureReason.RELYING_PARTY_REJECTED,
                    ),
                    ActivityEntry(null, 1u, "app", "request", ProtocolVersion.V4, 100u, ActivityOutcome.INCOMPLETE, emptyList(), null),
                )
            val ids = entries.map { store.recordActivity(it, 100u) }

            fun ActivityEntry.normalized() = copy(issuerSchemaIds = issuerSchemaIds.sorted())
            assertEquals(
                entries.zip(ids).map { (entry, id) -> entry.copy(id = id, timestamp = entry.timestamp ?: 100u).normalized() }.toSet(),
                store.listActivities(ActivityQuery(), 10u, 0u).map { it.normalized() }.toSet(),
            )
            assertEquals(1, store.listActivities(ActivityQuery(0u), 10u, 0u).size)
            assertTrue(store.listActivities(ActivityQuery(), 10u, 2u).isEmpty())
            assertEquals(2uL, store.clearActivities())
        }

    @Test fun hostStorageExceptionKeepsItsVariant() =
        withStore(Storage(StorageException.Keystore("denied"))) { store ->
            assertFailsWith<StorageException.Keystore> { store.initialize(42u, 100u) }
        }

    @Test fun listenersRunOnNativeDaemonThreads() =
        withStore { store ->
            store.initialize(42u, 100u)
            val activity = CountDownLatch(2)
            val threads = CopyOnWriteArrayList<Thread>()
            store.setVaultChangedListener { fail("no vault change expected") }
            store.setActivityChangedListener {
                threads.add(Thread.currentThread())
                activity.countDown()
            }
            val entry = ActivityEntry(null, 1u, "app", "id", ProtocolVersion.V4, 1u, ActivityOutcome.COMPLETED, emptyList(), null)
            store.recordActivity(entry, 100u)
            store.recordActivity(entry, 101u)
            assertTrue(activity.await(5, TimeUnit.SECONDS))
            assertTrue(threads.all { it.isDaemon }, "native threads attach as daemons")
            assertEquals(1, threads.toSet().size, "the notification thread stays attached")
            store.importVaultFromBackup(store.exportVaultForBackup())
        }

    @Test fun loggerReceivesRustLogsOnAttachedThreads() {
        val messages = CopyOnWriteArrayList<Pair<LogLevel, String>>()
        val received = CountDownLatch(1)
        WalletKit.initLogging(
            object : Logger {
                override fun log(
                    level: LogLevel,
                    message: String,
                ) {
                    messages.add(level to message)
                    if (message.contains("typed-logger-check")) received.countDown()
                }
            },
            LogLevel.TRACE,
        )
        WalletKit.emitLog(LogLevel.WARN, "typed-logger-check")
        assertTrue(received.await(5, TimeUnit.SECONDS))
        assertTrue(messages.any { (level, message) -> level == LogLevel.WARN && message.contains("typed-logger-check") })
    }

    private class Provider(
        private val failure: RequestIntegrityException? = null,
    ) : RequestIntegrityProvider,
        RequestDigestSigner {
        val digests = CopyOnWriteArrayList<ByteArray>()

        override suspend fun prepare(): RequestIntegritySession {
            delay(10)
            failure?.let { throw it }
            return RequestIntegritySession("integrity-token", RequestIntegrityPlatform.ANDROID, this)
        }

        override fun signDigest(clientDataHash: ByteArray): ByteArray = clientDataHash.also { digests.add(it) }
    }

    private val request = FlamingoMatchRequest.GrayBadge(FlamingoLiveCapture.Vanilla(byteArrayOf(1, 2, 3)), byteArrayOf(4), 0.5)

    @Test fun attestedMatchingSignsWithTheHostProvider() =
        runBlocking<Unit> {
            val provider = Provider()
            FlamingoMatcher.newAttested("https://127.0.0.1:9", provider).use { attested ->
                attested.dangerouslySkipMeasurements().use { matcher ->
                    assertFailsWith<FlamingoException> { matcher.performMatch(request) }
                }
            }
            assertEquals(listOf(32), provider.digests.map { it.size })
        }

    @Test fun integrityProviderFailuresKeepTheirType() =
        runBlocking<Unit> {
            FlamingoMatcher.newAttested("https://127.0.0.1:9", Provider(RequestIntegrityException.Unavailable())).use { attested ->
                attested.dangerouslySkipMeasurements().use { matcher ->
                    val failure = assertFailsWith<FlamingoException.RequestIntegrity> { matcher.performMatch(request) }
                    assertIs<RequestIntegrityException.Unavailable>(failure.value0)
                }
            }
            assertFailsWith<FlamingoException.Configuration> { FlamingoMatcher.newAttested("http://127.0.0.1:9", Provider()) }
        }
}
