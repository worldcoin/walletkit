package org.world.walletkit

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** An HTTP server that accepts requests and never answers, so native calls stay in flight. */
private class SilentServer : AutoCloseable {
    private val server = ServerSocket(0, 512, InetAddress.getLoopbackAddress())
    private val sockets = CopyOnWriteArrayList<Socket>()
    val accepted = Semaphore(0)
    val closedByClient = Semaphore(0)
    val url = "https://127.0.0.1:${server.localPort}"

    init {
        Thread({
            while (!server.isClosed) {
                val socket =
                    try {
                        server.accept()
                    } catch (closed: Exception) {
                        break
                    }
                sockets.add(socket)
                accepted.release()
                Thread({
                    try {
                        while (socket.getInputStream().read() != -1) Unit
                    } catch (ignored: Exception) {
                    }
                    closedByClient.release()
                }, "silent-server-reader").apply { isDaemon = true }.start()
            }
        }, "silent-server").apply { isDaemon = true }.start()
    }

    override fun close() {
        server.close()
        sockets.forEach(Socket::close)
    }
}

class AsyncTest {
    private fun manager(server: SilentServer) = UserAgentBuilder.create().use { RecoveryBindingManager.newWithBaseUrl(server.url, it) }

    @Test fun cancellationStopsTheNativeCallInFlight() =
        runBlocking<Unit> {
            SilentServer().use { server ->
                manager(server).use { manager ->
                    val call = async(Dispatchers.Default) { manager.getRecoveryBinding(42u) }
                    assertTrue(server.accepted.tryAcquire(10, TimeUnit.SECONDS), "request reached the server")
                    call.cancel()
                    assertFailsWith<CancellationException> { call.await() }
                    assertTrue(server.closedByClient.tryAcquire(10, TimeUnit.SECONDS), "native future dropped its connection")
                }
            }
        }

    @Test fun admissionRejectsCallsBeyondTheWorkerQueue() =
        runBlocking<Unit> {
            SilentServer().use { server ->
                manager(server).use { manager ->
                    val calls = List(4 + 128) { async(Dispatchers.Default) { manager.getRecoveryBinding(it.toULong()) } }
                    assertTrue(server.accepted.tryAcquire(4, 10, TimeUnit.SECONDS), "all four workers busy")
                    delay(500) // Let the remaining calls fill the queue.
                    val busy = assertFailsWith<WalletKitBridgeException> { manager.getRecoveryBinding(0u) }
                    assertEquals("Busy", busy.code)
                    calls.forEach { it.cancel() }
                    calls.forEach { call -> assertFailsWith<CancellationException> { call.await() } }
                    assertTrue(server.closedByClient.tryAcquire(4, 10, TimeUnit.SECONDS), "running calls cancelled")
                }
            }
            // The workers drain; new calls are admitted again.
            FieldElement.fromU64(1u).use { assertEquals(32, it.toBytes().size) }
            assertEquals(1, NativeCalls.async { 1 })
        }

    @Test fun closingAnInputDuringACallDoesNotFreeIt() =
        runBlocking<Unit> {
            SilentServer().use { server ->
                val manager = manager(server)
                val call = async(Dispatchers.Default) { manager.getRecoveryBinding(7u) }
                assertTrue(server.accepted.tryAcquire(10, TimeUnit.SECONDS))
                manager.close()
                assertFailsWith<IllegalStateException> { manager.getRecoveryBinding(7u) }
                call.cancel()
                assertFailsWith<CancellationException> { call.await() }
            }
        }
}
