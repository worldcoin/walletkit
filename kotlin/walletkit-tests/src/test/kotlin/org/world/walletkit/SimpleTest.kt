package org.world.walletkit

import uniffi.walletkit_core.FieldElement
import uniffi.walletkit_core.LogLevel
import uniffi.walletkit_core.Logger
import uniffi.walletkit_core.OwnershipProof
import uniffi.walletkit_core.emitLog
import uniffi.walletkit_core.initLogging
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

private class CapturingLogger : Logger {
    private val lock = Any()
    private val entries = mutableListOf<Pair<LogLevel, String>>()

    override fun log(
        level: LogLevel,
        message: String,
    ) {
        synchronized(lock) {
            entries.add(level to message)
        }
    }

    fun snapshot(): List<Pair<LogLevel, String>> =
        synchronized(lock) {
            entries.toList()
        }
}

class SimpleTest {
    @Test
    fun initLoggingForwardsLevelAndMessage() {
        val logger = CapturingLogger()
        initLogging(logger, LogLevel.INFO)
        emitLog(LogLevel.INFO, "bridge test")

        // Log delivery happens on a dedicated background thread, so give it
        // a moment to flush through the channel.
        Thread.sleep(50)

        val entries = logger.snapshot()
        assertTrue(entries.isNotEmpty(), "expected at least one bridged log entry")

        val hasBridgedMessage =
            entries.any { (level, message) ->
                level == LogLevel.INFO && message.contains("bridge test")
            }
        assertTrue(hasBridgedMessage, "expected info-level bridged log")
    }

    // Compile-time only: a rename, a dropped export, or a changed parameter
    // type fails here. Calling it needs a proof, so that stays in Rust.
    @Test
    fun ownershipProofExposesVerificationRequestBuilder() {
        fun callBuilder(
            proof: OwnershipProof,
            challengeId: String,
            credentialSub: FieldElement,
        ): String = proof.toVerificationRequestJson(challengeId, credentialSub)

        assertNotNull(::callBuilder)
    }
}
