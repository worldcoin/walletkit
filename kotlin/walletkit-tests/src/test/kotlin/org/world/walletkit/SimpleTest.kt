package org.world.walletkit

import uniffi.walletkit_core.LogLevel
import uniffi.walletkit_core.Logger
import uniffi.walletkit_core.emitLog
import uniffi.walletkit_core.initLogging
import kotlin.test.Test
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
        initLogging(logger)
        emitLog(LogLevel.INFO, "bridge test")

        val entries = logger.snapshot()
        assertTrue(entries.isNotEmpty(), "expected at least one bridged log entry")

        val hasBridgedMessage =
            entries.any { (level, message) ->
                level == LogLevel.INFO && message.contains("bridge test")
            }
        assertTrue(hasBridgedMessage, "expected info-level bridged log")
    }
}
