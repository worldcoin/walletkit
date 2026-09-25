package org.world.walletkit

import uniffi.walletkit_core.FlamingoException
import uniffi.walletkit_core.FlamingoMatcher
import kotlin.test.Test
import kotlin.test.assertFailsWith

class FlamingoTest {
    @Test
    fun debugMeasurementsRequireExplicitOptIn() {
        val measurements = (0u..2u).associateWith { ByteArray(48) }
        FlamingoMatcher("https://verifier.example.com").use { matcher ->
            assertFailsWith<FlamingoException.Configuration> {
                matcher.withMeasurements(measurements)
            }
            matcher.withDebugMeasurements(measurements).use { debug ->
                assertFailsWith<FlamingoException.Configuration> {
                    debug.withMeasurements(measurements)
                }
            }
            assertFailsWith<FlamingoException.Configuration> {
                matcher.withDebugMeasurements(measurements - 2u)
            }
            assertFailsWith<FlamingoException.Configuration> {
                matcher.withDebugMeasurements(measurements + (0u to ByteArray(47)))
            }
        }
    }
}
