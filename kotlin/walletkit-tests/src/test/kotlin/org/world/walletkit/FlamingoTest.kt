package org.world.walletkit

import uniffi.walletkit_core.FlamingoException
import uniffi.walletkit_core.FlamingoMatcher
import kotlin.test.Test
import kotlin.test.assertFailsWith

class FlamingoTest {
    @Test
    fun measurementSkipIsExplicitAndStrictMeasurementsCanBeRestored() {
        val zeroMeasurements = (0u..2u).associateWith { ByteArray(48) }
        val trustedMeasurements = (0u..2u).associateWith { ByteArray(48) { 1 } }
        FlamingoMatcher("https://verifier.example.com").use { matcher ->
            assertFailsWith<FlamingoException.Configuration> {
                matcher.withMeasurements(zeroMeasurements)
            }
            matcher.dangerouslySkipMeasurements().use { skip ->
                assertFailsWith<FlamingoException.Configuration> {
                    skip.withMeasurements(emptyMap())
                }
                assertFailsWith<FlamingoException.Configuration> {
                    skip.withMeasurements(zeroMeasurements)
                }
                skip.withMeasurements(trustedMeasurements).use { strict ->
                    assertFailsWith<FlamingoException.Configuration> {
                        strict.withMeasurements(zeroMeasurements)
                    }
                }
            }
        }
    }
}
