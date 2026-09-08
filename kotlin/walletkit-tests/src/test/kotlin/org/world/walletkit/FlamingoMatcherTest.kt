package org.world.walletkit

import uniffi.walletkit_core.FlamingoMatcher
import uniffi.walletkit_core.FlamingoMeasurements
import kotlin.test.Test
import kotlin.test.assertFails

class FlamingoMatcherTest {
    @Test
    fun fluentConfiguration() {
        val matcher =
            FlamingoMatcher("https://verifier.example.com")
                .withMeasurements(
                    FlamingoMeasurements(
                        pcr0 = ByteArray(48) { 1 },
                        pcr1 = ByteArray(48) { 2 },
                        pcr2 = ByteArray(48) { 3 },
                    ),
                ).withHeaders(mapOf("Authorization" to "Bearer test-token"))

        matcher.withHeaders(emptyMap())
        assertFails { matcher.withHeaders(mapOf("x-test" to "invalid\nvalue")) }
        assertFails {
            matcher.withMeasurements(
                FlamingoMeasurements(
                    pcr0 = ByteArray(48),
                    pcr1 = ByteArray(48) { 2 },
                    pcr2 = ByteArray(48) { 3 },
                ),
            )
        }
    }
}
