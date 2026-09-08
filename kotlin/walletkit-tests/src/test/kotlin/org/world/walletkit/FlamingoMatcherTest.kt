package org.world.walletkit

import uniffi.walletkit_core.FlamingoMatcher
import kotlin.test.Test
import kotlin.test.assertFails

class FlamingoMatcherTest {
    @Test
    fun fluentConfiguration() {
        val matcher =
            FlamingoMatcher("https://verifier.example.com")
                .withMeasurements(
                    mapOf(
                        0u to ByteArray(48) { 1 },
                        1u to ByteArray(48) { 2 },
                        2u to ByteArray(48) { 3 },
                    ),
                ).withHeaders(mapOf("Authorization" to "Bearer test-token"))

        matcher.withHeaders(emptyMap())
        assertFails { matcher.withHeaders(mapOf("x-test" to "invalid\nvalue")) }
        assertFails { matcher.withMeasurements(emptyMap()) }
        assertFails {
            matcher.withMeasurements(
                mapOf(
                    0u to ByteArray(48),
                    1u to ByteArray(48) { 2 },
                    2u to ByteArray(48) { 3 },
                ),
            )
        }
    }
}
