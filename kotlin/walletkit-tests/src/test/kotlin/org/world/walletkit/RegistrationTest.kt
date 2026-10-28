package org.world.walletkit

import kotlinx.coroutines.test.runTest
import uniffi.walletkit_core.ApproverException
import uniffi.walletkit_core.BridgeClient
import uniffi.walletkit_core.BridgeException
import uniffi.walletkit_core.PendingRegistration
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class RegistrationTest {
    @Test
    fun bridgeClientKeepsItsDomain() {
        assertEquals("bridge.example", BridgeClient("bridge.example").domain())
    }

    @Test
    fun bridgeClientRejectsAnInvalidDomain() {
        assertFailsWith<BridgeException.InvalidDomain> {
            BridgeClient("not a domain")
        }
    }

    @Test
    fun receiveRejectsTextThatIsNotAPairingUri() =
        runTest {
            assertFailsWith<ApproverException.InvalidPairingUri> {
                PendingRegistration.receive("https://example.com", listOf(BridgeClient("bridge.example")))
            }
        }
}
