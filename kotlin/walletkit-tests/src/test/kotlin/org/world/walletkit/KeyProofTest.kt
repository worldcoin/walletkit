package org.world.walletkit

import uniffi.walletkit_core.WalletKitException
import uniffi.walletkit_core.createWorldIdKeyProof
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class KeyProofTest {
    @Test
    fun signsWithoutRegistrationAndRestoresTheSameKey() {
        val expiresAt = System.currentTimeMillis() / 1000 + 300
        val challenge =
            """{"version":1,"issuer":"https://auth.world.org","ceremony_id":"019af784-3d00-7000-8000-000000000001","nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","expires_at":$expiresAt}"""
                .toByteArray()
        val proof = createWorldIdKeyProof(ByteArray(32) { 0x11 }, challenge, "https://auth.world.org")
        assertEquals("A66IqHPC21NxH6PvdYOc4CiP0dUZ0YJU-c1P3Wnqc8Vg", proof.publicKey)
        assertEquals(
            proof,
            createWorldIdKeyProof(ByteArray(32) { 0x11 }, challenge, "https://auth.world.org"),
        )
        assertFailsWith<WalletKitException.InvalidInput> {
            createWorldIdKeyProof(ByteArray(32) { 0x11 }, challenge, "https://other.example")
        }
    }
}
