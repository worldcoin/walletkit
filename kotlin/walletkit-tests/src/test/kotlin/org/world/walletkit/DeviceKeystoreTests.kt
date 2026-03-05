package org.world.walletkit

import kotlin.test.Test
import kotlin.test.assertFails
import kotlin.test.assertTrue

class DeviceKeystoreTests {
    @Test
    fun sealAndOpenRoundTrip() {
        val keystore = InMemoryDeviceKeystore()
        val associatedData = "ad".encodeToByteArray()
        val plaintext = "hello".encodeToByteArray()

        val ciphertext = keystore.seal(associatedData, plaintext)
        val opened = keystore.openSealed(associatedData, ciphertext)

        assertTrue(opened.contentEquals(plaintext))
    }

    @Test
    fun associatedDataMismatchFails() {
        val keystore = InMemoryDeviceKeystore()
        val plaintext = "secret".encodeToByteArray()
        val ciphertext = keystore.seal("ad-1".encodeToByteArray(), plaintext)

        assertFails {
            keystore.openSealed("ad-2".encodeToByteArray(), ciphertext)
        }
    }

    @Test
    fun reopenWithSameKeyMaterialCanOpenCiphertext() {
        val keyBytes = randomKeystoreKeyBytes()
        val firstKeystore = InMemoryDeviceKeystore(keyBytes)
        val secondKeystore = InMemoryDeviceKeystore(keyBytes)
        val associatedData = "ad".encodeToByteArray()
        val plaintext = "hello".encodeToByteArray()

        val ciphertext = firstKeystore.seal(associatedData, plaintext)
        val opened = secondKeystore.openSealed(associatedData, ciphertext)

        assertTrue(opened.contentEquals(plaintext))
    }
}
