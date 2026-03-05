package org.world.walletkit.storage

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import uniffi.walletkit_core.DeviceKeystore
import uniffi.walletkit_core.StorageException

class AndroidDeviceKeystore(
    private val alias: String = "walletkit_device_key"
) : DeviceKeystore {
    private val lock = Any()

    override fun seal(associatedData: ByteArray, plaintext: ByteArray): ByteArray {
        try {
            val key = getOrCreateKey()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key)
            cipher.updateAAD(associatedData)
            val ciphertext = cipher.doFinal(plaintext)
            val iv = cipher.iv
            val output = ByteArray(1 + iv.size + ciphertext.size)
            output[0] = iv.size.toByte()
            System.arraycopy(iv, 0, output, 1, iv.size)
            System.arraycopy(ciphertext, 0, output, 1 + iv.size, ciphertext.size)
            return output
        } catch (error: Exception) {
            throw StorageException.Keystore("keystore seal failed: ${error.message}")
        }
    }

    override fun openSealed(
        associatedData: ByteArray,
        ciphertext: ByteArray
    ): ByteArray {
        if (ciphertext.isEmpty()) {
            throw StorageException.Keystore("keystore ciphertext is empty")
        }
        val ivLen = ciphertext[0].toInt() and 0xFF
        if (ciphertext.size < 1 + ivLen) {
            throw StorageException.Keystore("keystore ciphertext too short")
        }
        try {
            val key = getOrCreateKey()
            val iv = ciphertext.copyOfRange(1, 1 + ivLen)
            val payload = ciphertext.copyOfRange(1 + ivLen, ciphertext.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val spec = GCMParameterSpec(128, iv)
            cipher.init(Cipher.DECRYPT_MODE, key, spec)
            cipher.updateAAD(associatedData)
            return cipher.doFinal(payload)
        } catch (error: Exception) {
            throw StorageException.Keystore("keystore open failed: ${error.message}")
        }
    }

    private fun getOrCreateKey(): SecretKey {
        synchronized(lock) {
            try {
                val keyStore = KeyStore.getInstance("AndroidKeyStore")
                keyStore.load(null)
                val existing = keyStore.getKey(alias, null) as? SecretKey
                if (existing != null) {
                    return existing
                }

                val keyGenerator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES,
                    "AndroidKeyStore"
                )
                val spec = KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .setRandomizedEncryptionRequired(true)
                    .build()
                keyGenerator.init(spec)
                return keyGenerator.generateKey()
            } catch (error: Exception) {
                throw StorageException.Keystore("keystore init failed: ${error.message}")
            }
        }
    }
}
