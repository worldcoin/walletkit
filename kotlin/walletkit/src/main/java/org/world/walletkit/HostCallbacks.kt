package org.world.walletkit

// Rust calls these interfaces directly through JNI on its own threads, which stay attached
// to the JVM as daemons. Consumer rules keep their names and method signatures.

/**
 * Use authenticated encryption under a device-bound key; reject mismatched associated data.
 * Implementations must be thread-safe and must not synchronously re-enter WalletKit.
 */
interface DeviceKeystore {
    fun seal(
        associatedData: ByteArray,
        plaintext: ByteArray,
    ): ByteArray

    fun openSealed(
        associatedData: ByteArray,
        ciphertext: ByteArray,
    ): ByteArray
}

/** Thread-safe blob I/O. Writes atomically replace the entire blob; failures must throw. */
interface AtomicBlobStore {
    fun read(path: String): ByteArray?

    fun writeAtomic(
        path: String,
        bytes: ByteArray,
    )

    fun delete(path: String)
}

interface Logger {
    fun log(
        level: LogLevel,
        message: String,
    )
}

fun interface VaultChangedListener {
    fun onVaultChanged()
}

fun interface ActivityChangedListener {
    fun onActivityChanged()
}

/**
 * Supplies authentication material before each attested Flamingo connection or reassignment.
 * The host owns token acquisition, refresh, audience policy, and hardware-key lifecycle.
 * Throw [RequestIntegrityException] to report a typed failure; other exceptions become
 * [RequestIntegrityException.CallbackFailed].
 */
interface RequestIntegrityProvider {
    suspend fun prepare(): RequestIntegritySession
}

/**
 * Signs a 32-byte SHA-256 client-data digest with the key certified by the session token,
 * returning the platform's native signature encoding. Called on a background thread.
 */
interface RequestDigestSigner {
    fun signDigest(clientDataHash: ByteArray): ByteArray
}
