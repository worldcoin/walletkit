package org.world.walletkit

import java.io.ByteArrayOutputStream
import java.nio.BufferUnderflowException
import java.nio.ByteBuffer
import java.nio.ByteOrder

// Binary values exchanged with Rust; the layout is specified in crates/walletkit/src/native/codec.rs
// and the ordinals and variant indices in native/values.rs. Frozen-byte tests: CodecTest.kt.

/** Reads values written by Rust. Handles read before a decoding failure are released. */
internal class NativeReader private constructor(
    bytes: ByteArray,
) {
    private val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
    private val handles = mutableListOf<NativeHandle>()

    fun u8(): Int = buffer.get().toInt() and 0xff

    fun u16(): UShort = buffer.short.toUShort()

    fun u32(): UInt = buffer.int.toUInt()

    fun u64(): ULong = buffer.long.toULong()

    fun f32(): Float = Float.fromBits(buffer.int)

    fun f64(): Double = Double.fromBits(buffer.long)

    fun bool(): Boolean =
        when (u8()) {
            0 -> false
            1 -> true
            else -> throw invalid()
        }

    fun bytes(): ByteArray = ByteArray(length()).also { buffer.get(it) }

    // Rust strings are valid UTF-8, so decoding does not need a validating decoder.
    fun string(): String {
        val length = length()
        val value = String(buffer.array(), buffer.arrayOffset() + buffer.position(), length, Charsets.UTF_8)
        buffer.position(buffer.position() + length)
        return value
    }

    fun uint256(): Uint256 = Uint256.fromBytes(ByteArray(32).also { buffer.get(it) })

    fun handle(): NativeHandle = NativeHandle(u64().toLong()).also { handles.add(it) }

    inline fun <T> optional(read: NativeReader.() -> T): T? =
        when (u8()) {
            0 -> null
            1 -> read()
            else -> throw invalid()
        }

    inline fun <T> list(read: NativeReader.() -> T): List<T> = List(length()) { read() }

    fun <E : Enum<E>> enum(values: List<E>): E = values.getOrNull(u8()) ?: throw invalid()

    internal fun length(): Int {
        val length = u32().toLong()
        if (length > buffer.remaining()) throw invalid()
        return length.toInt()
    }

    companion object {
        fun <T> decode(
            bytes: ByteArray,
            read: NativeReader.() -> T,
        ): T {
            val reader = NativeReader(bytes)
            try {
                return reader.read().also { if (reader.buffer.hasRemaining()) throw invalid() }
            } catch (failure: Throwable) {
                reader.handles.forEach(NativeHandle::close)
                throw when (failure) {
                    is BufferUnderflowException, is IndexOutOfBoundsException, is IllegalArgumentException -> invalid()
                    else -> failure
                }
            }
        }

        internal fun invalid() = WalletKitBridgeException("InvalidResponse")
    }
}

/** Writes values for Rust to read. */
internal class NativeWriter private constructor() {
    private val output = ByteArrayOutputStream()

    fun u8(value: Int) = output.write(value)

    fun u32(value: UInt) =
        ByteBuffer
            .allocate(4)
            .order(ByteOrder.LITTLE_ENDIAN)
            .putInt(value.toInt())
            .array()
            .let(output::write)

    fun u64(value: ULong) =
        ByteBuffer
            .allocate(8)
            .order(ByteOrder.LITTLE_ENDIAN)
            .putLong(value.toLong())
            .array()
            .let(output::write)

    fun f64(value: Double) = u64(value.toRawBits().toULong())

    fun bytes(value: ByteArray) {
        u32(value.size.toUInt())
        output.write(value)
    }

    fun string(value: String) = bytes(value.encodeToByteArray())

    inline fun <T> optional(
        value: T?,
        write: NativeWriter.(T) -> Unit,
    ) {
        if (value == null) {
            u8(0)
        } else {
            u8(1)
            write(value)
        }
    }

    inline fun <T> list(
        values: Collection<T>,
        write: NativeWriter.(T) -> Unit,
    ) {
        u32(values.size.toUInt())
        values.forEach { write(it) }
    }

    inline fun <K, V> map(
        values: Map<K, V>,
        write: NativeWriter.(K, V) -> Unit,
    ) {
        u32(values.size.toUInt())
        values.forEach { (key, value) -> write(key, value) }
    }

    companion object {
        fun encode(write: NativeWriter.() -> Unit): ByteArray = NativeWriter().apply(write).output.toByteArray()
    }
}

internal fun decodeNativeError(bytes: ByteArray): Throwable =
    NativeReader.decode(bytes) {
        when (u8()) {
            0 -> {
                string().let { code ->
                    if (code ==
                        "Cancelled"
                    ) {
                        java.util.concurrent.CancellationException("WalletKit operation cancelled")
                    } else {
                        WalletKitBridgeException(code)
                    }
                }
            }

            1 -> {
                readWalletKitException()
            }

            2 -> {
                readStorageException()
            }

            3 -> {
                readFlamingoException()
            }

            4 -> {
                readCredentialConstraintsCheckException()
            }

            else -> {
                WalletKitBridgeException("UnknownErrorDomain")
            }
        }
    }

internal fun NativeReader.readCredentialConstraintsCheckResult() =
    CredentialConstraintsCheckResult(bool(), list { CredentialConstraintsCheckItem(string(), u64(), bool()) })

internal fun NativeReader.readCredentialRecord() = CredentialRecord(u64(), u64(), u64(), u64(), bool())

internal fun NativeReader.readActivityEntry() =
    ActivityEntry(
        id = optional { u64() },
        rpId = u64(),
        appIdentifier = string(),
        clientId = string(),
        protocol = enum(ProtocolVersion.entries),
        timestamp = optional { u64() },
        outcome = enum(ActivityOutcome.entries),
        issuerSchemaIds = list { u64() },
        failureReason = optional { enum(ActivityFailureReason.entries) },
    )

internal fun NativeWriter.writeActivityEntry(entry: ActivityEntry) {
    optional(entry.id) { u64(it) }
    u64(entry.rpId)
    string(entry.appIdentifier)
    string(entry.clientId)
    u8(entry.protocol.ordinal)
    optional(entry.timestamp) { u64(it) }
    u8(entry.outcome.ordinal)
    list(entry.issuerSchemaIds) { u64(it) }
    optional(entry.failureReason) { u8(it.ordinal) }
}

internal fun NativeReader.readRecoveryBinding() = RecoveryBinding(optional { string() }, optional { string() }, optional { string() })

internal fun NativeReader.readRecoveryUpdateSignature() = RecoveryUpdateSignature(bytes(), uint256())

internal fun NativeReader.readRecoveryData() = RecoveryData(string(), string(), string())

internal fun NativeReader.readRegistrationStatus(): RegistrationStatus =
    when (u8()) {
        0 -> RegistrationStatus.Queued
        1 -> RegistrationStatus.Batching
        2 -> RegistrationStatus.Submitted
        3 -> RegistrationStatus.Finalized
        4 -> RegistrationStatus.Failed(string(), optional { string() })
        else -> throw WalletKitBridgeException("InvalidResponse")
    }

internal fun NativeReader.readGatewayRequestStatus(): GatewayRequestStatus =
    when (u8()) {
        0 -> GatewayRequestStatus.Queued
        1 -> GatewayRequestStatus.Batching
        2 -> GatewayRequestStatus.Submitted(string())
        3 -> GatewayRequestStatus.Finalized(string())
        4 -> GatewayRequestStatus.Failed(string(), optional { string() })
        else -> throw WalletKitBridgeException("InvalidResponse")
    }

internal fun NativeWriter.writeStringMap(values: Map<String, String>) =
    map(values) { key, value ->
        string(key)
        string(value)
    }

internal fun NativeWriter.writeMeasurements(values: Map<UInt, ByteArray>) =
    map(values) { key, value ->
        u32(key)
        bytes(value)
    }

internal fun NativeWriter.writeFlamingoMatchRequest(request: FlamingoMatchRequest) =
    when (request) {
        is FlamingoMatchRequest.DeepFace -> {
            u8(0)
            bytes(request.orbCredential)
            writeFlamingoLiveCapture(request.live)
            bytes(request.rtmsChallenge)
            bytes(request.hashesJson)
            f64(request.matchThreshold)
        }

        is FlamingoMatchRequest.GrayBadge -> {
            u8(1)
            writeFlamingoLiveCapture(request.live)
            bytes(request.rtmsChallenge)
            f64(request.matchThreshold)
        }
    }

private fun NativeWriter.writeFlamingoLiveCapture(capture: FlamingoLiveCapture) =
    when (capture) {
        is FlamingoLiveCapture.Vanilla -> {
            u8(0)
            bytes(capture.image)
        }

        is FlamingoLiveCapture.LightGuard -> {
            u8(1)
            bytes(capture.illuminated)
            bytes(capture.unilluminated)
            u8(capture.matchingFrame.ordinal)
        }
    }

internal fun NativeReader.readFlamingoMatchOutcome(): FlamingoMatchOutcome =
    when (u8()) {
        0 -> FlamingoMatchOutcome.Matched(VerifiedMatchToken(handle()), readFlamingoDebugReport())
        1 -> FlamingoMatchOutcome.Rejected(readFlamingoMatchRejection(), readFlamingoDebugReport())
        else -> throw WalletKitBridgeException("InvalidResponse")
    }

private fun NativeReader.readFlamingoDebugReport(): FlamingoDebugReport =
    when (u8()) {
        0 -> FlamingoDebugReport.Available(string())
        1 -> FlamingoDebugReport.NotProduced
        2 -> FlamingoDebugReport.OmittedTooLarge(u64())
        else -> throw WalletKitBridgeException("InvalidResponse")
    }

private fun NativeReader.readFlamingoMatchRejection(): FlamingoMatchRejection =
    when (u8()) {
        0 -> {
            FlamingoMatchRejection.MalformedInputs
        }

        1 -> {
            FlamingoMatchRejection.InvalidHashesJson
        }

        2 -> {
            FlamingoMatchRejection.ThumbnailHashMismatch
        }

        3 -> {
            FlamingoMatchRejection.InvalidThreshold
        }

        4 -> {
            FlamingoMatchRejection.InputRejected(
                enum(FlamingoInputFailureReason.entries),
                optional { enum(FlamingoImageRole.entries) },
                optional { u64() },
            )
        }

        5 -> {
            FlamingoMatchRejection.MatchBelowThreshold(enum(FlamingoComparison.entries))
        }

        6 -> {
            FlamingoMatchRejection.ImageRejected(
                enum(FlamingoImageRole.entries),
                enum(FlamingoImageFailureReason.entries),
                optional { enum(FlamingoValidationTarget.entries) },
            )
        }

        7 -> {
            FlamingoMatchRejection.MatchingFailed(enum(FlamingoComparison.entries))
        }

        8 -> {
            FlamingoMatchRejection.Internal
        }

        else -> {
            throw WalletKitBridgeException("InvalidResponse")
        }
    }

internal fun NativeReader.readWalletKitException(): WalletKitException =
    when (u8()) {
        0 -> WalletKitException.Storage(readStorageException())
        1 -> WalletKitException.InvalidInput(string(), string())
        2 -> WalletKitException.InvalidNumber()
        3 -> WalletKitException.SerializationError(string())
        4 -> WalletKitException.NetworkError(string(), string(), optional { u16() })
        5 -> WalletKitException.Reqwest(string())
        6 -> WalletKitException.ProofGeneration(string())
        7 -> WalletKitException.SemaphoreNotEnabled()
        8 -> WalletKitException.CredentialNotIssued()
        9 -> WalletKitException.CredentialNotMined()
        10 -> WalletKitException.AccountDoesNotExist()
        11 -> WalletKitException.UnauthorizedAuthenticator()
        12 -> WalletKitException.AuthenticatorError(string())
        13 -> WalletKitException.UnfulfillableRequest()
        14 -> WalletKitException.ResponseValidation(string())
        15 -> WalletKitException.NullifierReplay()
        16 -> WalletKitException.InvalidRpSignature()
        17 -> WalletKitException.DuplicateNonce()
        18 -> WalletKitException.UnknownRp()
        19 -> WalletKitException.InactiveRp()
        20 -> WalletKitException.TimestampTooOld()
        21 -> WalletKitException.TimestampTooFarInFuture()
        22 -> WalletKitException.InvalidTimestamp()
        23 -> WalletKitException.RpSignatureExpired()
        24 -> WalletKitException.Groth16MaterialCacheInvalid(string(), string())
        25 -> WalletKitException.Groth16MaterialEmbeddedLoad(string())
        26 -> WalletKitException.Generic(string())
        27 -> WalletKitException.RecoveryBindingDoesNotExist()
        28 -> WalletKitException.SessionIdMismatch()
        29 -> WalletKitException.NfcNonRetryable(string())
        30 -> WalletKitException.DebugReportNotFound()
        31 -> WalletKitException.IdentityNotFound()
        32 -> WalletKitException.NoSuccessfulCaptureFound()
        33 -> WalletKitException.NotEligibleForRecovery()
        34 -> WalletKitException.OhttpError(string())
        35 -> WalletKitException.InvalidActionSession()
        else -> throw WalletKitBridgeException("InvalidResponse")
    }

internal fun NativeReader.readStorageException(): StorageException =
    when (u8()) {
        0 -> StorageException.Keystore(string())
        1 -> StorageException.BlobStore(string())
        2 -> StorageException.Lock(string())
        3 -> StorageException.Serialization(string())
        4 -> StorageException.Crypto(string())
        5 -> StorageException.InvalidEnvelope(string())
        6 -> StorageException.InvalidInput(string())
        7 -> StorageException.UnsupportedEnvelopeVersion(u32())
        8 -> StorageException.VaultDb(string())
        9 -> StorageException.CacheDb(string())
        10 -> StorageException.PersistentStorage(string())
        11 -> StorageException.InvalidLeafIndex(u64(), u64())
        12 -> StorageException.CorruptedVault(string())
        13 -> StorageException.NotInitialized()
        14 -> StorageException.NullifierAlreadyDisclosed()
        15 -> StorageException.CredentialNotFound()
        16 -> StorageException.CredentialIdNotFound(u64())
        17 -> StorageException.CorruptedCacheEntry(u8().toUByte())
        18 -> StorageException.ActivityDb(string())
        19 -> StorageException.ActivityInvalidRecord(string())
        20 -> StorageException.Callback(string())
        else -> throw WalletKitBridgeException("InvalidResponse")
    }

/** Host callbacks report storage failures to Rust in the same encoding. */
internal fun NativeWriter.writeStorageException(failure: StorageException) {
    fun message(
        index: Int,
        value: String,
    ) {
        u8(index)
        string(value)
    }
    when (failure) {
        is StorageException.Keystore -> {
            message(0, failure.value0)
        }

        is StorageException.BlobStore -> {
            message(1, failure.value0)
        }

        is StorageException.Lock -> {
            message(2, failure.value0)
        }

        is StorageException.Serialization -> {
            message(3, failure.value0)
        }

        is StorageException.Crypto -> {
            message(4, failure.value0)
        }

        is StorageException.InvalidEnvelope -> {
            message(5, failure.value0)
        }

        is StorageException.InvalidInput -> {
            message(6, failure.value0)
        }

        is StorageException.UnsupportedEnvelopeVersion -> {
            u8(7)
            u32(failure.value0)
        }

        is StorageException.VaultDb -> {
            message(8, failure.value0)
        }

        is StorageException.CacheDb -> {
            message(9, failure.value0)
        }

        is StorageException.PersistentStorage -> {
            message(10, failure.value0)
        }

        is StorageException.InvalidLeafIndex -> {
            u8(11)
            u64(failure.expected)
            u64(failure.provided)
        }

        is StorageException.CorruptedVault -> {
            message(12, failure.value0)
        }

        is StorageException.NotInitialized -> {
            u8(13)
        }

        is StorageException.NullifierAlreadyDisclosed -> {
            u8(14)
        }

        is StorageException.CredentialNotFound -> {
            u8(15)
        }

        is StorageException.CredentialIdNotFound -> {
            u8(16)
            u64(failure.credentialId)
        }

        is StorageException.CorruptedCacheEntry -> {
            u8(17)
            u8(failure.keyPrefix.toInt())
        }

        is StorageException.ActivityDb -> {
            message(18, failure.value0)
        }

        is StorageException.ActivityInvalidRecord -> {
            message(19, failure.value0)
        }

        is StorageException.Callback -> {
            message(20, failure.value0)
        }
    }
}

internal fun NativeReader.readFlamingoException(): FlamingoException =
    when (u8()) {
        0 -> FlamingoException.InvalidInput(string(), string(), enum(FlamingoInputFailureKind.entries), optional { u64() })
        1 -> FlamingoException.Configuration(string())
        2 -> FlamingoException.RequestIntegrity(requestIntegrityException(u8()))
        3 -> FlamingoException.Service(string(), bool())
        4 -> FlamingoException.Timeout()
        5 -> FlamingoException.Transport(string())
        6 -> FlamingoException.InvalidResponse(enum(FlamingoResponseStage.entries))
        7 -> FlamingoException.Attestation(string())
        8 -> FlamingoException.Channel(string())
        9 -> FlamingoException.InvalidSigningKey()
        10 -> FlamingoException.StatementInvalid()
        11 -> FlamingoException.ReassignmentRequired()
        else -> throw WalletKitBridgeException("InvalidResponse")
    }

internal fun requestIntegrityException(ordinal: Int): RequestIntegrityException =
    when (ordinal) {
        0 -> RequestIntegrityException.Unavailable()
        1 -> RequestIntegrityException.InvalidSession()
        2 -> RequestIntegrityException.SigningFailed()
        3 -> RequestIntegrityException.CallbackFailed()
        4 -> RequestIntegrityException.TimedOut()
        else -> throw WalletKitBridgeException("InvalidResponse")
    }

internal val RequestIntegrityException.ordinal: Int
    get() =
        when (this) {
            is RequestIntegrityException.Unavailable -> 0
            is RequestIntegrityException.InvalidSession -> 1
            is RequestIntegrityException.SigningFailed -> 2
            is RequestIntegrityException.CallbackFailed -> 3
            is RequestIntegrityException.TimedOut -> 4
        }

internal fun NativeReader.readCredentialConstraintsCheckException(): CredentialConstraintsCheckException =
    when (u8()) {
        0 -> CredentialConstraintsCheckException.Storage(readStorageException())
        1 -> CredentialConstraintsCheckException.ConstraintTooDeep()
        2 -> CredentialConstraintsCheckException.ConstraintTooLarge()
        else -> throw WalletKitBridgeException("InvalidResponse")
    }
