package org.world.walletkit

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import java.lang.ref.PhantomReference
import java.lang.ref.ReferenceQueue
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import kotlin.coroutines.resumeWithException

class WalletKitBridgeException(
    val code: String,
) : Exception("WalletKitBridge.$code")

/**
 * Typed JNI entry points, one per SDK method, exported by Rust `#[jni_export]` functions.
 * Resource arguments are the owning [NativeHandle], whose JNI reference keeps the owner
 * reachable during the call; resource results are new handle IDs that the caller wraps.
 */
internal object NativeBridge {
    private const val ABI_VERSION = 2

    init {
        System.loadLibrary("walletkit")
        check(abiVersion() == ABI_VERSION) { "Incompatible WalletKit native library" }
    }

    @JvmStatic external fun abiVersion(): Int

    @JvmStatic external fun operationNew(): Long

    @JvmStatic external fun operationCancel(operation: Long)

    @JvmStatic external fun objectRelease(handle: Long)

    @JvmStatic external fun integrityPrepared(
        completion: Long,
        token: String,
        platform: Int,
        signer: RequestDigestSigner,
    )

    @JvmStatic external fun integrityFailed(
        completion: Long,
        error: Int,
    )

    @JvmStatic external fun fieldElementFromBytes(bytes: ByteArray): Long

    @JvmStatic external fun fieldElementFromU64(value: Long): Long

    @JvmStatic external fun fieldElementToBytes(element: NativeHandle): ByteArray

    @JvmStatic external fun fieldElementTryFromHexString(hexString: String): Long

    @JvmStatic external fun fieldElementToHexString(element: NativeHandle): String

    @JvmStatic external fun credentialFromBytes(bytes: ByteArray): Long

    @JvmStatic external fun credentialSub(credential: NativeHandle): Long

    @JvmStatic external fun credentialIssuerSchemaId(credential: NativeHandle): Long

    @JvmStatic external fun credentialExpiresAt(credential: NativeHandle): Long

    @JvmStatic external fun credentialAssociatedDataCommitment(credential: NativeHandle): Long

    @JvmStatic external fun credentialClaims(credential: NativeHandle): ByteArray

    @JvmStatic external fun credentialClaimsHex(credential: NativeHandle): ByteArray

    @JvmStatic external fun proofRequestFromJson(json: String): Long

    @JvmStatic external fun proofRequestToJson(request: NativeHandle): String

    @JvmStatic external fun proofRequestId(request: NativeHandle): String

    @JvmStatic external fun proofRequestVersion(request: NativeHandle): Int

    @JvmStatic external fun proofResponseToJson(response: NativeHandle): String

    @JvmStatic external fun proofResponseId(response: NativeHandle): String

    @JvmStatic external fun proofResponseVersion(response: NativeHandle): Int

    @JvmStatic external fun proofResponseError(response: NativeHandle): String?

    @JvmStatic external fun ownershipProofEncode(proof: NativeHandle): ByteArray

    @JvmStatic external fun ownershipProofEncodeB64(proof: NativeHandle): String

    @JvmStatic external fun ownershipProofMerkleRoot(proof: NativeHandle): Long

    @JvmStatic external fun userAgentHeaderValue(userAgent: NativeHandle): String

    @JvmStatic external fun userAgentBuilderNew(): Long

    @JvmStatic external fun userAgentBuilderWithSegment(
        builder: NativeHandle,
        name: String,
        version: String,
    ): Long

    @JvmStatic external fun userAgentBuilderWithAppSegmentForClient(
        builder: NativeHandle,
        appVersion: String,
        clientName: String,
    ): Long

    @JvmStatic external fun userAgentBuilderWithWalletkitSegment(builder: NativeHandle): Long

    @JvmStatic external fun userAgentBuilderWithClientSegment(
        builder: NativeHandle,
        clientName: String,
        osVersion: String,
    ): Long

    @JvmStatic external fun userAgentBuilderBuild(builder: NativeHandle): Long

    @JvmStatic external fun storagePathsFromRoot(root: String): Long

    @JvmStatic external fun storagePathsRootPathString(paths: NativeHandle): String

    @JvmStatic external fun storagePathsWorldidDirPathString(paths: NativeHandle): String

    @JvmStatic external fun storagePathsVaultDbPathString(paths: NativeHandle): String

    @JvmStatic external fun storagePathsCacheDbPathString(paths: NativeHandle): String

    @JvmStatic external fun storagePathsLockPathString(paths: NativeHandle): String

    @JvmStatic external fun storagePathsGroth16DirPathString(paths: NativeHandle): String

    @JvmStatic external fun storagePathsQueryZkeyPathString(paths: NativeHandle): String

    @JvmStatic external fun storagePathsNullifierZkeyPathString(paths: NativeHandle): String

    @JvmStatic external fun storagePathsQueryGraphPathString(paths: NativeHandle): String

    @JvmStatic external fun storagePathsNullifierGraphPathString(paths: NativeHandle): String

    @JvmStatic external fun credentialStoreNewWithComponents(
        paths: NativeHandle,
        keystore: DeviceKeystore,
        blobStore: AtomicBlobStore,
    ): Long

    @JvmStatic external fun credentialStoreStoragePaths(store: NativeHandle): Long

    @JvmStatic external fun credentialStoreInitialize(
        store: NativeHandle,
        leafIndex: Long,
        now: Long,
    )

    @JvmStatic external fun credentialStoreListCredentials(
        store: NativeHandle,
        issuerSchemaId: Long?,
        now: Long,
    ): ByteArray

    @JvmStatic external fun credentialStoreFetchCredential(
        store: NativeHandle,
        issuerSchemaId: Long,
        now: Long,
    ): Long

    @JvmStatic external fun credentialStoreDeleteCredential(
        store: NativeHandle,
        credentialId: Long,
    )

    @JvmStatic external fun credentialStoreStoreCredential(
        store: NativeHandle,
        credential: NativeHandle,
        blindingFactor: NativeHandle,
        expiresAt: Long,
        associatedData: ByteArray?,
        now: Long,
    ): Long

    @JvmStatic external fun credentialStoreDangerDeleteAllCredentials(store: NativeHandle): Long

    @JvmStatic external fun credentialStoreRecordActivity(
        store: NativeHandle,
        entry: ByteArray,
        now: Long,
    ): Long

    @JvmStatic external fun credentialStoreListActivities(
        store: NativeHandle,
        issuerSchemaId: Long?,
        limit: Int,
        offset: Int,
    ): ByteArray

    @JvmStatic external fun credentialStoreActivityMetadata(store: NativeHandle): Long

    @JvmStatic external fun credentialStoreClearActivities(store: NativeHandle): Long

    @JvmStatic external fun credentialStoreDestroyStorage(store: NativeHandle)

    @JvmStatic external fun credentialStoreExportVaultForBackup(store: NativeHandle): ByteArray

    @JvmStatic external fun credentialStoreImportVaultFromBackup(
        store: NativeHandle,
        backupBytes: ByteArray,
    )

    @JvmStatic external fun credentialStoreMergeVaultFromBackup(
        store: NativeHandle,
        backupBytes: ByteArray,
    ): Long

    @JvmStatic external fun credentialStoreSetVaultChangedListener(
        store: NativeHandle,
        listener: VaultChangedListener,
    )

    @JvmStatic external fun credentialStoreSetActivityChangedListener(
        store: NativeHandle,
        listener: ActivityChangedListener,
    )

    @JvmStatic external fun checkCredentialsAgainstProofRequest(
        request: NativeHandle,
        store: NativeHandle,
        now: Long,
    ): ByteArray

    @JvmStatic external fun emitLog(
        level: Int,
        message: String,
    )

    @JvmStatic external fun initLogging(
        logger: Logger,
        level: Int,
    )

    @JvmStatic external fun sanitizeHexSecrets(input: String): String

    @JvmStatic external fun validateAuthenticatorPubkey(authenticatorPubkey: String): String

    @JvmStatic external fun recoveryDataFromSeed(seed: ByteArray): ByteArray

    @JvmStatic external fun environmentPohRecoveryAgentAddress(environment: Int): String

    @JvmStatic external fun environmentWorldIdVerifierAddress(environment: Int): String

    @JvmStatic external fun authenticatorInitStorage(
        authenticator: NativeHandle,
        now: Long,
    )

    @JvmStatic external fun authenticatorDestroyStorage(authenticator: NativeHandle)

    @JvmStatic external fun authenticatorPackedAccountData(authenticator: NativeHandle): ByteArray

    @JvmStatic external fun authenticatorLeafIndex(authenticator: NativeHandle): Long

    @JvmStatic external fun authenticatorOnchainAddress(authenticator: NativeHandle): String

    @JvmStatic external fun authenticatorGetPackedAccountDataRemote(
        operation: Long,
        authenticator: NativeHandle,
    ): ByteArray

    @JvmStatic external fun authenticatorGenerateCredentialBlindingFactorRemote(
        operation: Long,
        authenticator: NativeHandle,
        issuerSchemaId: Long,
    ): Long

    @JvmStatic external fun authenticatorComputeCredentialSub(
        authenticator: NativeHandle,
        blindingFactor: NativeHandle,
    ): Long

    @JvmStatic external fun authenticatorDangerSignChallenge(
        authenticator: NativeHandle,
        challenge: ByteArray,
    ): ByteArray

    @JvmStatic external fun authenticatorDangerSignInitiateRecoveryAgentUpdate(
        operation: Long,
        authenticator: NativeHandle,
        newRecoveryAgent: String,
    ): ByteArray

    @JvmStatic external fun authenticatorUpdateRecoveryAgent(
        operation: Long,
        authenticator: NativeHandle,
        newRecoveryAgent: String,
    ): String

    @JvmStatic external fun authenticatorRevertRecoveryAgentUpdate(
        operation: Long,
        authenticator: NativeHandle,
    ): String

    @JvmStatic external fun authenticatorInsertAuthenticator(
        operation: Long,
        authenticator: NativeHandle,
        newAuthenticatorPubkey: String,
        newAuthenticatorAddress: String,
    ): String

    @JvmStatic external fun authenticatorHasAuthenticatorPubkey(
        operation: Long,
        authenticator: NativeHandle,
        authenticatorPubkey: String,
    ): Boolean

    @JvmStatic external fun authenticatorGetAuthenticatorPubkeys(
        operation: Long,
        authenticator: NativeHandle,
    ): ByteArray

    @JvmStatic external fun authenticatorRemoveAuthenticator(
        operation: Long,
        authenticator: NativeHandle,
        authenticatorAddress: String,
        pubkeyId: Int,
        expectedAuthenticatorPubkey: String,
    ): String

    @JvmStatic external fun authenticatorPollStatus(
        operation: Long,
        authenticator: NativeHandle,
        requestId: String,
    ): ByteArray

    @JvmStatic external fun authenticatorGenerateProof(
        operation: Long,
        authenticator: NativeHandle,
        proofRequest: NativeHandle,
        now: Long?,
    ): Long

    @JvmStatic external fun authenticatorProveCredentialSub(
        operation: Long,
        authenticator: NativeHandle,
        nonce: NativeHandle,
        context: NativeHandle,
        blindingFactor: NativeHandle,
        sub: NativeHandle,
    ): Long

    @JvmStatic external fun authenticatorInitWithDefaults(
        operation: Long,
        seed: ByteArray,
        rpcUrl: String?,
        environment: Int,
        region: Int,
        artifacts: NativeHandle,
        store: NativeHandle,
    ): Long

    @JvmStatic external fun authenticatorInitWithOhttpDefaults(
        operation: Long,
        seed: ByteArray,
        rpcUrl: String?,
        environment: Int,
        region: Int,
        artifacts: NativeHandle,
        store: NativeHandle,
    ): Long

    @JvmStatic external fun authenticatorInit(
        operation: Long,
        seed: ByteArray,
        config: String,
        artifacts: NativeHandle,
        store: NativeHandle,
    ): Long

    @JvmStatic external fun initializingAuthenticatorRegisterWithDefaults(
        operation: Long,
        seed: ByteArray,
        rpcUrl: String?,
        environment: Int,
        region: Int,
        recoveryAddress: String?,
    ): Long

    @JvmStatic external fun initializingAuthenticatorRegisterWithOhttpDefaults(
        operation: Long,
        seed: ByteArray,
        rpcUrl: String?,
        environment: Int,
        region: Int,
        recoveryAddress: String?,
    ): Long

    @JvmStatic external fun initializingAuthenticatorRegister(
        operation: Long,
        seed: ByteArray,
        config: String,
        recoveryAddress: String?,
    ): Long

    @JvmStatic external fun initializingAuthenticatorPollStatus(
        operation: Long,
        authenticator: NativeHandle,
    ): ByteArray

    @JvmStatic external fun embeddedZkArtifactsNew(): Long

    @JvmStatic external fun embeddedZkArtifactsAsZkArtifactSource(artifacts: NativeHandle): Long

    @JvmStatic external fun cachingZkArtifactsNew(storagePaths: NativeHandle): Long

    @JvmStatic external fun cachingZkArtifactsAsZkArtifactSource(artifacts: NativeHandle): Long

    @JvmStatic external fun cachingZkArtifactsPreload(artifacts: NativeHandle)

    @JvmStatic external fun addressBookNew(): Long

    @JvmStatic external fun addressBookGenerateProofContext(
        addressBook: NativeHandle,
        addressToVerify: String,
        timestamp: Long,
    ): Long

    @JvmStatic external fun worldIdNew(
        secret: ByteArray,
        environment: Int,
    ): Long

    @JvmStatic external fun worldIdGenerateNullifierHash(
        worldId: NativeHandle,
        context: NativeHandle,
    ): ByteArray

    @JvmStatic external fun worldIdGetIdentityCommitment(
        worldId: NativeHandle,
        credentialType: Int,
    ): ByteArray

    @JvmStatic external fun worldIdGenerateProof(
        operation: Long,
        worldId: NativeHandle,
        context: NativeHandle,
    ): Long

    @JvmStatic external fun worldIdIsEqualTo(
        worldId: NativeHandle,
        other: NativeHandle,
    ): Boolean

    @JvmStatic external fun proofContextNew(
        appId: String,
        action: String?,
        signal: String?,
        credentialType: Int,
    ): Long

    @JvmStatic external fun proofContextNewFromBytes(
        appId: String,
        action: ByteArray?,
        signal: ByteArray?,
        credentialType: Int,
    ): Long

    @JvmStatic external fun proofContextNewFromSignalHash(
        appId: String,
        action: ByteArray?,
        credentialType: Int,
        signalHash: ByteArray,
    ): Long

    @JvmStatic external fun proofContextGetExternalNullifier(context: NativeHandle): ByteArray

    @JvmStatic external fun proofContextGetSignalHash(context: NativeHandle): ByteArray

    @JvmStatic external fun proofContextGetCredentialType(context: NativeHandle): Int

    @JvmStatic external fun proofContextLegacyNewFromPreImageExternalNullifier(
        externalNullifier: ByteArray,
        credentialType: Int,
        signal: ByteArray?,
        requireMinedProof: Boolean,
    ): Long

    @JvmStatic external fun proofContextLegacyNewFromRawExternalNullifier(
        externalNullifier: ByteArray,
        credentialType: Int,
        signal: ByteArray?,
        requireMinedProof: Boolean,
    ): Long

    @JvmStatic external fun proofOutputToJson(output: NativeHandle): String

    @JvmStatic external fun proofOutputGetNullifierHash(output: NativeHandle): ByteArray

    @JvmStatic external fun proofOutputGetMerkleRoot(output: NativeHandle): ByteArray

    @JvmStatic external fun proofOutputGetProofAsString(output: NativeHandle): String

    @JvmStatic external fun proofOutputGetCredentialType(output: NativeHandle): Int

    @JvmStatic external fun merkleTreeProofFromIdentityCommitment(
        operation: Long,
        identityCommitment: ByteArray,
        sequencerHost: String,
        requireMinedProof: Boolean,
    ): Long

    @JvmStatic external fun merkleTreeProofFromJsonProof(
        jsonProof: String,
        merkleRoot: String,
    ): Long

    @JvmStatic external fun tfhNfcIssuerNew(
        environment: Int,
        userAgent: String,
    ): Long

    @JvmStatic external fun tfhNfcIssuerRefreshNfcCredential(
        operation: Long,
        issuer: NativeHandle,
        requestBody: String,
        headers: ByteArray,
    ): Long

    @JvmStatic external fun recoveryBindingManagerNew(
        environment: Int,
        userAgentBuilder: NativeHandle,
    ): Long

    @JvmStatic external fun recoveryBindingManagerNewWithBaseUrl(
        baseUrl: String,
        userAgentBuilder: NativeHandle,
    ): Long

    @JvmStatic external fun recoveryBindingManagerBindRecoveryAgent(
        operation: Long,
        manager: NativeHandle,
        authenticator: NativeHandle,
        sub: String,
        recoveryAgentAddress: String,
    )

    @JvmStatic external fun recoveryBindingManagerUnbindRecoveryAgent(
        operation: Long,
        manager: NativeHandle,
        authenticator: NativeHandle,
        sub: String,
    )

    @JvmStatic external fun recoveryBindingManagerGetRecoveryBinding(
        operation: Long,
        manager: NativeHandle,
        leafIndex: Long,
    ): ByteArray

    @JvmStatic external fun verifiedMatchTokenMatchCoefficient(token: NativeHandle): Float

    @JvmStatic external fun flamingoMatcherNew(hostUrl: String): Long

    @JvmStatic external fun flamingoMatcherNewAttested(
        hostUrl: String,
        integrityProvider: RequestIntegrityProvider,
    ): Long

    @JvmStatic external fun flamingoMatcherWithMeasurements(
        matcher: NativeHandle,
        measurements: ByteArray,
    ): Long

    @JvmStatic external fun flamingoMatcherDangerouslySkipMeasurements(matcher: NativeHandle): Long

    @JvmStatic external fun flamingoMatcherWithHeaders(
        matcher: NativeHandle,
        headers: ByteArray,
    ): Long

    @JvmStatic external fun flamingoMatcherPerformMatch(
        operation: Long,
        matcher: NativeHandle,
        request: ByteArray,
    ): ByteArray

    // Called by Rust; consumer rules keep these names and signatures.
    @JvmStatic fun nativeError(details: ByteArray): Throwable = decodeNativeError(details)

    @JvmStatic fun callbackError(failure: Throwable): ByteArray? =
        (failure as? StorageException)?.let { NativeWriter.encode { writeStorageException(it) } }

    @JvmStatic fun log(
        logger: Logger,
        level: Int,
        message: String,
    ) = logger.log(LogLevel.entries[level], message)

    // A completion that cannot be delivered (for example an invalid token) must not crash
    // the app; Rust then reports a timeout for that connection.
    private val integrityScope =
        CoroutineScope(SupervisorJob() + Dispatchers.Default + CoroutineExceptionHandler { _, _ -> })

    @JvmStatic fun prepareIntegrity(
        provider: RequestIntegrityProvider,
        completion: Long,
    ) {
        integrityScope.launch {
            val session =
                try {
                    provider.prepare()
                } catch (failure: RequestIntegrityException) {
                    integrityFailed(completion, failure.ordinal)
                    return@launch
                } catch (failure: Throwable) {
                    // Host messages may contain secrets; only the failure class crosses.
                    integrityFailed(completion, RequestIntegrityException.CallbackFailed().ordinal)
                    if (failure is CancellationException) throw failure
                    return@launch
                }
            integrityPrepared(completion, session.token, session.platform.ordinal, session.signer)
        }
    }
}

internal class NativeHandle(
    id: Long,
) : AutoCloseable {
    // Read by Rust entry points, which reject zero as closed.
    @JvmField @Volatile
    var id: Long = id
    private val state = HandleState(id)
    private val reference = NativeCleaner.register(this, state)

    override fun close() {
        id = 0
        state.close()
        NativeCleaner.remove(reference)
    }
}

internal class HandleState(
    private var id: Long,
) : AutoCloseable {
    override fun close() {
        val owned = synchronized(this) { id.also { id = 0 } }
        if (owned != 0L) NativeBridge.objectRelease(owned)
    }
}

// AutoCloseable is deterministic; the queue is a fallback for abandoned resources on API 23+.
private object NativeCleaner {
    private val queue = ReferenceQueue<NativeHandle>()
    private val states = ConcurrentHashMap<PhantomReference<NativeHandle>, HandleState>()

    init {
        Thread({
            try {
                while (true) {
                    val reference = queue.remove()
                    states.remove(reference)?.close()
                    reference.clear()
                }
            } catch (interrupted: InterruptedException) {
                Thread.currentThread().interrupt()
                System.err.println("WalletKit native cleanup thread interrupted")
            }
        }, "walletkit-cleanup").apply { isDaemon = true }.start()
    }

    fun register(
        handle: NativeHandle,
        state: HandleState,
    ): PhantomReference<NativeHandle> = PhantomReference(handle, queue).also { states[it] = state }

    fun remove(reference: PhantomReference<NativeHandle>) {
        states.remove(reference)
        reference.clear()
    }
}

/**
 * Runs blocking native calls for `suspend` methods on four workers with 128 queued calls;
 * further calls fail with `Busy`. Cancelling the coroutine cancels the native operation,
 * which stops at its next yield point; a result that arrives after cancellation is released.
 */
internal object NativeCalls {
    private val executor =
        ThreadPoolExecutor(
            4,
            4,
            0L,
            TimeUnit.MILLISECONDS,
            ArrayBlockingQueue(128),
            { work -> Thread(work, "walletkit-native").apply { isDaemon = true } },
            ThreadPoolExecutor.AbortPolicy(),
        )

    @OptIn(ExperimentalCoroutinesApi::class)
    suspend fun <T> async(
        release: (T) -> Unit = { (it as? AutoCloseable)?.close() },
        call: (Long) -> T,
    ): T {
        val operation = NativeBridge.operationNew()
        return suspendCancellableCoroutine { continuation ->
            continuation.invokeOnCancellation { NativeBridge.operationCancel(operation) }
            val work =
                Runnable {
                    val result =
                        try {
                            Result.success(call(operation))
                        } catch (failure: Throwable) {
                            Result.failure(failure)
                        } finally {
                            NativeBridge.objectRelease(operation)
                        }
                    result.fold(
                        { value -> continuation.resume(value) { release(value) } },
                        { failure -> continuation.resumeWithException(failure) },
                    )
                }
            try {
                executor.execute(work)
            } catch (rejected: RejectedExecutionException) {
                NativeBridge.objectRelease(operation)
                continuation.resumeWithException(WalletKitBridgeException("Busy"))
            }
        }
    }
}

/** Unsigned 256-bit integer. The immutable hexadecimal representation has exactly 64 digits. */
class Uint256 private constructor(
    val hex: String,
) {
    fun toBytes(): ByteArray =
        hex
            .drop(2)
            .chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()

    override fun equals(other: Any?): Boolean = other is Uint256 && hex == other.hex

    override fun hashCode(): Int = hex.hashCode()

    override fun toString(): String = hex

    companion object {
        fun fromHex(value: String): Uint256 {
            val digits = value.removePrefix("0x")
            require(
                digits.isNotEmpty() && digits.length <= 64 &&
                    digits.all {
                        it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F'
                    },
            ) { "Invalid unsigned 256-bit integer" }
            return Uint256("0x" + digits.lowercase().padStart(64, '0'))
        }

        fun fromBytes(value: ByteArray): Uint256 {
            require(value.size == 32) { "Expected 32 bytes" }
            return fromHex(value.joinToString("") { "%02x".format(it.toInt() and 255) })
        }
    }
}
