package org.world.walletkit

object WalletKit {
    fun checkCredentialsAgainstProofRequest(
        request: ProofRequest,
        store: CredentialStore,
        now: ULong,
    ): CredentialConstraintsCheckResult =
        NativeReader.decode(NativeBridge.checkCredentialsAgainstProofRequest(request.handle, store.handle, now.toLong())) {
            readCredentialConstraintsCheckResult()
        }

    fun emitLog(
        level: LogLevel,
        message: String,
    ): Unit = NativeBridge.emitLog(level.ordinal, message)

    fun initLogging(
        logger: Logger,
        level: LogLevel?,
    ): Unit = NativeBridge.initLogging(logger, level?.ordinal ?: -1)

    fun sanitizeHexSecrets(input: String): String = NativeBridge.sanitizeHexSecrets(input)

    fun validateAuthenticatorPubkey(authenticatorPubkey: String): String = NativeBridge.validateAuthenticatorPubkey(authenticatorPubkey)

    fun recoveryDataFromSeed(seed: ByteArray): RecoveryData =
        NativeReader.decode(NativeBridge.recoveryDataFromSeed(seed)) { readRecoveryData() }
}
