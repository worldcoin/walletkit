package org.world.walletkit

class ProofContext internal constructor(
    internal val handle: NativeHandle,
) : AutoCloseable {
    override fun close() = handle.close()

    fun getExternalNullifier(): Uint256 = Uint256.fromBytes(NativeBridge.proofContextGetExternalNullifier(handle))

    fun getSignalHash(): Uint256 = Uint256.fromBytes(NativeBridge.proofContextGetSignalHash(handle))

    fun getCredentialType(): CredentialType = CredentialType.entries[NativeBridge.proofContextGetCredentialType(handle)]

    companion object {
        fun create(
            appId: String,
            action: String?,
            signal: String?,
            credentialType: CredentialType,
        ): ProofContext = ProofContext(NativeHandle(NativeBridge.proofContextNew(appId, action, signal, credentialType.ordinal)))

        fun newFromBytes(
            appId: String,
            action: ByteArray?,
            signal: ByteArray?,
            credentialType: CredentialType,
        ): ProofContext = ProofContext(NativeHandle(NativeBridge.proofContextNewFromBytes(appId, action, signal, credentialType.ordinal)))

        fun newFromSignalHash(
            appId: String,
            action: ByteArray?,
            credentialType: CredentialType,
            signalHash: Uint256,
        ): ProofContext =
            ProofContext(
                NativeHandle(NativeBridge.proofContextNewFromSignalHash(appId, action, credentialType.ordinal, signalHash.toBytes())),
            )

        fun legacyNewFromPreImageExternalNullifier(
            externalNullifier: ByteArray,
            credentialType: CredentialType,
            signal: ByteArray?,
            requireMinedProof: Boolean,
        ): ProofContext =
            ProofContext(
                NativeHandle(
                    NativeBridge.proofContextLegacyNewFromPreImageExternalNullifier(
                        externalNullifier,
                        credentialType.ordinal,
                        signal,
                        requireMinedProof,
                    ),
                ),
            )

        fun legacyNewFromRawExternalNullifier(
            externalNullifier: Uint256,
            credentialType: CredentialType,
            signal: ByteArray?,
            requireMinedProof: Boolean,
        ): ProofContext =
            ProofContext(
                NativeHandle(
                    NativeBridge.proofContextLegacyNewFromRawExternalNullifier(
                        externalNullifier.toBytes(),
                        credentialType.ordinal,
                        signal,
                        requireMinedProof,
                    ),
                ),
            )
    }
}
