package org.world.walletkit

class RecoveryBindingManager internal constructor(
    internal val handle: NativeHandle,
) : AutoCloseable {
    override fun close() = handle.close()

    suspend fun bindRecoveryAgent(
        authenticator: Authenticator,
        sub: String,
        recoveryAgentAddress: String,
    ): Unit =
        NativeCalls.async { operation ->
            NativeBridge.recoveryBindingManagerBindRecoveryAgent(operation, handle, authenticator.handle, sub, recoveryAgentAddress)
        }

    suspend fun unbindRecoveryAgent(
        authenticator: Authenticator,
        sub: String,
    ): Unit =
        NativeCalls.async { operation ->
            NativeBridge.recoveryBindingManagerUnbindRecoveryAgent(operation, handle, authenticator.handle, sub)
        }

    suspend fun getRecoveryBinding(leafIndex: ULong): RecoveryBinding =
        NativeCalls.async { operation ->
            NativeReader.decode(
                NativeBridge.recoveryBindingManagerGetRecoveryBinding(operation, handle, leafIndex.toLong()),
            ) { readRecoveryBinding() }
        }

    companion object {
        fun create(
            environment: Environment,
            userAgentBuilder: UserAgentBuilder,
        ): RecoveryBindingManager =
            RecoveryBindingManager(NativeHandle(NativeBridge.recoveryBindingManagerNew(environment.ordinal, userAgentBuilder.handle)))

        fun newWithBaseUrl(
            baseUrl: String,
            userAgentBuilder: UserAgentBuilder,
        ): RecoveryBindingManager =
            RecoveryBindingManager(NativeHandle(NativeBridge.recoveryBindingManagerNewWithBaseUrl(baseUrl, userAgentBuilder.handle)))
    }
}
