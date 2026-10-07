package org.world.walletkit

class InitializingAuthenticator internal constructor(
    internal val handle: NativeHandle,
) : AutoCloseable {
    override fun close() = handle.close()

    suspend fun pollStatus(): RegistrationStatus =
        NativeCalls.async { operation ->
            NativeReader.decode(NativeBridge.initializingAuthenticatorPollStatus(operation, handle)) { readRegistrationStatus() }
        }

    companion object {
        suspend fun registerWithDefaults(
            seed: ByteArray,
            rpcUrl: String?,
            environment: Environment,
            region: Region?,
            recoveryAddress: String?,
        ): InitializingAuthenticator =
            NativeCalls.async { operation ->
                InitializingAuthenticator(
                    NativeHandle(
                        NativeBridge.initializingAuthenticatorRegisterWithDefaults(
                            operation,
                            seed,
                            rpcUrl,
                            environment.ordinal,
                            region?.ordinal ?: -1,
                            recoveryAddress,
                        ),
                    ),
                )
            }

        suspend fun registerWithOhttpDefaults(
            seed: ByteArray,
            rpcUrl: String?,
            environment: Environment,
            region: Region?,
            recoveryAddress: String?,
        ): InitializingAuthenticator =
            NativeCalls.async { operation ->
                InitializingAuthenticator(
                    NativeHandle(
                        NativeBridge.initializingAuthenticatorRegisterWithOhttpDefaults(
                            operation,
                            seed,
                            rpcUrl,
                            environment.ordinal,
                            region?.ordinal ?: -1,
                            recoveryAddress,
                        ),
                    ),
                )
            }

        suspend fun register(
            seed: ByteArray,
            config: String,
            recoveryAddress: String?,
        ): InitializingAuthenticator =
            NativeCalls.async { operation ->
                InitializingAuthenticator(
                    NativeHandle(NativeBridge.initializingAuthenticatorRegister(operation, seed, config, recoveryAddress)),
                )
            }
    }
}
