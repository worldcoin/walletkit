package org.world.walletkit

class TfhNfcIssuer internal constructor(
    internal val handle: NativeHandle,
) : AutoCloseable {
    override fun close() = handle.close()

    suspend fun refreshNfcCredential(
        requestBody: String,
        headers: Map<String, String>,
    ): Credential =
        NativeCalls.async { operation ->
            Credential(
                NativeHandle(
                    NativeBridge.tfhNfcIssuerRefreshNfcCredential(
                        operation,
                        handle,
                        requestBody,
                        NativeWriter.encode {
                            writeStringMap(headers)
                        },
                    ),
                ),
            )
        }

    companion object {
        fun create(
            environment: Environment,
            userAgent: String,
        ): TfhNfcIssuer = TfhNfcIssuer(NativeHandle(NativeBridge.tfhNfcIssuerNew(environment.ordinal, userAgent)))
    }
}
