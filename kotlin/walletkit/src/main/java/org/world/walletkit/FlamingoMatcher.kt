package org.world.walletkit

class FlamingoMatcher internal constructor(
    internal val handle: NativeHandle,
) : AutoCloseable {
    override fun close() = handle.close()

    fun withMeasurements(measurements: Map<UInt, ByteArray>): FlamingoMatcher =
        FlamingoMatcher(
            NativeHandle(NativeBridge.flamingoMatcherWithMeasurements(handle, NativeWriter.encode { writeMeasurements(measurements) })),
        )

    /** Disables enclave measurement pins, accepting any otherwise valid attested code, including debug enclaves. Development only; never use in production. */
    fun dangerouslySkipMeasurements(): FlamingoMatcher =
        FlamingoMatcher(NativeHandle(NativeBridge.flamingoMatcherDangerouslySkipMeasurements(handle)))

    fun withHeaders(headers: Map<String, String>): FlamingoMatcher =
        FlamingoMatcher(NativeHandle(NativeBridge.flamingoMatcherWithHeaders(handle, NativeWriter.encode { writeStringMap(headers) })))

    suspend fun performMatch(request: FlamingoMatchRequest): FlamingoMatchOutcome =
        NativeCalls.async(release = {
            (it as? FlamingoMatchOutcome.Matched)?.token?.close()
        }) { operation ->
            NativeReader.decode(
                NativeBridge.flamingoMatcherPerformMatch(
                    operation,
                    handle,
                    NativeWriter.encode {
                        writeFlamingoMatchRequest(request)
                    },
                ),
            ) { readFlamingoMatchOutcome() }
        }

    companion object {
        fun create(hostUrl: String): FlamingoMatcher = FlamingoMatcher(NativeHandle(NativeBridge.flamingoMatcherNew(hostUrl)))

        fun newAttested(
            hostUrl: String,
            integrityProvider: RequestIntegrityProvider,
        ): FlamingoMatcher = FlamingoMatcher(NativeHandle(NativeBridge.flamingoMatcherNewAttested(hostUrl, integrityProvider)))
    }
}
