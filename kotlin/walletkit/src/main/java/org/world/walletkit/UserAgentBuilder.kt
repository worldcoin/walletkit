package org.world.walletkit

class UserAgentBuilder internal constructor(
    internal val handle: NativeHandle,
) : AutoCloseable {
    override fun close() = handle.close()

    fun withSegment(
        name: String,
        version: String,
    ): UserAgentBuilder = UserAgentBuilder(NativeHandle(NativeBridge.userAgentBuilderWithSegment(handle, name, version)))

    fun withAppSegmentForClient(
        appVersion: String,
        clientName: String,
    ): UserAgentBuilder =
        UserAgentBuilder(NativeHandle(NativeBridge.userAgentBuilderWithAppSegmentForClient(handle, appVersion, clientName)))

    fun withWalletkitSegment(): UserAgentBuilder = UserAgentBuilder(NativeHandle(NativeBridge.userAgentBuilderWithWalletkitSegment(handle)))

    fun withClientSegment(
        clientName: String,
        osVersion: String,
    ): UserAgentBuilder = UserAgentBuilder(NativeHandle(NativeBridge.userAgentBuilderWithClientSegment(handle, clientName, osVersion)))

    fun build(): UserAgent = UserAgent(NativeHandle(NativeBridge.userAgentBuilderBuild(handle)))

    companion object {
        fun create(): UserAgentBuilder = UserAgentBuilder(NativeHandle(NativeBridge.userAgentBuilderNew()))
    }
}
