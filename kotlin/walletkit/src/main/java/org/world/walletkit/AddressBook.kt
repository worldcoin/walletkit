package org.world.walletkit

class AddressBook internal constructor(
    internal val handle: NativeHandle,
) : AutoCloseable {
    override fun close() = handle.close()

    fun generateProofContext(
        addressToVerify: String,
        timestamp: ULong,
    ): ProofContext = ProofContext(NativeHandle(NativeBridge.addressBookGenerateProofContext(handle, addressToVerify, timestamp.toLong())))

    companion object {
        fun create(): AddressBook = AddressBook(NativeHandle(NativeBridge.addressBookNew()))
    }
}
