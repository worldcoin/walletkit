package org.world.walletkit

class FieldElement internal constructor(
    internal val handle: NativeHandle,
) : AutoCloseable {
    override fun close() = handle.close()

    fun toBytes(): ByteArray = NativeBridge.fieldElementToBytes(handle)

    fun toHexString(): String = NativeBridge.fieldElementToHexString(handle)

    companion object {
        fun fromBytes(bytes: ByteArray): FieldElement = FieldElement(NativeHandle(NativeBridge.fieldElementFromBytes(bytes)))

        fun fromU64(value: ULong): FieldElement = FieldElement(NativeHandle(NativeBridge.fieldElementFromU64(value.toLong())))

        fun tryFromHexString(hexString: String): FieldElement =
            FieldElement(NativeHandle(NativeBridge.fieldElementTryFromHexString(hexString)))
    }
}
