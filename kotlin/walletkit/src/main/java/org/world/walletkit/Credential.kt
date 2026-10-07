package org.world.walletkit

class Credential internal constructor(
    internal val handle: NativeHandle,
) : AutoCloseable {
    override fun close() = handle.close()

    fun sub(): FieldElement = FieldElement(NativeHandle(NativeBridge.credentialSub(handle)))

    fun issuerSchemaId(): ULong = NativeBridge.credentialIssuerSchemaId(handle).toULong()

    fun expiresAt(): ULong = NativeBridge.credentialExpiresAt(handle).toULong()

    fun associatedDataCommitment(): FieldElement = FieldElement(NativeHandle(NativeBridge.credentialAssociatedDataCommitment(handle)))

    fun claims(): List<FieldElement> = NativeReader.decode(NativeBridge.credentialClaims(handle)) { list { FieldElement(handle()) } }

    fun claimsHex(): List<String> = NativeReader.decode(NativeBridge.credentialClaimsHex(handle)) { list { string() } }

    companion object {
        fun fromBytes(bytes: ByteArray): Credential = Credential(NativeHandle(NativeBridge.credentialFromBytes(bytes)))
    }
}
