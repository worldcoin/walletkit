package org.world.walletkit

class MerkleTreeProof internal constructor(
    internal val handle: NativeHandle,
) : AutoCloseable {
    override fun close() = handle.close()

    companion object {
        suspend fun fromIdentityCommitment(
            identityCommitment: Uint256,
            sequencerHost: String,
            requireMinedProof: Boolean,
        ): MerkleTreeProof =
            NativeCalls.async { operation ->
                MerkleTreeProof(
                    NativeHandle(
                        NativeBridge.merkleTreeProofFromIdentityCommitment(
                            operation,
                            identityCommitment.toBytes(),
                            sequencerHost,
                            requireMinedProof,
                        ),
                    ),
                )
            }

        fun fromJsonProof(
            jsonProof: String,
            merkleRoot: String,
        ): MerkleTreeProof = MerkleTreeProof(NativeHandle(NativeBridge.merkleTreeProofFromJsonProof(jsonProof, merkleRoot)))
    }
}
