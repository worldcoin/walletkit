import Foundation
internal import walletkit_coreFFI

/// A Rust-owned MerkleTreeProof resource. Closing rejects new calls; running calls retain their inputs.
public final class MerkleTreeProof: @unchecked Sendable {
  let handle: NativeHandle
  init(handle: NativeHandle) { self.handle = handle }
  public func close() { handle.close() }
}

extension MerkleTreeProof {
  public static func fromIdentityCommitment(
    identityCommitment: Uint256, sequencerHost: String, requireMinedProof: Bool
  ) async throws -> MerkleTreeProof {
    try await NativeBridge.async { operation in
      try withByteSlice(sequencerHost) { sequencerHostSlice in
        MerkleTreeProof(
          handle: NativeHandle(
            try call(WalletKitMerkleTreeProofHandle(id: 0)) {
              walletkit_merkle_tree_proof_from_identity_commitment(
                operation, identityCommitment.native, sequencerHostSlice, requireMinedProof, $0, $1)
            }.id))
      }
    }
  }
  public static func fromJsonProof(jsonProof: String, merkleRoot: String) throws -> MerkleTreeProof
  {
    try withByteSlice(jsonProof) { jsonProofSlice in
      try withByteSlice(merkleRoot) { merkleRootSlice in
        MerkleTreeProof(
          handle: NativeHandle(
            try call(WalletKitMerkleTreeProofHandle(id: 0)) {
              walletkit_merkle_tree_proof_from_json_proof(jsonProofSlice, merkleRootSlice, $0, $1)
            }.id))
      }
    }
  }
}
