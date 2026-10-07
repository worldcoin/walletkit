import Foundation
internal import walletkit_coreFFI

/// A Rust-owned WorldId resource. Closing rejects new calls; running calls retain their inputs.
public final class WorldId: @unchecked Sendable {
  let handle: NativeHandle
  init(handle: NativeHandle) { self.handle = handle }
  public func close() { handle.close() }
}

extension WorldId {
  public static func create(secret: Data, environment: Environment) throws -> WorldId {
    try withByteSlice(secret) { secretSlice in
      WorldId(
        handle: NativeHandle(
          try call(WalletKitWorldIdHandle(id: 0)) {
            walletkit_world_id_new(
              secretSlice, ordinal(environment, in: Environment.ordinals), $0, $1)
          }.id))
    }
  }
  public func generateNullifierHash(context: ProofContext) throws -> Uint256 {
    try handle.withID { worldIdID in
      try context.handle.withID { contextID in
        Uint256(
          native: try call(WalletKitUint256()) {
            walletkit_world_id_generate_nullifier_hash(
              WalletKitWorldIdHandle(id: worldIdID), WalletKitProofContextHandle(id: contextID), $0,
              $1)
          })
      }
    }
  }
  public func getIdentityCommitment(credentialType: CredentialType) throws -> Uint256 {
    try handle.withID { worldIdID in
      Uint256(
        native: try call(WalletKitUint256()) {
          walletkit_world_id_get_identity_commitment(
            WalletKitWorldIdHandle(id: worldIdID),
            ordinal(credentialType, in: CredentialType.ordinals), $0, $1)
        })
    }
  }
  public func generateProof(context: ProofContext) async throws -> ProofOutput {
    try await NativeBridge.async { operation in
      try self.handle.withID { worldIdID in
        try context.handle.withID { contextID in
          ProofOutput(
            handle: NativeHandle(
              try call(WalletKitProofOutputHandle(id: 0)) {
                walletkit_world_id_generate_proof(
                  operation, WalletKitWorldIdHandle(id: worldIdID),
                  WalletKitProofContextHandle(id: contextID), $0, $1)
              }.id))
        }
      }
    }
  }
  public func isEqualTo(other: WorldId) throws -> Bool {
    try handle.withID { worldIdID in
      try other.handle.withID { otherID in
        try call(false) {
          walletkit_world_id_is_equal_to(
            WalletKitWorldIdHandle(id: worldIdID), WalletKitWorldIdHandle(id: otherID), $0, $1)
        }
      }
    }
  }
}
