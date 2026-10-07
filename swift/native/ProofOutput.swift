import Foundation
internal import walletkit_coreFFI

/// A Rust-owned ProofOutput resource. Closing rejects new calls; running calls retain their inputs.
public final class ProofOutput: @unchecked Sendable {
  let handle: NativeHandle
  init(handle: NativeHandle) { self.handle = handle }
  public func close() { handle.close() }
}

extension ProofOutput {
  public func toJson() throws -> String {
    try handle.withID { outputID in
      try callString {
        walletkit_proof_output_to_json(WalletKitProofOutputHandle(id: outputID), $0, $1)
      }
    }
  }
  public func getNullifierHash() throws -> Uint256 {
    try handle.withID { outputID in
      Uint256(
        native: try call(WalletKitUint256()) {
          walletkit_proof_output_get_nullifier_hash(
            WalletKitProofOutputHandle(id: outputID), $0, $1)
        })
    }
  }
  public func getMerkleRoot() throws -> Uint256 {
    try handle.withID { outputID in
      Uint256(
        native: try call(WalletKitUint256()) {
          walletkit_proof_output_get_merkle_root(WalletKitProofOutputHandle(id: outputID), $0, $1)
        })
    }
  }
  public func getProofAsString() throws -> String {
    try handle.withID { outputID in
      try callString {
        walletkit_proof_output_get_proof_as_string(WalletKitProofOutputHandle(id: outputID), $0, $1)
      }
    }
  }
  public func getCredentialType() throws -> CredentialType {
    try handle.withID { outputID in
      try element(
        try call(UInt8(0)) {
          walletkit_proof_output_get_credential_type(
            WalletKitProofOutputHandle(id: outputID), $0, $1)
        }, of: CredentialType.ordinals)
    }
  }
}
