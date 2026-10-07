import Foundation
internal import walletkit_coreFFI

/// A Rust-owned OwnershipProof resource. Closing rejects new calls; running calls retain their inputs.
public final class OwnershipProof: @unchecked Sendable {
  let handle: NativeHandle
  init(handle: NativeHandle) { self.handle = handle }
  public func close() { handle.close() }
}

extension OwnershipProof {
  public func encode() throws -> Data {
    try handle.withID { proofID in
      try callData {
        walletkit_ownership_proof_encode(WalletKitOwnershipProofHandle(id: proofID), $0, $1)
      } ?? Data()
    }
  }
  public func encodeB64() throws -> String {
    try handle.withID { proofID in
      try callString {
        walletkit_ownership_proof_encode_b64(WalletKitOwnershipProofHandle(id: proofID), $0, $1)
      }
    }
  }
  public func merkleRoot() throws -> FieldElement {
    try handle.withID { proofID in
      FieldElement(
        handle: NativeHandle(
          try call(WalletKitFieldElementHandle(id: 0)) {
            walletkit_ownership_proof_merkle_root(
              WalletKitOwnershipProofHandle(id: proofID), $0, $1)
          }.id))
    }
  }
}
