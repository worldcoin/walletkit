import Foundation
internal import walletkit_coreFFI

/// A Rust-owned ProofResponse resource. Closing rejects new calls; running calls retain their inputs.
public final class ProofResponse: @unchecked Sendable {
  let handle: NativeHandle
  init(handle: NativeHandle) { self.handle = handle }
  public func close() { handle.close() }
}

extension ProofResponse {
  public func toJson() throws -> String {
    try handle.withID { responseID in
      try callString {
        walletkit_proof_response_to_json(WalletKitProofResponseHandle(id: responseID), $0, $1)
      }
    }
  }
  public func id() throws -> String {
    try handle.withID { responseID in
      try callString {
        walletkit_proof_response_id(WalletKitProofResponseHandle(id: responseID), $0, $1)
      }
    }
  }
  public func version() throws -> UInt8 {
    try handle.withID { responseID in
      try call(UInt8(0)) {
        walletkit_proof_response_version(WalletKitProofResponseHandle(id: responseID), $0, $1)
      }
    }
  }
  public func error() throws -> String? {
    try handle.withID { responseID in
      try callOptionalString {
        walletkit_proof_response_error(WalletKitProofResponseHandle(id: responseID), $0, $1)
      }
    }
  }
}
