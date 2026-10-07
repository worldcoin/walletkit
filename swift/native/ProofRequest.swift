import Foundation
internal import walletkit_coreFFI

/// A Rust-owned ProofRequest resource. Closing rejects new calls; running calls retain their inputs.
public final class ProofRequest: @unchecked Sendable {
  let handle: NativeHandle
  init(handle: NativeHandle) { self.handle = handle }
  public func close() { handle.close() }
}

extension ProofRequest {
  public static func fromJson(json: String) throws -> ProofRequest {
    try withByteSlice(json) { jsonSlice in
      ProofRequest(
        handle: NativeHandle(
          try call(WalletKitProofRequestHandle(id: 0)) {
            walletkit_proof_request_from_json(jsonSlice, $0, $1)
          }.id))
    }
  }
  public func toJson() throws -> String {
    try handle.withID { requestID in
      try callString {
        walletkit_proof_request_to_json(WalletKitProofRequestHandle(id: requestID), $0, $1)
      }
    }
  }
  public func id() throws -> String {
    try handle.withID { requestID in
      try callString {
        walletkit_proof_request_id(WalletKitProofRequestHandle(id: requestID), $0, $1)
      }
    }
  }
  public func version() throws -> UInt8 {
    try handle.withID { requestID in
      try call(UInt8(0)) {
        walletkit_proof_request_version(WalletKitProofRequestHandle(id: requestID), $0, $1)
      }
    }
  }
}
