import Foundation
internal import walletkit_coreFFI

/// A Rust-owned Credential resource. Closing rejects new calls; running calls retain their inputs.
public final class Credential: @unchecked Sendable {
  let handle: NativeHandle
  init(handle: NativeHandle) { self.handle = handle }
  public func close() { handle.close() }
}

extension Credential {
  public static func fromBytes(bytes: Data) throws -> Credential {
    try withByteSlice(bytes) { bytesSlice in
      Credential(
        handle: NativeHandle(
          try call(WalletKitCredentialHandle(id: 0)) {
            walletkit_credential_from_bytes(bytesSlice, $0, $1)
          }.id))
    }
  }
  public func sub() throws -> FieldElement {
    try handle.withID { credentialID in
      FieldElement(
        handle: NativeHandle(
          try call(WalletKitFieldElementHandle(id: 0)) {
            walletkit_credential_sub(WalletKitCredentialHandle(id: credentialID), $0, $1)
          }.id))
    }
  }
  public func issuerSchemaId() throws -> UInt64 {
    try handle.withID { credentialID in
      try call(UInt64(0)) {
        walletkit_credential_issuer_schema_id(WalletKitCredentialHandle(id: credentialID), $0, $1)
      }
    }
  }
  public func expiresAt() throws -> UInt64 {
    try handle.withID { credentialID in
      try call(UInt64(0)) {
        walletkit_credential_expires_at(WalletKitCredentialHandle(id: credentialID), $0, $1)
      }
    }
  }
  public func associatedDataCommitment() throws -> FieldElement {
    try handle.withID { credentialID in
      FieldElement(
        handle: NativeHandle(
          try call(WalletKitFieldElementHandle(id: 0)) {
            walletkit_credential_associated_data_commitment(
              WalletKitCredentialHandle(id: credentialID), $0, $1)
          }.id))
    }
  }
  public func claims() throws -> [FieldElement] {
    try handle.withID { credentialID in
      try ByteReader.decode(
        try callData {
          walletkit_credential_claims(WalletKitCredentialHandle(id: credentialID), $0, $1)
        } ?? Data()
      ) { try $0.list { FieldElement(handle: try $0.handle()) } }
    }
  }
  public func claimsHex() throws -> [String] {
    try handle.withID { credentialID in
      try ByteReader.decode(
        try callData {
          walletkit_credential_claims_hex(WalletKitCredentialHandle(id: credentialID), $0, $1)
        } ?? Data()
      ) { try $0.list { try $0.string() } }
    }
  }
}
