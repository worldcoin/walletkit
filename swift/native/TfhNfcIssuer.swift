import Foundation
internal import walletkit_coreFFI

/// A Rust-owned TfhNfcIssuer resource. Closing rejects new calls; running calls retain their inputs.
public final class TfhNfcIssuer: @unchecked Sendable {
  let handle: NativeHandle
  init(handle: NativeHandle) { self.handle = handle }
  public func close() { handle.close() }
}

extension TfhNfcIssuer {
  public static func create(environment: Environment, userAgent: String) throws -> TfhNfcIssuer {
    try withByteSlice(userAgent) { userAgentSlice in
      TfhNfcIssuer(
        handle: NativeHandle(
          try call(WalletKitTfhNfcIssuerHandle(id: 0)) {
            walletkit_tfh_nfc_issuer_new(
              ordinal(environment, in: Environment.ordinals), userAgentSlice, $0, $1)
          }.id))
    }
  }
  public func refreshNfcCredential(requestBody: String, headers: [String: String]) async throws
    -> Credential
  {
    try await NativeBridge.async { operation in
      try self.handle.withID { issuerID in
        try withByteSlice(requestBody) { requestBodySlice in
          try withByteSlice(ByteWriter.encode { writeStringMap(headers, &$0) }) { headersSlice in
            Credential(
              handle: NativeHandle(
                try call(WalletKitCredentialHandle(id: 0)) {
                  walletkit_tfh_nfc_issuer_refresh_nfc_credential(
                    operation, WalletKitTfhNfcIssuerHandle(id: issuerID), requestBodySlice,
                    headersSlice, $0, $1)
                }.id))
          }
        }
      }
    }
  }
}
