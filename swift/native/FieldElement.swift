import Foundation
internal import walletkit_coreFFI

/// A Rust-owned FieldElement resource. Closing rejects new calls; running calls retain their inputs.
public final class FieldElement: @unchecked Sendable {
  let handle: NativeHandle
  init(handle: NativeHandle) { self.handle = handle }
  public func close() { handle.close() }
}

extension FieldElement {
  public static func fromBytes(bytes: Data) throws -> FieldElement {
    try withByteSlice(bytes) { bytesSlice in
      FieldElement(
        handle: NativeHandle(
          try call(WalletKitFieldElementHandle(id: 0)) {
            walletkit_field_element_from_bytes(bytesSlice, $0, $1)
          }.id))
    }
  }
  public static func fromU64(value: UInt64) throws -> FieldElement {
    FieldElement(
      handle: NativeHandle(
        try call(WalletKitFieldElementHandle(id: 0)) {
          walletkit_field_element_from_u64(value, $0, $1)
        }.id))
  }
  public func toBytes() throws -> Data {
    try handle.withID { elementID in
      try callData {
        walletkit_field_element_to_bytes(WalletKitFieldElementHandle(id: elementID), $0, $1)
      } ?? Data()
    }
  }
  public static func tryFromHexString(hexString: String) throws -> FieldElement {
    try withByteSlice(hexString) { hexStringSlice in
      FieldElement(
        handle: NativeHandle(
          try call(WalletKitFieldElementHandle(id: 0)) {
            walletkit_field_element_try_from_hex_string(hexStringSlice, $0, $1)
          }.id))
    }
  }
  public func toHexString() throws -> String {
    try handle.withID { elementID in
      try callString {
        walletkit_field_element_to_hex_string(WalletKitFieldElementHandle(id: elementID), $0, $1)
      }
    }
  }
}
