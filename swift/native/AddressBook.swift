import Foundation
internal import walletkit_coreFFI

/// A Rust-owned AddressBook resource. Closing rejects new calls; running calls retain their inputs.
public final class AddressBook: @unchecked Sendable {
  let handle: NativeHandle
  init(handle: NativeHandle) { self.handle = handle }
  public func close() { handle.close() }
}

extension AddressBook {
  public static func create() throws -> AddressBook {
    AddressBook(
      handle: NativeHandle(
        try call(WalletKitAddressBookHandle(id: 0)) { walletkit_address_book_new($0, $1) }.id))
  }
  public func generateProofContext(addressToVerify: String, timestamp: UInt64) throws
    -> ProofContext
  {
    try handle.withID { addressBookID in
      try withByteSlice(addressToVerify) { addressToVerifySlice in
        ProofContext(
          handle: NativeHandle(
            try call(WalletKitProofContextHandle(id: 0)) {
              walletkit_address_book_generate_proof_context(
                WalletKitAddressBookHandle(id: addressBookID), addressToVerifySlice, timestamp, $0,
                $1)
            }.id))
      }
    }
  }
}
