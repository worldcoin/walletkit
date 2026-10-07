import Foundation
internal import walletkit_coreFFI

/// A Rust-owned InitializingAuthenticator resource. Closing rejects new calls; running calls retain their inputs.
public final class InitializingAuthenticator: @unchecked Sendable {
  let handle: NativeHandle
  init(handle: NativeHandle) { self.handle = handle }
  public func close() { handle.close() }
}

extension InitializingAuthenticator {
  public static func registerWithDefaults(
    seed: Data, rpcUrl: String?, environment: Environment, region: Region?, recoveryAddress: String?
  ) async throws -> InitializingAuthenticator {
    try await NativeBridge.async { operation in
      try withByteSlice(seed) { seedSlice in
        try withOptionalByteSlice(rpcUrl) { rpcUrlSlice in
          try withOptionalByteSlice(recoveryAddress) { recoveryAddressSlice in
            InitializingAuthenticator(
              handle: NativeHandle(
                try call(WalletKitInitializingAuthenticatorHandle(id: 0)) {
                  walletkit_initializing_authenticator_register_with_defaults(
                    operation, seedSlice, rpcUrlSlice,
                    ordinal(environment, in: Environment.ordinals),
                    region.map { Int32(ordinal($0, in: Region.ordinals)) } ?? -1,
                    recoveryAddressSlice, $0, $1)
                }.id))
          }
        }
      }
    }
  }
  public static func registerWithOhttpDefaults(
    seed: Data, rpcUrl: String?, environment: Environment, region: Region?, recoveryAddress: String?
  ) async throws -> InitializingAuthenticator {
    try await NativeBridge.async { operation in
      try withByteSlice(seed) { seedSlice in
        try withOptionalByteSlice(rpcUrl) { rpcUrlSlice in
          try withOptionalByteSlice(recoveryAddress) { recoveryAddressSlice in
            InitializingAuthenticator(
              handle: NativeHandle(
                try call(WalletKitInitializingAuthenticatorHandle(id: 0)) {
                  walletkit_initializing_authenticator_register_with_ohttp_defaults(
                    operation, seedSlice, rpcUrlSlice,
                    ordinal(environment, in: Environment.ordinals),
                    region.map { Int32(ordinal($0, in: Region.ordinals)) } ?? -1,
                    recoveryAddressSlice, $0, $1)
                }.id))
          }
        }
      }
    }
  }
  public static func register(seed: Data, config: String, recoveryAddress: String?) async throws
    -> InitializingAuthenticator
  {
    try await NativeBridge.async { operation in
      try withByteSlice(seed) { seedSlice in
        try withByteSlice(config) { configSlice in
          try withOptionalByteSlice(recoveryAddress) { recoveryAddressSlice in
            InitializingAuthenticator(
              handle: NativeHandle(
                try call(WalletKitInitializingAuthenticatorHandle(id: 0)) {
                  walletkit_initializing_authenticator_register(
                    operation, seedSlice, configSlice, recoveryAddressSlice, $0, $1)
                }.id))
          }
        }
      }
    }
  }
  public func pollStatus() async throws -> RegistrationStatus {
    try await NativeBridge.async { operation in
      try self.handle.withID { authenticatorID in
        try ByteReader.decode(
          try callData {
            walletkit_initializing_authenticator_poll_status(
              operation, WalletKitInitializingAuthenticatorHandle(id: authenticatorID), $0, $1)
          } ?? Data()
        ) { try RegistrationStatus.read(&$0) }
      }
    }
  }
}
