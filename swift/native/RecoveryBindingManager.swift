import Foundation
internal import walletkit_coreFFI

/// A Rust-owned RecoveryBindingManager resource. Closing rejects new calls; running calls retain their inputs.
public final class RecoveryBindingManager: @unchecked Sendable {
  let handle: NativeHandle
  init(handle: NativeHandle) { self.handle = handle }
  public func close() { handle.close() }
}

extension RecoveryBindingManager {
  public static func create(environment: Environment, userAgentBuilder: UserAgentBuilder) throws
    -> RecoveryBindingManager
  {
    try userAgentBuilder.handle.withID { userAgentBuilderID in
      RecoveryBindingManager(
        handle: NativeHandle(
          try call(WalletKitRecoveryBindingManagerHandle(id: 0)) {
            walletkit_recovery_binding_manager_new(
              ordinal(environment, in: Environment.ordinals),
              WalletKitUserAgentBuilderHandle(id: userAgentBuilderID), $0, $1)
          }.id))
    }
  }
  public static func newWithBaseUrl(baseUrl: String, userAgentBuilder: UserAgentBuilder) throws
    -> RecoveryBindingManager
  {
    try withByteSlice(baseUrl) { baseUrlSlice in
      try userAgentBuilder.handle.withID { userAgentBuilderID in
        RecoveryBindingManager(
          handle: NativeHandle(
            try call(WalletKitRecoveryBindingManagerHandle(id: 0)) {
              walletkit_recovery_binding_manager_new_with_base_url(
                baseUrlSlice, WalletKitUserAgentBuilderHandle(id: userAgentBuilderID), $0, $1)
            }.id))
      }
    }
  }
  public func bindRecoveryAgent(
    authenticator: Authenticator, sub: String, recoveryAgentAddress: String
  ) async throws {
    try await NativeBridge.async { operation in
      try self.handle.withID { managerID in
        try authenticator.handle.withID { authenticatorID in
          try withByteSlice(sub) { subSlice in
            try withByteSlice(recoveryAgentAddress) { recoveryAgentAddressSlice in
              try callUnit {
                walletkit_recovery_binding_manager_bind_recovery_agent(
                  operation, WalletKitRecoveryBindingManagerHandle(id: managerID),
                  WalletKitAuthenticatorHandle(id: authenticatorID), subSlice,
                  recoveryAgentAddressSlice, $0)
              }
            }
          }
        }
      }
    }
  }
  public func unbindRecoveryAgent(authenticator: Authenticator, sub: String) async throws {
    try await NativeBridge.async { operation in
      try self.handle.withID { managerID in
        try authenticator.handle.withID { authenticatorID in
          try withByteSlice(sub) { subSlice in
            try callUnit {
              walletkit_recovery_binding_manager_unbind_recovery_agent(
                operation, WalletKitRecoveryBindingManagerHandle(id: managerID),
                WalletKitAuthenticatorHandle(id: authenticatorID), subSlice, $0)
            }
          }
        }
      }
    }
  }
  public func getRecoveryBinding(leafIndex: UInt64) async throws -> RecoveryBinding {
    try await NativeBridge.async { operation in
      try self.handle.withID { managerID in
        try ByteReader.decode(
          try callData {
            walletkit_recovery_binding_manager_get_recovery_binding(
              operation, WalletKitRecoveryBindingManagerHandle(id: managerID), leafIndex, $0, $1)
          } ?? Data()
        ) { try RecoveryBinding.read(&$0) }
      }
    }
  }
}
