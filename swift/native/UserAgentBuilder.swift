import Foundation
internal import walletkit_coreFFI

/// A Rust-owned UserAgentBuilder resource. Closing rejects new calls; running calls retain their inputs.
public final class UserAgentBuilder: @unchecked Sendable {
  let handle: NativeHandle
  init(handle: NativeHandle) { self.handle = handle }
  public func close() { handle.close() }
}

extension UserAgentBuilder {
  public static func create() throws -> UserAgentBuilder {
    UserAgentBuilder(
      handle: NativeHandle(
        try call(WalletKitUserAgentBuilderHandle(id: 0)) {
          walletkit_user_agent_builder_new($0, $1)
        }.id))
  }
  public func withSegment(name: String, version: String) throws -> UserAgentBuilder {
    try handle.withID { builderID in
      try withByteSlice(name) { nameSlice in
        try withByteSlice(version) { versionSlice in
          UserAgentBuilder(
            handle: NativeHandle(
              try call(WalletKitUserAgentBuilderHandle(id: 0)) {
                walletkit_user_agent_builder_with_segment(
                  WalletKitUserAgentBuilderHandle(id: builderID), nameSlice, versionSlice, $0, $1)
              }.id))
        }
      }
    }
  }
  public func withAppSegmentForClient(appVersion: String, clientName: String) throws
    -> UserAgentBuilder
  {
    try handle.withID { builderID in
      try withByteSlice(appVersion) { appVersionSlice in
        try withByteSlice(clientName) { clientNameSlice in
          UserAgentBuilder(
            handle: NativeHandle(
              try call(WalletKitUserAgentBuilderHandle(id: 0)) {
                walletkit_user_agent_builder_with_app_segment_for_client(
                  WalletKitUserAgentBuilderHandle(id: builderID), appVersionSlice, clientNameSlice,
                  $0, $1)
              }.id))
        }
      }
    }
  }
  public func withWalletkitSegment() throws -> UserAgentBuilder {
    try handle.withID { builderID in
      UserAgentBuilder(
        handle: NativeHandle(
          try call(WalletKitUserAgentBuilderHandle(id: 0)) {
            walletkit_user_agent_builder_with_walletkit_segment(
              WalletKitUserAgentBuilderHandle(id: builderID), $0, $1)
          }.id))
    }
  }
  public func withClientSegment(clientName: String, osVersion: String) throws -> UserAgentBuilder {
    try handle.withID { builderID in
      try withByteSlice(clientName) { clientNameSlice in
        try withByteSlice(osVersion) { osVersionSlice in
          UserAgentBuilder(
            handle: NativeHandle(
              try call(WalletKitUserAgentBuilderHandle(id: 0)) {
                walletkit_user_agent_builder_with_client_segment(
                  WalletKitUserAgentBuilderHandle(id: builderID), clientNameSlice, osVersionSlice,
                  $0, $1)
              }.id))
        }
      }
    }
  }
  public func build() throws -> UserAgent {
    try handle.withID { builderID in
      UserAgent(
        handle: NativeHandle(
          try call(WalletKitUserAgentHandle(id: 0)) {
            walletkit_user_agent_builder_build(
              WalletKitUserAgentBuilderHandle(id: builderID), $0, $1)
          }.id))
    }
  }
}
