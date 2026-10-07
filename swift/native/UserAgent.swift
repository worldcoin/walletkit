import Foundation
internal import walletkit_coreFFI

/// A Rust-owned UserAgent resource. Closing rejects new calls; running calls retain their inputs.
public final class UserAgent: @unchecked Sendable {
  let handle: NativeHandle
  init(handle: NativeHandle) { self.handle = handle }
  public func close() { handle.close() }
}

extension UserAgent {
  public func headerValue() throws -> String {
    try handle.withID { userAgentID in
      try callString {
        walletkit_user_agent_header_value(WalletKitUserAgentHandle(id: userAgentID), $0, $1)
      }
    }
  }
}
