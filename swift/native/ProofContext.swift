import Foundation
internal import walletkit_coreFFI

/// A Rust-owned ProofContext resource. Closing rejects new calls; running calls retain their inputs.
public final class ProofContext: @unchecked Sendable {
  let handle: NativeHandle
  init(handle: NativeHandle) { self.handle = handle }
  public func close() { handle.close() }
}

extension ProofContext {
  public static func create(
    appId: String, action: String?, signal: String?, credentialType: CredentialType
  ) throws -> ProofContext {
    try withByteSlice(appId) { appIdSlice in
      try withOptionalByteSlice(action) { actionSlice in
        try withOptionalByteSlice(signal) { signalSlice in
          ProofContext(
            handle: NativeHandle(
              try call(WalletKitProofContextHandle(id: 0)) {
                walletkit_proof_context_new(
                  appIdSlice, actionSlice, signalSlice,
                  ordinal(credentialType, in: CredentialType.ordinals), $0, $1)
              }.id))
        }
      }
    }
  }
  public static func newFromBytes(
    appId: String, action: Data?, signal: Data?, credentialType: CredentialType
  ) throws -> ProofContext {
    try withByteSlice(appId) { appIdSlice in
      try withOptionalByteSlice(action) { actionSlice in
        try withOptionalByteSlice(signal) { signalSlice in
          ProofContext(
            handle: NativeHandle(
              try call(WalletKitProofContextHandle(id: 0)) {
                walletkit_proof_context_new_from_bytes(
                  appIdSlice, actionSlice, signalSlice,
                  ordinal(credentialType, in: CredentialType.ordinals), $0, $1)
              }.id))
        }
      }
    }
  }
  public static func newFromSignalHash(
    appId: String, action: Data?, credentialType: CredentialType, signalHash: Uint256
  ) throws -> ProofContext {
    try withByteSlice(appId) { appIdSlice in
      try withOptionalByteSlice(action) { actionSlice in
        ProofContext(
          handle: NativeHandle(
            try call(WalletKitProofContextHandle(id: 0)) {
              walletkit_proof_context_new_from_signal_hash(
                appIdSlice, actionSlice, ordinal(credentialType, in: CredentialType.ordinals),
                signalHash.native, $0, $1)
            }.id))
      }
    }
  }
  public func getExternalNullifier() throws -> Uint256 {
    try handle.withID { contextID in
      Uint256(
        native: try call(WalletKitUint256()) {
          walletkit_proof_context_get_external_nullifier(
            WalletKitProofContextHandle(id: contextID), $0, $1)
        })
    }
  }
  public func getSignalHash() throws -> Uint256 {
    try handle.withID { contextID in
      Uint256(
        native: try call(WalletKitUint256()) {
          walletkit_proof_context_get_signal_hash(
            WalletKitProofContextHandle(id: contextID), $0, $1)
        })
    }
  }
  public func getCredentialType() throws -> CredentialType {
    try handle.withID { contextID in
      try element(
        try call(UInt8(0)) {
          walletkit_proof_context_get_credential_type(
            WalletKitProofContextHandle(id: contextID), $0, $1)
        }, of: CredentialType.ordinals)
    }
  }
  public static func legacyNewFromPreImageExternalNullifier(
    externalNullifier: Data, credentialType: CredentialType, signal: Data?, requireMinedProof: Bool
  ) throws -> ProofContext {
    try withByteSlice(externalNullifier) { externalNullifierSlice in
      try withOptionalByteSlice(signal) { signalSlice in
        ProofContext(
          handle: NativeHandle(
            try call(WalletKitProofContextHandle(id: 0)) {
              walletkit_proof_context_legacy_new_from_pre_image_external_nullifier(
                externalNullifierSlice, ordinal(credentialType, in: CredentialType.ordinals),
                signalSlice, requireMinedProof, $0, $1)
            }.id))
      }
    }
  }
  public static func legacyNewFromRawExternalNullifier(
    externalNullifier: Uint256, credentialType: CredentialType, signal: Data?,
    requireMinedProof: Bool
  ) throws -> ProofContext {
    try withOptionalByteSlice(signal) { signalSlice in
      ProofContext(
        handle: NativeHandle(
          try call(WalletKitProofContextHandle(id: 0)) {
            walletkit_proof_context_legacy_new_from_raw_external_nullifier(
              externalNullifier.native, ordinal(credentialType, in: CredentialType.ordinals),
              signalSlice, requireMinedProof, $0, $1)
          }.id))
    }
  }
}
