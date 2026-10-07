import Foundation
internal import walletkit_coreFFI

/// A Rust-owned Authenticator resource. Closing rejects new calls; running calls retain their inputs.
public final class Authenticator: @unchecked Sendable {
  let handle: NativeHandle
  init(handle: NativeHandle) { self.handle = handle }
  public func close() { handle.close() }
}

extension Authenticator {
  public func initStorage(now: UInt64) throws {
    try handle.withID { authenticatorID in
      try callUnit {
        walletkit_authenticator_init_storage(
          WalletKitAuthenticatorHandle(id: authenticatorID), now, $0)
      }
    }
  }
  /// Deletes the key envelope, vault, and cache. The store becomes uninitialized. Use only for logout or account deletion.
  public func destroyStorage() throws {
    try handle.withID { authenticatorID in
      try callUnit {
        walletkit_authenticator_destroy_storage(
          WalletKitAuthenticatorHandle(id: authenticatorID), $0)
      }
    }
  }
  public func packedAccountData() throws -> Uint256 {
    try handle.withID { authenticatorID in
      Uint256(
        native: try call(WalletKitUint256()) {
          walletkit_authenticator_packed_account_data(
            WalletKitAuthenticatorHandle(id: authenticatorID), $0, $1)
        })
    }
  }
  public func leafIndex() throws -> UInt64 {
    try handle.withID { authenticatorID in
      try call(UInt64(0)) {
        walletkit_authenticator_leaf_index(
          WalletKitAuthenticatorHandle(id: authenticatorID), $0, $1)
      }
    }
  }
  public func onchainAddress() throws -> String {
    try handle.withID { authenticatorID in
      try callString {
        walletkit_authenticator_onchain_address(
          WalletKitAuthenticatorHandle(id: authenticatorID), $0, $1)
      }
    }
  }
  public func getPackedAccountDataRemote() async throws -> Uint256 {
    try await NativeBridge.async { operation in
      try self.handle.withID { authenticatorID in
        Uint256(
          native: try call(WalletKitUint256()) {
            walletkit_authenticator_get_packed_account_data_remote(
              operation, WalletKitAuthenticatorHandle(id: authenticatorID), $0, $1)
          })
      }
    }
  }
  public func generateCredentialBlindingFactorRemote(issuerSchemaId: UInt64) async throws
    -> FieldElement
  {
    try await NativeBridge.async { operation in
      try self.handle.withID { authenticatorID in
        FieldElement(
          handle: NativeHandle(
            try call(WalletKitFieldElementHandle(id: 0)) {
              walletkit_authenticator_generate_credential_blinding_factor_remote(
                operation, WalletKitAuthenticatorHandle(id: authenticatorID), issuerSchemaId, $0, $1
              )
            }.id))
      }
    }
  }
  public func computeCredentialSub(blindingFactor: FieldElement) throws -> FieldElement {
    try handle.withID { authenticatorID in
      try blindingFactor.handle.withID { blindingFactorID in
        FieldElement(
          handle: NativeHandle(
            try call(WalletKitFieldElementHandle(id: 0)) {
              walletkit_authenticator_compute_credential_sub(
                WalletKitAuthenticatorHandle(id: authenticatorID),
                WalletKitFieldElementHandle(id: blindingFactorID), $0, $1)
            }.id))
      }
    }
  }
  /// Signs with the on-chain key and reveals the user’s identity/leaf index. Use only to prove ownership to the trusted recovery agent.
  public func dangerSignChallenge(challenge: Data) throws -> Data {
    try handle.withID { authenticatorID in
      try withByteSlice(challenge) { challengeSlice in
        try callData {
          walletkit_authenticator_danger_sign_challenge(
            WalletKitAuthenticatorHandle(id: authenticatorID), challengeSlice, $0, $1)
        } ?? Data()
      }
    }
  }
  /// Signs a recovery-agent update. Only use with an explicitly authorized, validated recovery-agent address.
  public func dangerSignInitiateRecoveryAgentUpdate(newRecoveryAgent: String) async throws
    -> RecoveryUpdateSignature
  {
    try await NativeBridge.async { operation in
      try self.handle.withID { authenticatorID in
        try withByteSlice(newRecoveryAgent) { newRecoveryAgentSlice in
          try ByteReader.decode(
            try callData {
              walletkit_authenticator_danger_sign_initiate_recovery_agent_update(
                operation, WalletKitAuthenticatorHandle(id: authenticatorID), newRecoveryAgentSlice,
                $0, $1)
            } ?? Data()
          ) { try RecoveryUpdateSignature.read(&$0) }
        }
      }
    }
  }
  public func updateRecoveryAgent(newRecoveryAgent: String) async throws -> String {
    try await NativeBridge.async { operation in
      try self.handle.withID { authenticatorID in
        try withByteSlice(newRecoveryAgent) { newRecoveryAgentSlice in
          try callString {
            walletkit_authenticator_update_recovery_agent(
              operation, WalletKitAuthenticatorHandle(id: authenticatorID), newRecoveryAgentSlice,
              $0, $1)
          }
        }
      }
    }
  }
  public func revertRecoveryAgentUpdate() async throws -> String {
    try await NativeBridge.async { operation in
      try self.handle.withID { authenticatorID in
        try callString {
          walletkit_authenticator_revert_recovery_agent_update(
            operation, WalletKitAuthenticatorHandle(id: authenticatorID), $0, $1)
        }
      }
    }
  }
  public func insertAuthenticator(newAuthenticatorPubkey: String, newAuthenticatorAddress: String)
    async throws -> String
  {
    try await NativeBridge.async { operation in
      try self.handle.withID { authenticatorID in
        try withByteSlice(newAuthenticatorPubkey) { newAuthenticatorPubkeySlice in
          try withByteSlice(newAuthenticatorAddress) { newAuthenticatorAddressSlice in
            try callString {
              walletkit_authenticator_insert_authenticator(
                operation, WalletKitAuthenticatorHandle(id: authenticatorID),
                newAuthenticatorPubkeySlice, newAuthenticatorAddressSlice, $0, $1)
            }
          }
        }
      }
    }
  }
  public func hasAuthenticatorPubkey(authenticatorPubkey: String) async throws -> Bool {
    try await NativeBridge.async { operation in
      try self.handle.withID { authenticatorID in
        try withByteSlice(authenticatorPubkey) { authenticatorPubkeySlice in
          try call(false) {
            walletkit_authenticator_has_authenticator_pubkey(
              operation, WalletKitAuthenticatorHandle(id: authenticatorID),
              authenticatorPubkeySlice, $0, $1)
          }
        }
      }
    }
  }
  public func getAuthenticatorPubkeys() async throws -> [String?] {
    try await NativeBridge.async { operation in
      try self.handle.withID { authenticatorID in
        try ByteReader.decode(
          try callData {
            walletkit_authenticator_get_authenticator_pubkeys(
              operation, WalletKitAuthenticatorHandle(id: authenticatorID), $0, $1)
          } ?? Data()
        ) { try $0.list { try $0.optional { try $0.string() } } }
      }
    }
  }
  public func removeAuthenticator(
    authenticatorAddress: String, pubkeyId: UInt32, expectedAuthenticatorPubkey: String
  ) async throws -> String {
    try await NativeBridge.async { operation in
      try self.handle.withID { authenticatorID in
        try withByteSlice(authenticatorAddress) { authenticatorAddressSlice in
          try withByteSlice(expectedAuthenticatorPubkey) { expectedAuthenticatorPubkeySlice in
            try callString {
              walletkit_authenticator_remove_authenticator(
                operation, WalletKitAuthenticatorHandle(id: authenticatorID),
                authenticatorAddressSlice, pubkeyId, expectedAuthenticatorPubkeySlice, $0, $1)
            }
          }
        }
      }
    }
  }
  public func pollStatus(requestId: String) async throws -> GatewayRequestStatus {
    try await NativeBridge.async { operation in
      try self.handle.withID { authenticatorID in
        try withByteSlice(requestId) { requestIdSlice in
          try ByteReader.decode(
            try callData {
              walletkit_authenticator_poll_status(
                operation, WalletKitAuthenticatorHandle(id: authenticatorID), requestIdSlice, $0, $1
              )
            } ?? Data()
          ) { try GatewayRequestStatus.read(&$0) }
        }
      }
    }
  }
  public func generateProof(proofRequest: ProofRequest, now: UInt64?) async throws -> ProofResponse
  {
    try await NativeBridge.async { operation in
      try self.handle.withID { authenticatorID in
        try proofRequest.handle.withID { proofRequestID in
          try withOptional(now) { nowPointer in
            ProofResponse(
              handle: NativeHandle(
                try call(WalletKitProofResponseHandle(id: 0)) {
                  walletkit_authenticator_generate_proof(
                    operation, WalletKitAuthenticatorHandle(id: authenticatorID),
                    WalletKitProofRequestHandle(id: proofRequestID), nowPointer, $0, $1)
                }.id))
          }
        }
      }
    }
  }
  public func proveCredentialSub(
    nonce: FieldElement, context: FieldElement, blindingFactor: FieldElement, sub: FieldElement
  ) async throws -> OwnershipProof {
    try await NativeBridge.async { operation in
      try self.handle.withID { authenticatorID in
        try nonce.handle.withID { nonceID in
          try context.handle.withID { contextID in
            try blindingFactor.handle.withID { blindingFactorID in
              try sub.handle.withID { subID in
                OwnershipProof(
                  handle: NativeHandle(
                    try call(WalletKitOwnershipProofHandle(id: 0)) {
                      walletkit_authenticator_prove_credential_sub(
                        operation, WalletKitAuthenticatorHandle(id: authenticatorID),
                        WalletKitFieldElementHandle(id: nonceID),
                        WalletKitFieldElementHandle(id: contextID),
                        WalletKitFieldElementHandle(id: blindingFactorID),
                        WalletKitFieldElementHandle(id: subID), $0, $1)
                    }.id))
              }
            }
          }
        }
      }
    }
  }
  public static func initWithDefaults(
    seed: Data, rpcUrl: String?, environment: Environment, region: Region?,
    artifacts: WalletKitZkArtifactSource, store: CredentialStore
  ) async throws -> Authenticator {
    try await NativeBridge.async { operation in
      try withByteSlice(seed) { seedSlice in
        try withOptionalByteSlice(rpcUrl) { rpcUrlSlice in
          try artifacts.handle.withID { artifactsID in
            try store.handle.withID { storeID in
              Authenticator(
                handle: NativeHandle(
                  try call(WalletKitAuthenticatorHandle(id: 0)) {
                    walletkit_authenticator_init_with_defaults(
                      operation, seedSlice, rpcUrlSlice,
                      ordinal(environment, in: Environment.ordinals),
                      region.map { Int32(ordinal($0, in: Region.ordinals)) } ?? -1,
                      WalletKitZkArtifactSourceHandle(id: artifactsID),
                      WalletKitCredentialStoreHandle(id: storeID), $0, $1)
                  }.id))
            }
          }
        }
      }
    }
  }
  public static func initWithOhttpDefaults(
    seed: Data, rpcUrl: String?, environment: Environment, region: Region?,
    artifacts: WalletKitZkArtifactSource, store: CredentialStore
  ) async throws -> Authenticator {
    try await NativeBridge.async { operation in
      try withByteSlice(seed) { seedSlice in
        try withOptionalByteSlice(rpcUrl) { rpcUrlSlice in
          try artifacts.handle.withID { artifactsID in
            try store.handle.withID { storeID in
              Authenticator(
                handle: NativeHandle(
                  try call(WalletKitAuthenticatorHandle(id: 0)) {
                    walletkit_authenticator_init_with_ohttp_defaults(
                      operation, seedSlice, rpcUrlSlice,
                      ordinal(environment, in: Environment.ordinals),
                      region.map { Int32(ordinal($0, in: Region.ordinals)) } ?? -1,
                      WalletKitZkArtifactSourceHandle(id: artifactsID),
                      WalletKitCredentialStoreHandle(id: storeID), $0, $1)
                  }.id))
            }
          }
        }
      }
    }
  }
  public static func initialize(
    seed: Data, config: String, artifacts: WalletKitZkArtifactSource, store: CredentialStore
  ) async throws -> Authenticator {
    try await NativeBridge.async { operation in
      try withByteSlice(seed) { seedSlice in
        try withByteSlice(config) { configSlice in
          try artifacts.handle.withID { artifactsID in
            try store.handle.withID { storeID in
              Authenticator(
                handle: NativeHandle(
                  try call(WalletKitAuthenticatorHandle(id: 0)) {
                    walletkit_authenticator_init(
                      operation, seedSlice, configSlice,
                      WalletKitZkArtifactSourceHandle(id: artifactsID),
                      WalletKitCredentialStoreHandle(id: storeID), $0, $1)
                  }.id))
            }
          }
        }
      }
    }
  }
}
