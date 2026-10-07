import Foundation
internal import walletkit_coreFFI

/// Entry points that do not require an existing WalletKit resource.
public func checkCredentialsAgainstProofRequest(
  request: ProofRequest, store: CredentialStore, now: UInt64
) throws -> CredentialConstraintsCheckResult {
  try request.handle.withID { requestID in
    try store.handle.withID { storeID in
      try ByteReader.decode(
        try callData {
          walletkit_check_credentials_against_proof_request(
            WalletKitProofRequestHandle(id: requestID), WalletKitCredentialStoreHandle(id: storeID),
            now, $0, $1)
        } ?? Data()
      ) { try CredentialConstraintsCheckResult.read(&$0) }
    }
  }
}
public func emitLog(level: LogLevel, message: String) throws {
  try withByteSlice(message) { messageSlice in
    try callUnit { walletkit_emit_log(ordinal(level, in: LogLevel.ordinals), messageSlice, $0) }
  }
}
public func initLogging(logger: any Logger, level: LogLevel?) throws {
  try callUnit {
    walletkit_init_logging(
      loggerCallbacks(logger), level.map { Int32(ordinal($0, in: LogLevel.ordinals)) } ?? -1, $0)
  }
}
public func sanitizeHexSecrets(input: String) throws -> String {
  try withByteSlice(input) { inputSlice in
    try callString { walletkit_sanitize_hex_secrets(inputSlice, $0, $1) }
  }
}
public func validateAuthenticatorPubkey(authenticatorPubkey: String) throws -> String {
  try withByteSlice(authenticatorPubkey) { authenticatorPubkeySlice in
    try callString { walletkit_validate_authenticator_pubkey(authenticatorPubkeySlice, $0, $1) }
  }
}
public func recoveryDataFromSeed(seed: Data) throws -> RecoveryData {
  try withByteSlice(seed) { seedSlice in
    try ByteReader.decode(
      try callData { walletkit_recovery_data_from_seed(seedSlice, $0, $1) } ?? Data()
    ) { try RecoveryData.read(&$0) }
  }
}
