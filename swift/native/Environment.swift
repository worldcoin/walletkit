import Foundation
internal import walletkit_coreFFI

extension Environment {
  public func pohRecoveryAgentAddress() throws -> String {
    try callString {
      walletkit_environment_poh_recovery_agent_address(
        ordinal(self, in: Environment.ordinals), $0, $1)
    }
  }
  public func worldIdVerifierAddress() throws -> String {
    try callString {
      walletkit_environment_world_id_verifier_address(
        ordinal(self, in: Environment.ordinals), $0, $1)
    }
  }
}
