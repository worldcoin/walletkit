#[cfg(feature = "legacy-nullifiers")]
use {
    crate::{error::WalletKitError, proof::ProofContext, CredentialType},
    alloy_core::primitives::{Address, U256},
    alloy_core::sol_types::SolValue,
    ruint::uint,
    std::str::FromStr,
};

/// Allows interacting with the `WorldIDAddressBook` contract.
///
/// The address book allows users to verify their Wallet Address as Orb verified for a period of time.
///
/// Usage of `AddressBook` requires the `legacy-nullifiers` feature flag.
///
/// The contract of the address book can be found at: `0x57b930d551e677cc36e2fa036ae2fe8fdae0330d`
#[cfg(feature = "legacy-nullifiers")]
#[derive(uniffi::Object)]
pub struct AddressBook {}

/// The external nullifier used in the `WorldIDAddressBook` contract.
///
/// Matches the argument in the constructor to the contract.
///
/// Reference: <https://worldscan.org/address/0x57b930d551e677cc36e2fa036ae2fe8fdae0330d#code>
#[cfg(feature = "legacy-nullifiers")]
const ADDRESS_BOOK_EXTERNAL_NULLIFIER: U256 =
    uint!(0xd5b5db70bda32ef7812459f5edecda296cffb3529141e15fae18751275864d_U256);

#[cfg(feature = "legacy-nullifiers")]
impl Default for AddressBook {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "legacy-nullifiers")]
#[uniffi::export]
impl AddressBook {
    /// Initializes a new `AddressBook` instance.
    #[uniffi::constructor]
    #[must_use]
    pub const fn new() -> Self {
        Self {}
    }

    /// Generates a proof context for the `WorldIDAddressBook` contract to use in a World ID Proof.
    ///
    /// # Errors
    /// - Returns an error if the address is not a valid EVM address.
    /// - Returns an error if the timestamp is not a valid numeric timestamp.
    #[allow(clippy::unused_self)] // associated functions are not supported with Uniffi exports
    pub fn generate_proof_context(
        &self,
        address_to_verify: &str,
        timestamp: u64,
    ) -> Result<ProofContext, WalletKitError> {
        let address_to_verify = Address::from_str(address_to_verify).map_err(|_| {
            WalletKitError::InvalidInput {
                attribute: "address_to_verify".to_string(),
                reason: "Invalid address".to_string(),
            }
        })?;

        let timestamp = U256::from(timestamp);

        // https://github.com/worldcoin/worldcoin-vault/blob/main/src/WorldIDAddressBook.sol#L161
        let signal = (address_to_verify, timestamp).abi_encode_packed();

        let proof_context = ProofContext::legacy_new_from_raw_external_nullifier(
            &ADDRESS_BOOK_EXTERNAL_NULLIFIER.into(),
            CredentialType::Orb,
            Some(signal),
            true, // The address book explicitly requires a mined proof
        )?;

        Ok(proof_context)
    }
}

#[cfg(feature = "legacy-nullifiers")]
#[cfg(test)]
mod tests {
    use super::*;
    use semaphore_rs::hash_to_field;

    #[test]
    fn test_address_book_external_nullifier_and_signal() {
        #[allow(clippy::unreadable_literal)] // timestamp is more readable as a literal
        let context = AddressBook::new()
            .generate_proof_context(
                "0x57b930d551e677cc36e2fa036ae2fe8fdae0330d",
                1719859200,
            )
            .unwrap();

        let expected_external_nullifier = hash_to_field(b"internal_addressbook");

        assert_eq!(context.external_nullifier.0, expected_external_nullifier);

        assert_eq!(
            context.signal_hash.0,
            uint!(
                0x2d63e527e0dab7e40fbfef55995ed4bb3af8ff0a2b46d2d9b9f1ae21b644a4_U256
            )
        );
    }
}
