use alloy_core::sol_types::SolValue;
use semaphore::hash_to_field;

use crate::u256::U256Wrapper;

/// A `Proof::Context` contains the basic information on the verifier and the specific action a user will be proving.
///
/// A `Proof::Context` is required to generate a `Proof` and will generally be initialized from an `app_id` and `action`.
#[derive(Clone, PartialEq, Eq, Debug, uniffi::Object)]
pub struct Context {
    pub external_nullifier: U256Wrapper,
}

#[uniffi::export]
impl Context {
    /// Initializes a `Proof::Context`.
    ///
    /// Will compute the relevant external nullifier from the provided `app_id` and `action` as defined by the
    /// World ID Protocol. The external nullifier generation matches the logic in the
    /// [Developer Portal](https://github.com/worldcoin/developer-portal/blob/main/web/lib/hashing.ts).
    ///
    /// # Arguments
    ///
    /// * `app_id` - The ID of the application requesting proofs. This can be obtained from the Developer Portal.
    /// * `action` - Optional. Custom incognito action being requested.
    ///
    #[must_use]
    #[uniffi::constructor]
    pub fn new(app_id: &[u8], action: Option<Vec<u8>>) -> Self {
        let mut pre_image = hash_to_field(app_id).abi_encode_packed();

        if let Some(action) = action {
            pre_image.extend_from_slice(&action);
        }

        let external_nullifier = hash_to_field(&pre_image).into();

        Self { external_nullifier }
    }
}

#[cfg(test)]
mod tests {
    use alloy_core::primitives::address;
    use ruint::{aliases::U256, uint};

    use super::*;

    #[test]
    fn test_external_nullifier_hash_generation_no_action() {
        let context = Context::new(b"app_369183bd38f1641b6964ab51d7a20434", None);
        assert_eq!(
            context.external_nullifier.to_hex_string(),
            "0x0073e4a6b670e81dc619b1f8703aa7491dc5aaadf75409aba0ac2414014c0227"
        );

        let context =
            Context::new(b"app_369183bd38f1641b6964ab51d7a20434", Some(b"".to_vec()));
        assert_eq!(
            context.external_nullifier.to_hex_string(),
            "0x0073e4a6b670e81dc619b1f8703aa7491dc5aaadf75409aba0ac2414014c0227"
        );
    }

    /// This test case comes from the real example in the docs.
    /// Reference: <https://github.com/worldcoin/world-id-docs/blob/main/src/pages/world-id/try.tsx>
    #[test]
    fn test_external_nullifier_hash_generation_string_action_staging() {
        let context = Context::new(
            b"app_staging_45068dca85829d2fd90e2dd6f0bff997",
            Some(b"test-action-qli8g".to_vec()),
        );
        assert_eq!(
            context.external_nullifier.to_hex_string(),
            "0x00d8b157e767dc59faa533120ed0ce34fc51a71937292ea8baed6ee6f4fda866"
        );
    }

    #[test]
    fn test_external_nullifier_hash_generation_string_action() {
        let context = Context::new(
            b"app_10eb12bd96d8f7202892ff25f094c803",
            Some(b"test-123123".to_vec()),
        );
        assert_eq!(
            context.external_nullifier.0,
            // cspell:disable-next-line
            uint!(
                0x0065ebab05692ff2e0816cc4c3b83216c33eaa4d906c6495add6323fe0e2dc89_U256
            )
        );
    }

    #[test]
    fn test_external_nullifier_hash_generation_with_complex_abi_encoded_values() {
        let custom_action = [
            address!("541f3cc5772a64f2ba0a47e83236CcE2F089b188").abi_encode_packed(),
            U256::from(1).abi_encode_packed(),
            "hello".abi_encode_packed(),
        ]
        .concat();

        let context =
            Context::new(b"app_10eb12bd96d8f7202892ff25f094c803", Some(custom_action));
        assert_eq!(
            context.external_nullifier.to_hex_string(),
            // expected output obtained from Solidity
            "0x00f974ff06219e8ca992073d8bbe05084f81250dbd8f37cae733f24fcc0c5ffd"
        );
    }

    #[test]
    fn test_external_nullifier_hash_generation_with_complex_abi_encoded_values_staging()
    {
        let custom_action = [
            "world".abi_encode_packed(),
            U256::from(1).abi_encode_packed(),
            "hello".abi_encode_packed(),
        ]
        .concat();

        let context = Context::new(
            b"app_staging_45068dca85829d2fd90e2dd6f0bff997",
            Some(custom_action),
        );
        assert_eq!(
            context.external_nullifier.to_hex_string(),
            // expected output obtained from Solidity
            "0x005b49f95e822c7c37f4f043421689b11f880e617faa5cd0391803bc9bcc63c0"
        );
    }
}
