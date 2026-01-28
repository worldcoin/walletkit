use std::convert::TryFrom;

use crate::error::WalletKitError;
use crate::U256Wrapper;
use ruint::aliases::U256;

/// Converts a leaf index from `U256Wrapper` to `u64`.
///
/// # Errors
///
/// Returns an error if the leaf index does not fit in a `u64`.
pub(super) fn leaf_index_to_u64(
    leaf_index: &U256Wrapper,
) -> Result<u64, WalletKitError> {
    u64::try_from(leaf_index.0).map_err(|_| WalletKitError::InvalidInput {
        attribute: "leaf_index".to_string(),
        reason: "leaf index does not fit in u64".to_string(),
    })
}

pub(super) fn parse_fixed_bytes<const N: usize>(
    bytes: Vec<u8>,
    label: &str,
) -> Result<[u8; N], WalletKitError> {
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| WalletKitError::InvalidInput {
            attribute: label.to_string(),
            reason: format!("length mismatch: expected {N}, got {}", bytes.len()),
        })
}

pub(super) fn u256_to_hex(value: U256) -> String {
    format!("{value:#066x}")
}
