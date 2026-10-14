//! The credential vault a registration shares, in the format `WalletKit` reads and writes.

use std::fmt;

use world_id_core::registration::Vault;
use zeroize::Zeroizing;

/// The [`Vault::format`] of a [`PlaintextVault`].
pub const PLAINTEXT_VAULT_FORMAT: &str = "walletkit_plaintext_v1";

/// A plaintext credential vault backup, as `CredentialStore::export_vault_for_backup` writes it
/// and `CredentialStore::merge_vault_from_backup` reads it.
///
/// This is the only vault format `WalletKit` shares or imports. An Approving Authenticator sends
/// it with [`PLAINTEXT_VAULT_FORMAT`]; a Requesting Authenticator converts a received [`Vault`]
/// with [`PlaintextVault::try_from`], which rejects every other format, before importing it.
///
/// The bytes hold the account's credentials and are zeroized on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct PlaintextVault(Zeroizing<Vec<u8>>);

/// A received [`Vault`] is not a [`PlaintextVault`].
#[derive(Debug, thiserror::Error)]
#[error("the vault is not a WalletKit plaintext backup")]
pub struct UnsupportedVaultFormat {
    /// The format the vault declares. Untrusted text with no length limit of its own.
    pub format: String,
}

impl PlaintextVault {
    /// Wraps a plaintext vault backup.
    #[must_use]
    pub const fn new(backup: Zeroizing<Vec<u8>>) -> Self {
        Self(backup)
    }

    /// Returns the backup bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for PlaintextVault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PlaintextVault")
            .field("len", &self.0.len())
            .finish_non_exhaustive()
    }
}

impl From<PlaintextVault> for Vault {
    fn from(vault: PlaintextVault) -> Self {
        Self {
            format: PLAINTEXT_VAULT_FORMAT.to_string(),
            data: vault.0,
        }
    }
}

impl TryFrom<Vault> for PlaintextVault {
    type Error = UnsupportedVaultFormat;

    fn try_from(vault: Vault) -> Result<Self, Self::Error> {
        if vault.format != PLAINTEXT_VAULT_FORMAT {
            return Err(UnsupportedVaultFormat {
                format: vault.format,
            });
        }
        Ok(Self(vault.data))
    }
}

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::*;

    #[test]
    fn a_plaintext_vault_round_trips_through_the_protocol_vault() {
        let vault =
            Vault::from(PlaintextVault::new(b"SQLite format 3".to_vec().into()));
        assert_eq!(vault.format, "walletkit_plaintext_v1");
        assert_eq!(
            PlaintextVault::try_from(vault).unwrap().as_bytes(),
            b"SQLite format 3"
        );
    }

    #[test_case("walletkit_plaintext_v2"; "another version")]
    #[test_case("WALLETKIT_PLAINTEXT_V1"; "another case")]
    #[test_case(""; "empty")]
    fn other_formats_are_rejected(format: &str) {
        let vault = Vault {
            format: format.to_string(),
            data: b"SQLite format 3".to_vec().into(),
        };
        let error = PlaintextVault::try_from(vault).unwrap_err();
        assert_eq!(error.format, format);
    }
}
