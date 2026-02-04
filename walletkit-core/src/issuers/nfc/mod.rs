//! NFC credential issuer (passport, eID, MNC).
//!
//! ```rust,ignore
//! let issuer = NfcIssuer::new(&Environment::Production);
//! let payload = oxide.prepare_nfc_refresh_payload(...)?;
//!
//! let credential = issuer.refresh_nfc_credential(
//!     &payload.request_body,
//!     &zkp_auth_header,
//!     &attestation_token,
//! ).await?;
//!
//! // App stores credential via storage API
//! store.store_credential(
//!     credential.issuer_schema_id,
//!     subject_blinding_factor,  // from App
//!     credential.genesis_issued_at,
//!     credential.expires_at,
//!     credential.credential_blob,
//!     None,  // associated_data
//!     now,
//! )?;
//! ```

mod refresh;
mod types;

pub use refresh::NfcIssuer;
pub use types::NfcCredential;
