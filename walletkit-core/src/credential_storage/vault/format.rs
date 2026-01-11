//! File format constants and layout definitions.
//!
//! This module defines the binary format for the vault file, including
//! magic bytes, version numbers, record types, and layout offsets.

// Layout comments describe binary structure, not Rust identifiers
#![allow(clippy::doc_markdown)]


/// Magic bytes at the start of every vault file.
pub const FILE_MAGIC: &[u8; 8] = b"WIDVAULT";

/// Magic bytes for superblock records.
pub const SUPERBLOCK_MAGIC: &[u8; 5] = b"WIDSB";

/// Magic bytes for record envelopes in the data region.
pub const RECORD_MAGIC: &[u8; 4] = b"WIDR";


/// Current vault file format version.
pub const FORMAT_VERSION: u32 = 1;

/// Current vault index format version.
pub const INDEX_VERSION: u32 = 1;

/// Current record envelope version.
pub const RECORD_VERSION: u16 = 1;


/// Record type for transaction begin marker.
pub const RECORD_TYPE_TXN_BEGIN: u16 = 0x0001;

/// Record type for transaction commit marker.
pub const RECORD_TYPE_TXN_COMMIT: u16 = 0x0002;

/// Record type for encrypted index snapshot.
pub const RECORD_TYPE_ENCRYPTED_INDEX: u16 = 0x0003;

/// Record type for encrypted blob object.
pub const RECORD_TYPE_ENCRYPTED_BLOB: u16 = 0x0004;

// Blob Kinds

/// Blob kind for credential data.
pub const BLOB_KIND_CREDENTIAL: u8 = 0x01;

/// Blob kind for associated data.
pub const BLOB_KIND_ASSOCIATED_DATA: u8 = 0x02;


/// Size of the file header in bytes.
/// Layout: magic(8) + version(4) + account_id(32) + crc(4) = 48
pub const FILE_HEADER_SIZE: u64 = 48;

/// Size of a superblock in bytes.
/// Layout: magic(5) + generation(8) + offset(8) + hash(32) + crc(4) = 57
pub const SUPERBLOCK_SIZE: u64 = 57;

/// Byte offset of superblock A from start of file.
pub const SUPERBLOCK_A_OFFSET: u64 = FILE_HEADER_SIZE;

/// Byte offset of superblock B from start of file.
pub const SUPERBLOCK_B_OFFSET: u64 = FILE_HEADER_SIZE + SUPERBLOCK_SIZE;

/// Byte offset where the data region begins.
pub const DATA_REGION_START: u64 = SUPERBLOCK_B_OFFSET + SUPERBLOCK_SIZE;

/// Size of the record envelope header (excluding body).
/// Layout: magic(4) + type(2) + version(2) + len(4) + crc(4) = 16
pub const RECORD_ENVELOPE_HEADER_SIZE: usize = 16;


/// Size of XChaCha20-Poly1305 nonce in bytes.
pub const NONCE_SIZE: usize = 24;

/// Size of Poly1305 authentication tag in bytes.
pub const TAG_SIZE: usize = 16;

/// Size of SHA-256 hash output in bytes.
pub const HASH_SIZE: usize = 32;


/// Label for vault index encryption.
pub const LABEL_VAULT_INDEX: &[u8] = b"vault:index";

/// Label for credential blob encryption.
pub const LABEL_VAULT_BLOB_CRED: &[u8] = b"vault:blob:cred";

/// Label for associated data blob encryption.
pub const LABEL_VAULT_BLOB_AD: &[u8] = b"vault:blob:ad";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_constants() {
        assert_eq!(FILE_HEADER_SIZE, 48);
        assert_eq!(SUPERBLOCK_SIZE, 57);
        assert_eq!(FILE_MAGIC.len(), 8);
        assert_eq!(SUPERBLOCK_MAGIC.len(), 5);
        assert_eq!(RECORD_MAGIC.len(), 4);
    }
}
