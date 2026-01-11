//! File header and superblock definitions.
//!
//! The file header identifies the vault file and contains the account ID.
//! Superblocks (A and B) store the committed transaction pointer for atomic updates.

// Binary format code uses small constant casts that are safe
#![allow(clippy::cast_possible_truncation)]
// Type names like TxnCommit appear in docs without backticks for readability
#![allow(clippy::doc_markdown)]

use crate::credential_storage::{AccountId, StorageError};

use super::format::{
    FILE_HEADER_SIZE, FILE_MAGIC, FORMAT_VERSION, HASH_SIZE, SUPERBLOCK_MAGIC, SUPERBLOCK_SIZE,
};

// =============================================================================
// FileHeader
// =============================================================================

/// File header at the start of every vault file.
///
/// # Binary Layout (48 bytes)
///
/// ```text
/// Offset  Size  Field
/// ------  ----  -----
/// 0       8     magic ("WIDVAULT")
/// 8       4     format_version (u32 LE)
/// 12      32    account_id
/// 44      4     crc32 (over bytes 0..44)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHeader {
    /// Format version for migration support.
    pub format_version: u32,
    /// Account this vault belongs to.
    pub account_id: AccountId,
}

impl FileHeader {
    /// Creates a new file header for an account.
    #[must_use]
    pub const fn new(account_id: AccountId) -> Self {
        Self {
            format_version: FORMAT_VERSION,
            account_id,
        }
    }

    /// Encodes the header to bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; FILE_HEADER_SIZE as usize] {
        let mut buf = [0u8; FILE_HEADER_SIZE as usize];

        // Magic
        buf[0..8].copy_from_slice(FILE_MAGIC);

        // Format version (LE)
        buf[8..12].copy_from_slice(&self.format_version.to_le_bytes());

        // Account ID
        buf[12..44].copy_from_slice(self.account_id.as_bytes());

        // CRC32 over bytes 0..44
        let crc = crc32fast::hash(&buf[0..44]);
        buf[44..48].copy_from_slice(&crc.to_le_bytes());

        buf
    }

    /// Decodes a header from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The buffer is too short
    /// - Magic bytes don't match
    /// - CRC32 validation fails
    /// - Format version is unsupported
    pub fn decode(bytes: &[u8]) -> Result<Self, StorageError> {
        if bytes.len() < FILE_HEADER_SIZE as usize {
            return Err(StorageError::UnexpectedEof {
                context: "file header too short".to_string(),
            });
        }

        // Validate magic
        if &bytes[0..8] != FILE_MAGIC {
            return Err(StorageError::InvalidMagic {
                expected: FILE_MAGIC,
                found: bytes[0..8].to_vec(),
            });
        }

        // Validate CRC32
        let expected_crc = crc32fast::hash(&bytes[0..44]);
        let stored_crc = u32::from_le_bytes([bytes[44], bytes[45], bytes[46], bytes[47]]);
        if expected_crc != stored_crc {
            return Err(StorageError::ChecksumMismatch {
                context: "file header CRC mismatch".to_string(),
            });
        }

        // Parse format version
        let format_version = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if format_version != FORMAT_VERSION {
            return Err(StorageError::InvalidVersion {
                expected: FORMAT_VERSION,
                found: format_version,
            });
        }

        // Parse account ID
        let mut account_id_bytes = [0u8; 32];
        account_id_bytes.copy_from_slice(&bytes[12..44]);

        Ok(Self {
            format_version,
            account_id: AccountId::new(account_id_bytes),
        })
    }
}

// =============================================================================
// Superblock
// =============================================================================

/// Superblock storing the committed transaction pointer.
///
/// Two copies (A and B) enable atomic updates. The active state is defined
/// by the highest-generation valid superblock.
///
/// # Binary Layout (57 bytes)
///
/// ```text
/// Offset  Size  Field
/// ------  ----  -----
/// 0       5     magic ("WIDSB")
/// 5       8     generation (u64 LE)
/// 13      8     committed_txn_offset (u64 LE)
/// 21      32    committed_txn_hash (SHA256)
/// 53      4     crc32 (over bytes 0..53)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Superblock {
    /// Monotonically increasing generation number.
    pub generation: u64,
    /// Byte offset of the TxnCommit record.
    pub committed_txn_offset: u64,
    /// SHA256 hash of the TxnCommit record bytes.
    pub committed_txn_hash: [u8; HASH_SIZE],
}

impl Superblock {
    /// Creates a new superblock.
    #[must_use]
    pub const fn new(
        generation: u64,
        committed_txn_offset: u64,
        committed_txn_hash: [u8; HASH_SIZE],
    ) -> Self {
        Self {
            generation,
            committed_txn_offset,
            committed_txn_hash,
        }
    }

    /// Encodes the superblock to bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; SUPERBLOCK_SIZE as usize] {
        let mut buf = [0u8; SUPERBLOCK_SIZE as usize];

        // Magic
        buf[0..5].copy_from_slice(SUPERBLOCK_MAGIC);

        // Generation (LE)
        buf[5..13].copy_from_slice(&self.generation.to_le_bytes());

        // Committed txn offset (LE)
        buf[13..21].copy_from_slice(&self.committed_txn_offset.to_le_bytes());

        // Committed txn hash
        buf[21..53].copy_from_slice(&self.committed_txn_hash);

        // CRC32 over bytes 0..53
        let crc = crc32fast::hash(&buf[0..53]);
        buf[53..57].copy_from_slice(&crc.to_le_bytes());

        buf
    }

    /// Decodes a superblock from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer is too short or parsing fails.
    /// Does NOT validate CRC - use [`is_valid`] for that.
    pub fn decode(bytes: &[u8]) -> Result<Self, StorageError> {
        if bytes.len() < SUPERBLOCK_SIZE as usize {
            return Err(StorageError::UnexpectedEof {
                context: "superblock too short".to_string(),
            });
        }

        // Parse generation
        let generation = u64::from_le_bytes([
            bytes[5], bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11], bytes[12],
        ]);

        // Parse committed txn offset
        let committed_txn_offset = u64::from_le_bytes([
            bytes[13], bytes[14], bytes[15], bytes[16], bytes[17], bytes[18], bytes[19], bytes[20],
        ]);

        // Parse committed txn hash
        let mut committed_txn_hash = [0u8; HASH_SIZE];
        committed_txn_hash.copy_from_slice(&bytes[21..53]);

        Ok(Self {
            generation,
            committed_txn_offset,
            committed_txn_hash,
        })
    }

    /// Checks if the superblock bytes are valid (magic and CRC match).
    #[must_use]
    pub fn is_valid(bytes: &[u8]) -> bool {
        if bytes.len() < SUPERBLOCK_SIZE as usize {
            return false;
        }

        // Check magic
        if &bytes[0..5] != SUPERBLOCK_MAGIC {
            return false;
        }

        // Check CRC32
        let expected_crc = crc32fast::hash(&bytes[0..53]);
        let stored_crc = u32::from_le_bytes([bytes[53], bytes[54], bytes[55], bytes[56]]);

        expected_crc == stored_crc
    }

    /// Attempts to decode a superblock, returning None if invalid.
    #[must_use]
    pub fn try_decode(bytes: &[u8]) -> Option<Self> {
        if !Self::is_valid(bytes) {
            return None;
        }
        Self::decode(bytes).ok()
    }
}

// =============================================================================
// Superblock Selection
// =============================================================================

/// Which superblock slot is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuperblockSlot {
    /// Superblock A (first slot).
    A,
    /// Superblock B (second slot).
    B,
}

impl SuperblockSlot {
    /// Returns the other slot.
    #[must_use]
    pub const fn other(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }

    /// Returns the byte offset for this slot.
    #[must_use]
    pub const fn offset(self) -> u64 {
        match self {
            Self::A => super::format::SUPERBLOCK_A_OFFSET,
            Self::B => super::format::SUPERBLOCK_B_OFFSET,
        }
    }
}

/// Selects the active superblock (highest valid generation).
///
/// # Arguments
///
/// * `sb_a` - Optional parsed superblock A
/// * `sb_b` - Optional parsed superblock B
///
/// # Returns
///
/// The active superblock and its slot, or None if neither is valid.
#[must_use]
pub const fn select_active_superblock(
    sb_a: Option<Superblock>,
    sb_b: Option<Superblock>,
) -> Option<(Superblock, SuperblockSlot)> {
    match (sb_a, sb_b) {
        (Some(a), Some(b)) => {
            if a.generation >= b.generation {
                Some((a, SuperblockSlot::A))
            } else {
                Some((b, SuperblockSlot::B))
            }
        }
        (Some(a), None) => Some((a, SuperblockSlot::A)),
        (None, Some(b)) => Some((b, SuperblockSlot::B)),
        (None, None) => None,
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_header_roundtrip() {
        let account_id = AccountId::new([0x42u8; 32]);
        let header = FileHeader::new(account_id);

        let encoded = header.encode();
        assert_eq!(encoded.len(), FILE_HEADER_SIZE as usize);

        let decoded = FileHeader::decode(&encoded).unwrap();
        assert_eq!(header, decoded);
    }

    #[test]
    fn test_file_header_magic() {
        let header = FileHeader::new(AccountId::new([0u8; 32]));
        let encoded = header.encode();

        assert_eq!(&encoded[0..8], FILE_MAGIC);
    }

    #[test]
    fn test_file_header_invalid_magic() {
        let mut bytes = FileHeader::new(AccountId::new([0u8; 32])).encode();
        bytes[0] = 0xFF; // Corrupt magic

        let result = FileHeader::decode(&bytes);
        assert!(matches!(result, Err(StorageError::InvalidMagic { .. })));
    }

    #[test]
    fn test_file_header_invalid_crc() {
        let mut bytes = FileHeader::new(AccountId::new([0u8; 32])).encode();
        bytes[44] ^= 0xFF; // Corrupt CRC

        let result = FileHeader::decode(&bytes);
        assert!(matches!(result, Err(StorageError::ChecksumMismatch { .. })));
    }

    #[test]
    fn test_superblock_roundtrip() {
        let sb = Superblock::new(42, 1234, [0xABu8; 32]);

        let encoded = sb.encode();
        assert_eq!(encoded.len(), SUPERBLOCK_SIZE as usize);

        let decoded = Superblock::decode(&encoded).unwrap();
        assert_eq!(sb, decoded);
    }

    #[test]
    fn test_superblock_is_valid() {
        let sb = Superblock::new(1, 100, [0u8; 32]);
        let encoded = sb.encode();

        assert!(Superblock::is_valid(&encoded));

        // Corrupt magic
        let mut corrupted = encoded;
        corrupted[0] = 0xFF;
        assert!(!Superblock::is_valid(&corrupted));

        // Corrupt CRC
        let mut corrupted = encoded;
        corrupted[53] ^= 0xFF;
        assert!(!Superblock::is_valid(&corrupted));
    }

    #[test]
    fn test_superblock_try_decode() {
        let sb = Superblock::new(5, 200, [0x11u8; 32]);
        let encoded = sb.encode();

        let decoded = Superblock::try_decode(&encoded);
        assert_eq!(decoded, Some(sb));

        // Invalid superblock returns None
        let invalid = vec![0u8; SUPERBLOCK_SIZE as usize];
        assert_eq!(Superblock::try_decode(&invalid), None);
    }

    #[test]
    fn test_select_active_superblock() {
        let sb_a = Superblock::new(5, 100, [0u8; 32]);
        let sb_b = Superblock::new(10, 200, [0u8; 32]);

        // B has higher generation
        let (active, slot) = select_active_superblock(Some(sb_a.clone()), Some(sb_b.clone())).unwrap();
        assert_eq!(active, sb_b);
        assert_eq!(slot, SuperblockSlot::B);

        // A has higher generation
        let sb_a_high = Superblock::new(15, 300, [0u8; 32]);
        let (active, slot) = select_active_superblock(Some(sb_a_high.clone()), Some(sb_b)).unwrap();
        assert_eq!(active, sb_a_high);
        assert_eq!(slot, SuperblockSlot::A);

        // Only A valid
        let (active, slot) = select_active_superblock(Some(sb_a.clone()), None).unwrap();
        assert_eq!(active, sb_a);
        assert_eq!(slot, SuperblockSlot::A);

        // Only B valid
        let sb_b = Superblock::new(1, 50, [0u8; 32]);
        let (active, slot) = select_active_superblock(None, Some(sb_b.clone())).unwrap();
        assert_eq!(active, sb_b);
        assert_eq!(slot, SuperblockSlot::B);

        // Neither valid
        assert!(select_active_superblock(None, None).is_none());
    }

    #[test]
    fn test_superblock_slot_other() {
        assert_eq!(SuperblockSlot::A.other(), SuperblockSlot::B);
        assert_eq!(SuperblockSlot::B.other(), SuperblockSlot::A);
    }

    #[test]
    fn test_superblock_slot_offset() {
        assert_eq!(SuperblockSlot::A.offset(), super::super::format::SUPERBLOCK_A_OFFSET);
        assert_eq!(SuperblockSlot::B.offset(), super::super::format::SUPERBLOCK_B_OFFSET);
    }
}
