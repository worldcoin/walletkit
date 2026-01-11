//! Record types for the vault append-only data region.
//!
//! All records use a common envelope format with magic bytes, type, version,
//! length, and CRC32 checksum.

// Binary format code uses small constant casts that are safe
#![allow(clippy::cast_possible_truncation)]
// Type names like TxnBegin appear in docs without backticks for readability
#![allow(clippy::doc_markdown)]

use crate::credential_storage::{BlobKind, ContentId, StorageError};

use super::format::{
    HASH_SIZE, NONCE_SIZE, RECORD_ENVELOPE_HEADER_SIZE, RECORD_MAGIC, RECORD_TYPE_ENCRYPTED_BLOB,
    RECORD_TYPE_ENCRYPTED_INDEX, RECORD_TYPE_TXN_BEGIN, RECORD_TYPE_TXN_COMMIT, RECORD_VERSION,
};

// =============================================================================
// Record Envelope
// =============================================================================

/// Common envelope wrapping all record types in the data region.
///
/// # Binary Layout
///
/// ```text
/// Offset  Size  Field
/// ------  ----  -----
/// 0       4     magic ("WIDR")
/// 4       2     record_type (u16 LE)
/// 6       2     record_version (u16 LE)
/// 8       4     body_len (u32 LE)
/// 12      4     crc32 (over type + version + body_len + body)
/// 16      N     body
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordEnvelope {
    /// Type of record contained in this envelope.
    pub record_type: u16,
    /// Version of the record format.
    pub record_version: u16,
    /// Record body bytes.
    pub body: Vec<u8>,
}

impl RecordEnvelope {
    /// Creates a new record envelope.
    #[must_use]
    pub const fn new(record_type: u16, body: Vec<u8>) -> Self {
        Self {
            record_type,
            record_version: RECORD_VERSION,
            body,
        }
    }

    /// Returns the total encoded length including header.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        RECORD_ENVELOPE_HEADER_SIZE + self.body.len()
    }

    /// Encodes the envelope to bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let body_len = self.body.len() as u32;
        let total_len = RECORD_ENVELOPE_HEADER_SIZE + self.body.len();
        let mut buf = Vec::with_capacity(total_len);

        // Magic
        buf.extend_from_slice(RECORD_MAGIC);

        // Type (LE)
        buf.extend_from_slice(&self.record_type.to_le_bytes());

        // Version (LE)
        buf.extend_from_slice(&self.record_version.to_le_bytes());

        // Body length (LE)
        buf.extend_from_slice(&body_len.to_le_bytes());

        // CRC32 placeholder - will be computed over type + version + body_len + body
        let crc_start = buf.len();
        buf.extend_from_slice(&[0u8; 4]);

        // Body
        buf.extend_from_slice(&self.body);

        // Compute CRC32 over type + version + body_len + body (bytes 4..12 + body)
        let mut crc_input = Vec::with_capacity(8 + self.body.len());
        crc_input.extend_from_slice(&buf[4..12]); // type + version + body_len
        crc_input.extend_from_slice(&self.body);
        let crc = crc32fast::hash(&crc_input);

        buf[crc_start..crc_start + 4].copy_from_slice(&crc.to_le_bytes());

        buf
    }

    /// Decodes an envelope from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Buffer is too short
    /// - Magic bytes don't match
    /// - CRC32 validation fails
    pub fn decode(bytes: &[u8]) -> Result<Self, StorageError> {
        if bytes.len() < RECORD_ENVELOPE_HEADER_SIZE {
            return Err(StorageError::UnexpectedEof {
                context: "record envelope header too short".to_string(),
            });
        }

        // Validate magic
        if &bytes[0..4] != RECORD_MAGIC {
            return Err(StorageError::InvalidMagic {
                expected: RECORD_MAGIC,
                found: bytes[0..4].to_vec(),
            });
        }

        // Parse header fields
        let record_type = u16::from_le_bytes([bytes[4], bytes[5]]);
        let record_version = u16::from_le_bytes([bytes[6], bytes[7]]);
        let body_len = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
        let stored_crc = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);

        // Validate we have enough bytes for the body
        let total_len = RECORD_ENVELOPE_HEADER_SIZE + body_len;
        if bytes.len() < total_len {
            return Err(StorageError::UnexpectedEof {
                context: format!(
                    "record envelope body too short: expected {body_len}, got {}",
                    bytes.len() - RECORD_ENVELOPE_HEADER_SIZE
                ),
            });
        }

        // Extract body
        let body = bytes[RECORD_ENVELOPE_HEADER_SIZE..total_len].to_vec();

        // Validate CRC32 over type + version + body_len + body
        let mut crc_input = Vec::with_capacity(8 + body_len);
        crc_input.extend_from_slice(&bytes[4..12]); // type + version + body_len
        crc_input.extend_from_slice(&body);
        let expected_crc = crc32fast::hash(&crc_input);

        if expected_crc != stored_crc {
            return Err(StorageError::ChecksumMismatch {
                context: "record envelope CRC mismatch".to_string(),
            });
        }

        Ok(Self {
            record_type,
            record_version,
            body,
        })
    }

    /// Reads just the header to determine body length without parsing body.
    ///
    /// # Errors
    ///
    /// Returns an error if the header is too short.
    pub fn peek_body_len(header_bytes: &[u8]) -> Result<u32, StorageError> {
        if header_bytes.len() < RECORD_ENVELOPE_HEADER_SIZE {
            return Err(StorageError::UnexpectedEof {
                context: "record envelope header too short for peek".to_string(),
            });
        }

        Ok(u32::from_le_bytes([
            header_bytes[8],
            header_bytes[9],
            header_bytes[10],
            header_bytes[11],
        ]))
    }
}

// =============================================================================
// TxnBegin
// =============================================================================

/// Transaction begin marker.
///
/// # Binary Layout (24 bytes)
///
/// ```text
/// Offset  Size  Field
/// ------  ----  -----
/// 0       16    txn_id (random UUID)
/// 16      8     started_at (u64 LE, Unix timestamp)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxnBegin {
    /// Random transaction ID.
    pub txn_id: [u8; 16],
    /// Unix timestamp when the transaction started.
    pub started_at: u64,
}

impl TxnBegin {
    /// Size of the encoded body.
    pub const BODY_SIZE: usize = 24;

    /// Creates a new transaction begin record.
    #[must_use]
    pub const fn new(txn_id: [u8; 16], started_at: u64) -> Self {
        Self { txn_id, started_at }
    }

    /// Encodes to body bytes (without envelope).
    #[must_use]
    pub fn encode_body(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::BODY_SIZE);
        buf.extend_from_slice(&self.txn_id);
        buf.extend_from_slice(&self.started_at.to_le_bytes());
        buf
    }

    /// Decodes from body bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the body is too short.
    pub fn decode_body(body: &[u8]) -> Result<Self, StorageError> {
        if body.len() < Self::BODY_SIZE {
            return Err(StorageError::UnexpectedEof {
                context: "TxnBegin body too short".to_string(),
            });
        }

        let mut txn_id = [0u8; 16];
        txn_id.copy_from_slice(&body[0..16]);

        let started_at = u64::from_le_bytes([
            body[16], body[17], body[18], body[19], body[20], body[21], body[22], body[23],
        ]);

        Ok(Self { txn_id, started_at })
    }

    /// Creates a record envelope for this transaction begin.
    #[must_use]
    pub fn to_envelope(&self) -> RecordEnvelope {
        RecordEnvelope::new(RECORD_TYPE_TXN_BEGIN, self.encode_body())
    }
}

// =============================================================================
// TxnCommit
// =============================================================================

/// Transaction commit with index pointer.
///
/// # Binary Layout (72 bytes)
///
/// ```text
/// Offset  Size  Field
/// ------  ----  -----
/// 0       16    txn_id
/// 16      8     index_offset (u64 LE)
/// 24      4     index_len (u32 LE)
/// 28      32    index_ciphertext_hash (SHA256)
/// 60      8     committed_at (u64 LE, Unix timestamp)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxnCommit {
    /// Transaction ID (must match TxnBegin).
    pub txn_id: [u8; 16],
    /// Byte offset of the EncryptedIndexSnapshot record.
    pub index_offset: u64,
    /// Byte length of the index record.
    pub index_len: u32,
    /// SHA256 hash of the index record body bytes.
    pub index_ciphertext_hash: [u8; HASH_SIZE],
    /// Unix timestamp when the transaction was committed.
    pub committed_at: u64,
}

impl TxnCommit {
    /// Size of the encoded body.
    pub const BODY_SIZE: usize = 68;

    /// Creates a new transaction commit record.
    #[must_use]
    pub const fn new(
        txn_id: [u8; 16],
        index_offset: u64,
        index_len: u32,
        index_ciphertext_hash: [u8; HASH_SIZE],
        committed_at: u64,
    ) -> Self {
        Self {
            txn_id,
            index_offset,
            index_len,
            index_ciphertext_hash,
            committed_at,
        }
    }

    /// Encodes to body bytes (without envelope).
    #[must_use]
    pub fn encode_body(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::BODY_SIZE);
        buf.extend_from_slice(&self.txn_id);
        buf.extend_from_slice(&self.index_offset.to_le_bytes());
        buf.extend_from_slice(&self.index_len.to_le_bytes());
        buf.extend_from_slice(&self.index_ciphertext_hash);
        buf.extend_from_slice(&self.committed_at.to_le_bytes());
        buf
    }

    /// Decodes from body bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the body is too short.
    pub fn decode_body(body: &[u8]) -> Result<Self, StorageError> {
        if body.len() < Self::BODY_SIZE {
            return Err(StorageError::UnexpectedEof {
                context: "TxnCommit body too short".to_string(),
            });
        }

        let mut txn_id = [0u8; 16];
        txn_id.copy_from_slice(&body[0..16]);

        let index_offset = u64::from_le_bytes([
            body[16], body[17], body[18], body[19], body[20], body[21], body[22], body[23],
        ]);

        let index_len = u32::from_le_bytes([body[24], body[25], body[26], body[27]]);

        let mut index_ciphertext_hash = [0u8; HASH_SIZE];
        index_ciphertext_hash.copy_from_slice(&body[28..60]);

        let committed_at = u64::from_le_bytes([
            body[60], body[61], body[62], body[63], body[64], body[65], body[66], body[67],
        ]);

        Ok(Self {
            txn_id,
            index_offset,
            index_len,
            index_ciphertext_hash,
            committed_at,
        })
    }

    /// Creates a record envelope for this transaction commit.
    #[must_use]
    pub fn to_envelope(&self) -> RecordEnvelope {
        RecordEnvelope::new(RECORD_TYPE_TXN_COMMIT, self.encode_body())
    }
}

// =============================================================================
// EncryptedIndexSnapshot
// =============================================================================

/// Encrypted index snapshot record.
///
/// # Binary Layout (variable)
///
/// ```text
/// Offset  Size  Field
/// ------  ----  -----
/// 0       24    nonce (XChaCha20)
/// 24      N     ciphertext (AEAD encrypted VaultIndex)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedIndexSnapshot {
    /// XChaCha20-Poly1305 nonce.
    pub nonce: [u8; NONCE_SIZE],
    /// Encrypted VaultIndex with auth tag.
    pub ciphertext: Vec<u8>,
}

impl EncryptedIndexSnapshot {
    /// Creates a new encrypted index snapshot.
    #[must_use]
    pub const fn new(nonce: [u8; NONCE_SIZE], ciphertext: Vec<u8>) -> Self {
        Self { nonce, ciphertext }
    }

    /// Encodes to body bytes (without envelope).
    #[must_use]
    pub fn encode_body(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(NONCE_SIZE + self.ciphertext.len());
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.ciphertext);
        buf
    }

    /// Decodes from body bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the body is too short for the nonce.
    pub fn decode_body(body: &[u8]) -> Result<Self, StorageError> {
        if body.len() < NONCE_SIZE {
            return Err(StorageError::UnexpectedEof {
                context: "EncryptedIndexSnapshot body too short for nonce".to_string(),
            });
        }

        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&body[0..NONCE_SIZE]);

        let ciphertext = body[NONCE_SIZE..].to_vec();

        Ok(Self { nonce, ciphertext })
    }

    /// Creates a record envelope for this encrypted index snapshot.
    #[must_use]
    pub fn to_envelope(&self) -> RecordEnvelope {
        RecordEnvelope::new(RECORD_TYPE_ENCRYPTED_INDEX, self.encode_body())
    }
}

// =============================================================================
// EncryptedBlobObject
// =============================================================================

/// Encrypted blob object record.
///
/// # Binary Layout (variable)
///
/// ```text
/// Offset  Size  Field
/// ------  ----  -----
/// 0       32    content_id (SHA256 of plaintext)
/// 32      1     blob_kind
/// 33      24    nonce (XChaCha20)
/// 57      N     ciphertext (AEAD encrypted blob)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedBlobObject {
    /// Content-addressable ID (SHA256 of plaintext).
    pub content_id: ContentId,
    /// Classification of this blob.
    pub blob_kind: BlobKind,
    /// XChaCha20-Poly1305 nonce.
    pub nonce: [u8; NONCE_SIZE],
    /// Encrypted blob data with auth tag.
    pub ciphertext: Vec<u8>,
}

impl EncryptedBlobObject {
    /// Fixed header size before ciphertext.
    pub const HEADER_SIZE: usize = 32 + 1 + NONCE_SIZE; // 57 bytes

    /// Creates a new encrypted blob object.
    #[must_use]
    pub const fn new(
        content_id: ContentId,
        blob_kind: BlobKind,
        nonce: [u8; NONCE_SIZE],
        ciphertext: Vec<u8>,
    ) -> Self {
        Self {
            content_id,
            blob_kind,
            nonce,
            ciphertext,
        }
    }

    /// Encodes to body bytes (without envelope).
    #[must_use]
    pub fn encode_body(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::HEADER_SIZE + self.ciphertext.len());
        buf.extend_from_slice(self.content_id.as_bytes());
        buf.push(self.blob_kind as u8);
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.ciphertext);
        buf
    }

    /// Decodes from body bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the body is too short or blob kind is invalid.
    pub fn decode_body(body: &[u8]) -> Result<Self, StorageError> {
        if body.len() < Self::HEADER_SIZE {
            return Err(StorageError::UnexpectedEof {
                context: "EncryptedBlobObject body too short".to_string(),
            });
        }

        let mut content_id_bytes = [0u8; 32];
        content_id_bytes.copy_from_slice(&body[0..32]);
        let content_id = ContentId::new(content_id_bytes);

        let blob_kind = BlobKind::from_u8(body[32]).ok_or_else(|| StorageError::CorruptedData {
            context: format!("invalid blob kind: {}", body[32]),
        })?;

        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&body[33..33 + NONCE_SIZE]);

        let ciphertext = body[Self::HEADER_SIZE..].to_vec();

        Ok(Self {
            content_id,
            blob_kind,
            nonce,
            ciphertext,
        })
    }

    /// Creates a record envelope for this encrypted blob object.
    #[must_use]
    pub fn to_envelope(&self) -> RecordEnvelope {
        RecordEnvelope::new(RECORD_TYPE_ENCRYPTED_BLOB, self.encode_body())
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_envelope_roundtrip() {
        let envelope = RecordEnvelope::new(RECORD_TYPE_TXN_BEGIN, vec![1, 2, 3, 4, 5]);

        let encoded = envelope.encode();
        assert_eq!(encoded.len(), envelope.encoded_len());

        let decoded = RecordEnvelope::decode(&encoded).unwrap();
        assert_eq!(envelope, decoded);
    }

    #[test]
    fn test_record_envelope_empty_body() {
        let envelope = RecordEnvelope::new(0x9999, vec![]);

        let encoded = envelope.encode();
        let decoded = RecordEnvelope::decode(&encoded).unwrap();
        assert_eq!(envelope, decoded);
    }

    #[test]
    fn test_record_envelope_large_body() {
        let body = vec![0xAB; 10000];
        let envelope = RecordEnvelope::new(RECORD_TYPE_ENCRYPTED_INDEX, body);

        let encoded = envelope.encode();
        let decoded = RecordEnvelope::decode(&encoded).unwrap();
        assert_eq!(envelope, decoded);
    }

    #[test]
    fn test_record_envelope_invalid_magic() {
        let mut encoded = RecordEnvelope::new(0, vec![1, 2, 3]).encode();
        encoded[0] = 0xFF;

        let result = RecordEnvelope::decode(&encoded);
        assert!(matches!(result, Err(StorageError::InvalidMagic { .. })));
    }

    #[test]
    fn test_record_envelope_invalid_crc() {
        let mut encoded = RecordEnvelope::new(0, vec![1, 2, 3]).encode();
        encoded[12] ^= 0xFF;

        let result = RecordEnvelope::decode(&encoded);
        assert!(matches!(result, Err(StorageError::ChecksumMismatch { .. })));
    }

    #[test]
    fn test_record_envelope_peek_body_len() {
        let envelope = RecordEnvelope::new(0, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let encoded = envelope.encode();

        let body_len = RecordEnvelope::peek_body_len(&encoded).unwrap();
        assert_eq!(body_len, 10);
    }

    #[test]
    fn test_txn_begin_roundtrip() {
        let txn = TxnBegin::new([0x42u8; 16], 1234567890);

        let body = txn.encode_body();
        assert_eq!(body.len(), TxnBegin::BODY_SIZE);

        let decoded = TxnBegin::decode_body(&body).unwrap();
        assert_eq!(txn, decoded);
    }

    #[test]
    fn test_txn_begin_envelope() {
        let txn = TxnBegin::new([1u8; 16], 999);
        let envelope = txn.to_envelope();

        assert_eq!(envelope.record_type, RECORD_TYPE_TXN_BEGIN);

        let encoded = envelope.encode();
        let decoded_envelope = RecordEnvelope::decode(&encoded).unwrap();
        let decoded_txn = TxnBegin::decode_body(&decoded_envelope.body).unwrap();
        assert_eq!(txn, decoded_txn);
    }

    #[test]
    fn test_txn_commit_roundtrip() {
        let txn = TxnCommit::new([0xABu8; 16], 12345, 678, [0xCDu8; 32], 9876543210);

        let body = txn.encode_body();
        assert_eq!(body.len(), TxnCommit::BODY_SIZE);

        let decoded = TxnCommit::decode_body(&body).unwrap();
        assert_eq!(txn, decoded);
    }

    #[test]
    fn test_txn_commit_envelope() {
        let txn = TxnCommit::new([2u8; 16], 100, 50, [3u8; 32], 12345);
        let envelope = txn.to_envelope();

        assert_eq!(envelope.record_type, RECORD_TYPE_TXN_COMMIT);

        let encoded = envelope.encode();
        let decoded_envelope = RecordEnvelope::decode(&encoded).unwrap();
        let decoded_txn = TxnCommit::decode_body(&decoded_envelope.body).unwrap();
        assert_eq!(txn, decoded_txn);
    }

    #[test]
    fn test_encrypted_index_snapshot_roundtrip() {
        let snapshot = EncryptedIndexSnapshot::new([0x11u8; 24], vec![1, 2, 3, 4, 5, 6, 7, 8]);

        let body = snapshot.encode_body();
        let decoded = EncryptedIndexSnapshot::decode_body(&body).unwrap();
        assert_eq!(snapshot, decoded);
    }

    #[test]
    fn test_encrypted_index_snapshot_envelope() {
        let snapshot = EncryptedIndexSnapshot::new([0x22u8; 24], vec![0xAA; 100]);
        let envelope = snapshot.to_envelope();

        assert_eq!(envelope.record_type, RECORD_TYPE_ENCRYPTED_INDEX);

        let encoded = envelope.encode();
        let decoded_envelope = RecordEnvelope::decode(&encoded).unwrap();
        let decoded_snapshot = EncryptedIndexSnapshot::decode_body(&decoded_envelope.body).unwrap();
        assert_eq!(snapshot, decoded_snapshot);
    }

    #[test]
    fn test_encrypted_blob_object_roundtrip() {
        let blob = EncryptedBlobObject::new(
            ContentId::new([0x33u8; 32]),
            BlobKind::CredentialBlob,
            [0x44u8; 24],
            vec![0xBB; 200],
        );

        let body = blob.encode_body();
        let decoded = EncryptedBlobObject::decode_body(&body).unwrap();
        assert_eq!(blob, decoded);
    }

    #[test]
    fn test_encrypted_blob_object_envelope() {
        let blob = EncryptedBlobObject::new(
            ContentId::new([0x55u8; 32]),
            BlobKind::AssociatedData,
            [0x66u8; 24],
            vec![0xCC; 50],
        );
        let envelope = blob.to_envelope();

        assert_eq!(envelope.record_type, RECORD_TYPE_ENCRYPTED_BLOB);

        let encoded = envelope.encode();
        let decoded_envelope = RecordEnvelope::decode(&encoded).unwrap();
        let decoded_blob = EncryptedBlobObject::decode_body(&decoded_envelope.body).unwrap();
        assert_eq!(blob, decoded_blob);
    }

    #[test]
    fn test_encrypted_blob_object_invalid_kind() {
        let mut body = EncryptedBlobObject::new(
            ContentId::new([0u8; 32]),
            BlobKind::CredentialBlob,
            [0u8; 24],
            vec![],
        )
        .encode_body();

        // Set invalid blob kind
        body[32] = 0xFF;

        let result = EncryptedBlobObject::decode_body(&body);
        assert!(matches!(result, Err(StorageError::CorruptedData { .. })));
    }
}
