//! Content-addressed identifier for stored blobs.

use sha2::{Digest, Sha256};

/// Length in bytes of a [`ContentId`].
pub const CONTENT_ID_LEN: usize = 32;

/// Content identifier for a stored blob — `SHA-256` over the kind tag and
/// plaintext bytes.
pub type ContentId = [u8; CONTENT_ID_LEN];

const CONTENT_ID_PREFIX: &[u8] = b"worldid:blob";

/// Computes a [`ContentId`] for `plaintext` namespaced by `kind_tag`.
///
/// The kind tag namespace is owned by the caller (each consumer defines its
/// own `u8` constants). Tags do not collide across consumers because each
/// consumer keeps its own database file.
///
/// **On-disk compatibility:** the byte layout fed into `SHA-256` is
/// `CONTENT_ID_PREFIX || [kind_tag] || plaintext`. Changing this layout would
/// invalidate existing content IDs on every device.
#[must_use]
pub fn compute_content_id(kind_tag: u8, plaintext: &[u8]) -> ContentId {
    let mut hasher = Sha256::new();
    hasher.update(CONTENT_ID_PREFIX);
    hasher.update([kind_tag]);
    hasher.update(plaintext);
    let digest = hasher.finalize();
    let mut out = [0u8; CONTENT_ID_LEN];
    out.copy_from_slice(&digest);
    out
}
