//! In-memory implementations of platform traits for testing.
//!
//! These implementations are NOT secure for production use. They are
//! designed for unit and integration testing of the storage engine.

// Allow certain clippy lints for test-only code
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::significant_drop_tightening)]
#![allow(clippy::cast_possible_truncation)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use crate::credential_storage::{AccountId, StorageError, StorageResult};

use super::{AccountLockManager, AtomicBlobStore, DeviceKeystore, VaultFileStore};

// =============================================================================
// Memory Keystore
// =============================================================================

/// In-memory device keystore using a fixed test key.
///
/// **FOR TESTING ONLY** — This implementation uses a simple XOR-based
/// "encryption" that provides no real security. It's designed to test
/// the storage engine's interaction with a keystore without requiring
/// actual cryptographic operations.
///
/// # Implementation Details
///
/// - Uses a fixed 32-byte key derived from a seed
/// - "Encrypts" by XOR-ing data with a keystream derived from the key and AD
/// - Prepends an 8-byte "nonce" (actually just random bytes for testing)
pub struct MemoryKeystore {
    /// The "device key" - just a fixed test value.
    key: [u8; 32],
}

impl MemoryKeystore {
    /// Creates a new memory keystore with a default test key.
    #[must_use]
    pub fn new() -> Self {
        Self {
            // Fixed test key - DO NOT USE IN PRODUCTION
            key: [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
            ],
        }
    }

    /// Creates a new memory keystore with a custom key.
    #[must_use]
    pub fn with_key(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Derives a keystream from the key and associated data.
    /// This is NOT cryptographically secure - for testing only.
    fn derive_keystream(&self, ad: &[u8], len: usize) -> Vec<u8> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut keystream = Vec::with_capacity(len);
        let mut counter = 0u64;

        while keystream.len() < len {
            let mut hasher = DefaultHasher::new();
            self.key.hash(&mut hasher);
            ad.hash(&mut hasher);
            counter.hash(&mut hasher);
            
            let hash = hasher.finish().to_le_bytes();
            keystream.extend_from_slice(&hash);
            counter += 1;
        }

        keystream.truncate(len);
        keystream
    }
}

impl Default for MemoryKeystore {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceKeystore for MemoryKeystore {
    fn seal(&self, associated_data: &[u8], plaintext: &[u8]) -> StorageResult<Vec<u8>> {
        // Generate a "nonce" (just random bytes for testing)
        let mut nonce = [0u8; 8];
        getrandom::getrandom(&mut nonce).map_err(|e| StorageError::Internal {
            message: format!("getrandom failed: {e}"),
        })?;

        // Derive keystream
        let mut ad_with_nonce = associated_data.to_vec();
        ad_with_nonce.extend_from_slice(&nonce);
        let keystream = self.derive_keystream(&ad_with_nonce, plaintext.len());

        // "Encrypt" by XORing
        let ciphertext: Vec<u8> = plaintext
            .iter()
            .zip(keystream.iter())
            .map(|(p, k)| p ^ k)
            .collect();

        // Prepend nonce
        let mut result = Vec::with_capacity(8 + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    fn open(&self, associated_data: &[u8], ciphertext: &[u8]) -> StorageResult<Vec<u8>> {
        if ciphertext.len() < 8 {
            return Err(StorageError::decryption("ciphertext too short"));
        }

        // Extract nonce
        let nonce = &ciphertext[0..8];
        let encrypted = &ciphertext[8..];

        // Derive keystream
        let mut ad_with_nonce = associated_data.to_vec();
        ad_with_nonce.extend_from_slice(nonce);
        let keystream = self.derive_keystream(&ad_with_nonce, encrypted.len());

        // "Decrypt" by XORing
        let plaintext: Vec<u8> = encrypted
            .iter()
            .zip(keystream.iter())
            .map(|(c, k)| c ^ k)
            .collect();

        Ok(plaintext)
    }
}

// =============================================================================
// Memory Blob Store
// =============================================================================

/// In-memory atomic blob store backed by a `HashMap`.
///
/// Thread-safe implementation for testing concurrent access patterns.
pub struct MemoryBlobStore {
    /// Storage for blobs, keyed by name.
    blobs: RwLock<HashMap<String, Vec<u8>>>,
}

impl MemoryBlobStore {
    /// Creates a new empty memory blob store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            blobs: RwLock::new(HashMap::new()),
        }
    }

    /// Returns the number of stored blobs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.blobs.read().unwrap().len()
    }

    /// Returns `true` if no blobs are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.blobs.read().unwrap().is_empty()
    }

    /// Clears all stored blobs.
    pub fn clear(&self) {
        self.blobs.write().unwrap().clear();
    }

    /// Returns a list of all blob names.
    #[must_use]
    pub fn list(&self) -> Vec<String> {
        self.blobs.read().unwrap().keys().cloned().collect()
    }
}

impl Default for MemoryBlobStore {
    fn default() -> Self {
        Self::new()
    }
}

impl AtomicBlobStore for MemoryBlobStore {
    fn read(&self, name: &str) -> StorageResult<Option<Vec<u8>>> {
        Ok(self.blobs.read().unwrap().get(name).cloned())
    }

    fn write_atomic(&self, name: &str, bytes: &[u8]) -> StorageResult<()> {
        self.blobs.write().unwrap().insert(name.to_string(), bytes.to_vec());
        Ok(())
    }

    fn delete(&self, name: &str) -> StorageResult<()> {
        self.blobs.write().unwrap().remove(name);
        Ok(())
    }

    fn exists(&self, name: &str) -> StorageResult<bool> {
        Ok(self.blobs.read().unwrap().contains_key(name))
    }
}

// =============================================================================
// Memory Vault Store
// =============================================================================

/// In-memory vault file store backed by a `Vec<u8>`.
///
/// Thread-safe implementation that simulates a random-access file.
pub struct MemoryVaultStore {
    /// The "file" contents.
    data: RwLock<Vec<u8>>,
    /// Tracks sync calls for testing.
    sync_count: Mutex<u64>,
}

impl MemoryVaultStore {
    /// Creates a new empty memory vault store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            data: RwLock::new(Vec::new()),
            sync_count: Mutex::new(0),
        }
    }

    /// Creates a new memory vault store with initial data.
    #[must_use]
    pub fn with_data(data: Vec<u8>) -> Self {
        Self {
            data: RwLock::new(data),
            sync_count: Mutex::new(0),
        }
    }

    /// Returns the number of times `sync()` has been called.
    #[must_use]
    pub fn sync_count(&self) -> u64 {
        *self.sync_count.lock().unwrap()
    }

    /// Resets the sync counter to zero.
    pub fn reset_sync_count(&self) {
        *self.sync_count.lock().unwrap() = 0;
    }

    /// Returns a copy of the current data.
    #[must_use]
    pub fn get_data(&self) -> Vec<u8> {
        self.data.read().unwrap().clone()
    }

    /// Clears all data.
    pub fn clear(&self) {
        self.data.write().unwrap().clear();
    }
}

impl Default for MemoryVaultStore {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultFileStore for MemoryVaultStore {
    fn len(&self) -> StorageResult<u64> {
        Ok(self.data.read().unwrap().len() as u64)
    }

    fn read_at(&self, offset: u64, len: u32) -> StorageResult<Vec<u8>> {
        let data = self.data.read().unwrap();
        let start = offset as usize;
        let end = start + len as usize;

        if end > data.len() {
            return Err(StorageError::IoError {
                context: format!("read beyond EOF: offset={offset}, len={len}, file_len={}", data.len()),
                source: std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "read beyond EOF"),
            });
        }

        Ok(data[start..end].to_vec())
    }

    fn write_at(&self, offset: u64, bytes: &[u8]) -> StorageResult<()> {
        let mut data = self.data.write().unwrap();
        let start = offset as usize;
        let end = start + bytes.len();

        // Extend if necessary
        if end > data.len() {
            data.resize(end, 0);
        }

        data[start..end].copy_from_slice(bytes);
        Ok(())
    }

    fn append(&self, bytes: &[u8]) -> StorageResult<u64> {
        let mut data = self.data.write().unwrap();
        let offset = data.len() as u64;
        data.extend_from_slice(bytes);
        Ok(offset)
    }

    fn sync(&self) -> StorageResult<()> {
        let mut count = self.sync_count.lock().unwrap();
        *count += 1;
        Ok(())
    }

    fn set_len(&self, len: u64) -> StorageResult<()> {
        let mut data = self.data.write().unwrap();
        data.resize(len as usize, 0);
        Ok(())
    }
}

// =============================================================================
// Memory Lock Manager
// =============================================================================

/// In-memory account lock manager using a `Mutex` per account.
///
/// Thread-safe implementation for testing concurrent access patterns.
pub struct MemoryLockManager {
    /// Locks for each account.
    locks: RwLock<HashMap<AccountId, Arc<Mutex<()>>>>,
}

impl MemoryLockManager {
    /// Creates a new memory lock manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            locks: RwLock::new(HashMap::new()),
        }
    }

    /// Gets or creates a lock for an account.
    fn get_lock(&self, account_id: &AccountId) -> Arc<Mutex<()>> {
        // First try read lock
        {
            let locks = self.locks.read().unwrap();
            if let Some(lock) = locks.get(account_id) {
                return Arc::clone(lock);
            }
        }

        // Need to create a new lock
        let mut locks = self.locks.write().unwrap();
        locks
            .entry(*account_id)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// Returns the number of tracked accounts.
    #[must_use]
    pub fn account_count(&self) -> usize {
        self.locks.read().unwrap().len()
    }

    /// Clears all tracked locks.
    pub fn clear(&self) {
        self.locks.write().unwrap().clear();
    }
}

impl Default for MemoryLockManager {
    fn default() -> Self {
        Self::new()
    }
}

impl AccountLockManager for MemoryLockManager {
    fn with_account_lock<R, F>(&self, account_id: &AccountId, f: F) -> StorageResult<R>
    where
        F: FnOnce() -> StorageResult<R>,
    {
        let lock = self.get_lock(account_id);
        let _guard = lock.lock().map_err(|e| StorageError::lock(format!("mutex poisoned: {e}")))?;
        f()
    }

    fn try_with_account_lock<R, F>(&self, account_id: &AccountId, f: F) -> StorageResult<Option<R>>
    where
        F: FnOnce() -> StorageResult<R>,
    {
        let lock = self.get_lock(account_id);
        let guard = match lock.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::WouldBlock) => return Ok(None),
            Err(std::sync::TryLockError::Poisoned(e)) => {
                return Err(StorageError::lock(format!("mutex poisoned: {e}")));
            }
        };
        let result = f();
        drop(guard);
        result.map(Some)
    }
}

// =============================================================================
// Memory Platform Bundle
// =============================================================================

/// Combines all in-memory implementations for easy test setup.
///
/// # Example
///
/// ```
/// use walletkit_core::credential_storage::platform::MemoryPlatform;
///
/// let platform = MemoryPlatform::new();
///
/// // Use platform.keystore, platform.blob_store, etc.
/// ```
pub struct MemoryPlatform {
    /// In-memory device keystore.
    pub keystore: Arc<MemoryKeystore>,
    /// In-memory blob store.
    pub blob_store: Arc<MemoryBlobStore>,
    /// In-memory vault store.
    pub vault_store: Arc<MemoryVaultStore>,
    /// In-memory lock manager.
    pub lock_manager: Arc<MemoryLockManager>,
}

impl MemoryPlatform {
    /// Creates a new memory platform with default components.
    #[must_use]
    pub fn new() -> Self {
        Self {
            keystore: Arc::new(MemoryKeystore::new()),
            blob_store: Arc::new(MemoryBlobStore::new()),
            vault_store: Arc::new(MemoryVaultStore::new()),
            lock_manager: Arc::new(MemoryLockManager::new()),
        }
    }

    /// Clears all stored data (useful for test isolation).
    pub fn reset(&self) {
        self.blob_store.clear();
        self.vault_store.clear();
        self.lock_manager.clear();
    }
}

impl Default for MemoryPlatform {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_keystore_roundtrip() {
        let keystore = MemoryKeystore::new();
        let plaintext = b"hello, world!";
        let ad = b"test-associated-data";

        let ciphertext = keystore.seal(ad, plaintext).unwrap();
        assert_ne!(&ciphertext[8..], plaintext); // Should be "encrypted"

        let decrypted = keystore.open(ad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_memory_keystore_different_ad() {
        let keystore = MemoryKeystore::new();
        let plaintext = b"secret data";
        let ad1 = b"context-1";
        let ad2 = b"context-2";

        let ciphertext = keystore.seal(ad1, plaintext).unwrap();
        
        // Decrypting with different AD should produce different (wrong) result
        let decrypted = keystore.open(ad2, &ciphertext).unwrap();
        assert_ne!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_memory_keystore_short_ciphertext() {
        let keystore = MemoryKeystore::new();
        let result = keystore.open(b"ad", &[1, 2, 3, 4, 5, 6, 7]); // Only 7 bytes
        assert!(result.is_err());
    }

    #[test]
    fn test_memory_blob_store_basic() {
        let store = MemoryBlobStore::new();
        
        assert!(store.is_empty());
        assert!(store.read("test").unwrap().is_none());

        store.write_atomic("test", b"hello").unwrap();
        assert_eq!(store.len(), 1);
        assert!(store.exists("test").unwrap());
        assert_eq!(store.read("test").unwrap(), Some(b"hello".to_vec()));

        store.write_atomic("test", b"world").unwrap();
        assert_eq!(store.read("test").unwrap(), Some(b"world".to_vec()));

        store.delete("test").unwrap();
        assert!(store.read("test").unwrap().is_none());
        assert!(!store.exists("test").unwrap());
    }

    #[test]
    fn test_memory_blob_store_multiple() {
        let store = MemoryBlobStore::new();
        
        store.write_atomic("a", b"data-a").unwrap();
        store.write_atomic("b", b"data-b").unwrap();
        store.write_atomic("c", b"data-c").unwrap();

        assert_eq!(store.len(), 3);
        
        let names = store.list();
        assert!(names.contains(&"a".to_string()));
        assert!(names.contains(&"b".to_string()));
        assert!(names.contains(&"c".to_string()));

        store.clear();
        assert!(store.is_empty());
    }

    #[test]
    fn test_memory_vault_store_basic() {
        let store = MemoryVaultStore::new();
        
        assert!(store.is_empty().unwrap());
        assert_eq!(store.len().unwrap(), 0);

        // Append data
        let offset = store.append(b"hello").unwrap();
        assert_eq!(offset, 0);
        assert_eq!(store.len().unwrap(), 5);

        let offset = store.append(b" world").unwrap();
        assert_eq!(offset, 5);
        assert_eq!(store.len().unwrap(), 11);

        // Read
        assert_eq!(store.read_at(0, 5).unwrap(), b"hello");
        assert_eq!(store.read_at(5, 6).unwrap(), b" world");
        assert_eq!(store.read_at(0, 11).unwrap(), b"hello world");
    }

    #[test]
    fn test_memory_vault_store_write_at() {
        let store = MemoryVaultStore::new();
        
        // Write beyond current length extends file
        store.write_at(10, b"test").unwrap();
        assert_eq!(store.len().unwrap(), 14);

        // Read back
        let data = store.read_at(10, 4).unwrap();
        assert_eq!(data, b"test");

        // Overwrite
        store.write_at(0, b"header").unwrap();
        let data = store.read_at(0, 6).unwrap();
        assert_eq!(data, b"header");
    }

    #[test]
    fn test_memory_vault_store_read_beyond_eof() {
        let store = MemoryVaultStore::new();
        store.append(b"short").unwrap();

        let result = store.read_at(0, 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_memory_vault_store_sync() {
        let store = MemoryVaultStore::new();
        
        assert_eq!(store.sync_count(), 0);
        store.sync().unwrap();
        assert_eq!(store.sync_count(), 1);
        store.sync().unwrap();
        assert_eq!(store.sync_count(), 2);

        store.reset_sync_count();
        assert_eq!(store.sync_count(), 0);
    }

    #[test]
    fn test_memory_vault_store_set_len() {
        let store = MemoryVaultStore::new();
        
        store.set_len(100).unwrap();
        assert_eq!(store.len().unwrap(), 100);

        store.set_len(50).unwrap();
        assert_eq!(store.len().unwrap(), 50);
    }

    #[test]
    fn test_memory_lock_manager_basic() {
        let lock_manager = MemoryLockManager::new();
        let account_id = AccountId::new([1u8; 32]);

        let result = lock_manager.with_account_lock(&account_id, || {
            Ok(42)
        }).unwrap();

        assert_eq!(result, 42);
        assert_eq!(lock_manager.account_count(), 1);
    }

    #[test]
    fn test_memory_lock_manager_try_lock() {
        let lock_manager = Arc::new(MemoryLockManager::new());
        let account_id = AccountId::new([1u8; 32]);

        // Should succeed when lock is free
        let result = lock_manager.try_with_account_lock(&account_id, || {
            Ok(42)
        }).unwrap();
        assert_eq!(result, Some(42));
    }

    #[test]
    fn test_memory_lock_manager_multiple_accounts() {
        let lock_manager = MemoryLockManager::new();
        let account1 = AccountId::new([1u8; 32]);
        let account2 = AccountId::new([2u8; 32]);

        lock_manager.with_account_lock(&account1, || Ok(())).unwrap();
        lock_manager.with_account_lock(&account2, || Ok(())).unwrap();

        assert_eq!(lock_manager.account_count(), 2);

        lock_manager.clear();
        assert_eq!(lock_manager.account_count(), 0);
    }

    #[test]
    fn test_memory_platform_bundle() {
        let platform = MemoryPlatform::new();

        // Test keystore
        let ct = platform.keystore.seal(b"ad", b"data").unwrap();
        let pt = platform.keystore.open(b"ad", &ct).unwrap();
        assert_eq!(pt, b"data");

        // Test blob store
        platform.blob_store.write_atomic("test", b"blob").unwrap();
        assert!(platform.blob_store.exists("test").unwrap());

        // Test vault store
        platform.vault_store.append(b"vault data").unwrap();
        assert!(!platform.vault_store.is_empty().unwrap());

        // Test lock manager
        let account = AccountId::new([0u8; 32]);
        platform.lock_manager.with_account_lock(&account, || Ok(())).unwrap();

        // Reset clears everything
        platform.reset();
        assert!(platform.blob_store.is_empty());
        assert!(platform.vault_store.is_empty().unwrap());
        assert_eq!(platform.lock_manager.account_count(), 0);
    }

    #[test]
    fn test_memory_blob_store_thread_safety() {
        use std::thread;

        let store = Arc::new(MemoryBlobStore::new());
        let mut handles = vec![];

        // Spawn multiple threads writing different keys
        for i in 0..10 {
            let store = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                let name = format!("key-{i}");
                store.write_atomic(&name, format!("value-{i}").as_bytes()).unwrap();
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(store.len(), 10);
    }
}
