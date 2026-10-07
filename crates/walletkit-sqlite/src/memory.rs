//! Temporary plaintext databases in the WASM memory VFS.

use sqlite_wasm_rs::{MemVfsUtil, WasmOsCallback};

use crate::{DbResult, Error};

/// An imported database removed from the memory VFS when dropped.
/// Close or detach all connections to it before dropping this value.
pub struct ImportedDatabase {
    vfs: MemVfsUtil<WasmOsCallback>,
    path: String,
}

impl ImportedDatabase {
    /// Copies a plaintext SQLite image into the memory VFS at a unique path.
    ///
    /// # Errors
    /// Returns an error if the image header is invalid or the path already exists.
    pub fn new(path: String, bytes: &[u8]) -> DbResult<Self> {
        let header = bytes
            .get(..18)
            .ok_or_else(|| Error::new(-1, "invalid backup header"))?;
        let page_size = u16::from_be_bytes([header[16], header[17]]);
        if page_size != 1
            && (!(512..=32768).contains(&page_size) || !page_size.is_power_of_two())
        {
            return Err(Error::new(-1, "invalid backup page size"));
        }
        let vfs = MemVfsUtil::new();
        vfs.import_db(&path, bytes).map_err(|e| {
            Error::new(
                -1,
                format!("failed to import plaintext backup into memory VFS: {e}"),
            )
        })?;
        Ok(Self { vfs, path })
    }
}

impl Drop for ImportedDatabase {
    fn drop(&mut self) {
        self.vfs.delete_db(&self.path);
    }
}
