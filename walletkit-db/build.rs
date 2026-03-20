//! Build script for walletkit-db.
//!
//! On non-WASM targets this downloads the sqlite3mc amalgamation zip from the
//! official v2.3.2 release, extracts the pre-generated amalgamation files, and
//! compiles them into a static library.
//!
//! On WASM targets compilation is skipped because `sqlite-wasm-rs` provides
//! the pre-compiled WASM binary.
//!
//! ## Release zip
//!
//! The upstream v2.3.2 release ships a dedicated amalgamation zip
//! (`sqlite3mc-2.3.2-sqlite-3.51.3-amalgamation.zip`) that already contains
//! `sqlite3mc_amalgamation.c` and `sqlite3mc_amalgamation.h` at the root — no
//! Python or build-time source generation is required.
//!
//! v2.3.2 includes the thread-safety fix for `sqlite3mc_cipher_name` (upstream
//! issue #228, commit `07a1a60`) that landed after the v2.3.1 release.
//!
//! Upstream issue:  <https://github.com/utelle/SQLite3MultipleCiphers/issues/228>
//! Fix commit:      <https://github.com/utelle/SQLite3MultipleCiphers/commit/07a1a60>
//! Release:         <https://github.com/utelle/SQLite3MultipleCiphers/releases/tag/v2.3.2>

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

const SQLITE3MC_VERSION: &str = "2.3.2";
const SQLITE_VERSION: &str = "3.51.3";

const DOWNLOAD_URL: &str = "https://github.com/utelle/SQLite3MultipleCiphers/releases/\
    download/v2.3.2/sqlite3mc-2.3.2-sqlite-3.51.3-amalgamation.zip";
const EXPECTED_SHA256: &str =
    "3462d3f09e91daa829b8787d93f451168fbafc4ccbf9d579f5e4117416f5c82d";

fn main() {
    build_sqlite3mc();
}

fn build_sqlite3mc() {
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if target_arch == "wasm32" {
        return;
    }

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR not set"));
    let source_dir = out_dir.join(format!("sqlite3mc-{SQLITE3MC_VERSION}"));
    let amalgamation_c = source_dir.join("sqlite3mc_amalgamation.c");
    let amalgamation_h = source_dir.join("sqlite3mc_amalgamation.h");

    // Download and extract if not already cached in OUT_DIR.
    if !amalgamation_c.exists() || !amalgamation_h.exists() {
        std::fs::create_dir_all(&source_dir).expect("failed to create source dir");
        let zip_path = out_dir.join("sqlite3mc-amalgamation.zip");
        download(&zip_path);
        verify_checksum(&zip_path);
        extract(&zip_path, &source_dir);
        assert!(
            amalgamation_c.exists(),
            "sqlite3mc_amalgamation.c not found after extraction"
        );
        assert!(
            amalgamation_h.exists(),
            "sqlite3mc_amalgamation.h not found after extraction"
        );
    }

    compile(&amalgamation_c, &source_dir);
}

/// Downloads the release amalgamation zip using curl.
fn download(dest: &Path) {
    println!(
        "cargo:warning=Downloading sqlite3mc v{SQLITE3MC_VERSION} amalgamation \
         (SQLite {SQLITE_VERSION})..."
    );
    let status = Command::new("curl")
        .args(["-fsSL", "-o"])
        .arg(dest)
        .arg(DOWNLOAD_URL)
        .status()
        .expect("failed to run curl -- is it installed?");
    assert!(status.success(), "curl failed with status {status}");
}

/// Verifies the SHA-256 checksum of the downloaded archive.
fn verify_checksum(zip_path: &Path) {
    let data = std::fs::read(zip_path).expect("failed to read zip for checksum");
    let hash = Sha256::digest(&data);
    let actual_hash = format!("{hash:x}");
    assert_eq!(
        actual_hash, EXPECTED_SHA256,
        "sqlite3mc checksum mismatch!\n  expected: {EXPECTED_SHA256}\n  actual:   {actual_hash}\n\
         The download may be corrupted or the release zip has changed."
    );
}

/// Extracts the amalgamation zip into `dest_dir`.
///
/// The release amalgamation zip has no top-level directory prefix; files
/// (`sqlite3mc_amalgamation.c`, `sqlite3mc_amalgamation.h`, etc.) sit at the
/// root of the archive and are extracted directly into `dest_dir`.
fn extract(zip_path: &Path, dest_dir: &Path) {
    let file = std::fs::File::open(zip_path).expect("failed to open zip");
    let mut archive = zip::ZipArchive::new(file).expect("failed to read zip archive");

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).expect("failed to read zip entry");
        let raw_name = entry.name().to_owned();

        if raw_name.is_empty() {
            continue;
        }

        // Guard against zip-slip: reject entries with absolute paths or `..`
        // components. In practice the SHA-256 check above ensures the archive
        // hasn't been tampered with, but this is an extra layer of defence.
        if raw_name.contains("..") || raw_name.starts_with('/') {
            panic!("zip entry with unsafe path rejected: {raw_name}");
        }

        let dest_path = dest_dir.join(&raw_name);
        if entry.is_dir() {
            std::fs::create_dir_all(&dest_path).unwrap_or_else(|e| {
                panic!("failed to create dir {}: {e}", dest_path.display())
            });
        } else {
            if let Some(parent) = dest_path.parent() {
                std::fs::create_dir_all(parent).unwrap_or_else(|e| {
                    panic!("failed to create dir {}: {e}", parent.display())
                });
            }
            let mut buf =
                Vec::with_capacity(usize::try_from(entry.size()).unwrap_or(0));
            entry
                .read_to_end(&mut buf)
                .unwrap_or_else(|e| panic!("failed to read {raw_name} from zip: {e}"));
            std::fs::write(&dest_path, &buf).unwrap_or_else(|e| {
                panic!("failed to write {}: {e}", dest_path.display())
            });
        }
    }
}

/// Compiles the sqlite3mc amalgamation into a static library.
fn compile(amalgamation_c: &Path, include_dir: &Path) {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    let mut build = cc::Build::new();
    build
        .file(amalgamation_c)
        .include(include_dir)
        // Core SQLite configuration
        .define("SQLITE_CORE", None)
        .define("SQLITE_THREADSAFE", "1")
        .define("SQLITE_ENABLE_COLUMN_METADATA", None)
        .define("SQLITE_ENABLE_FTS5", None)
        .define("SQLITE_ENABLE_JSON1", None)
        .define("SQLITE_ENABLE_RTREE", None)
        .define("SQLITE_DEFAULT_WAL_SYNCHRONOUS", "1")
        .define("SQLITE_DQS", "0")
        // sqlite3mc cipher configuration -- default to ChaCha20-Poly1305
        .define("CODEC_TYPE", "CODEC_TYPE_CHACHA20")
        // Disable Argon2 threading (not needed, avoids pthread dep on some targets)
        .define("ARGON2_NO_THREADS", None)
        // Optimizations
        .define("SQLITE_DEFAULT_MEMSTATUS", "0")
        .define("SQLITE_LIKE_DOESNT_MATCH_BLOBS", None)
        .define("SQLITE_OMIT_DEPRECATED", None)
        .define("SQLITE_OMIT_SHARED_CACHE", None);

    match target_os.as_str() {
        "android" | "ios" | "macos" => {
            build.define("HAVE_USLEEP", "1");
            build.define("HAVE_LOCALTIME_R", "1");
        }
        "linux" => {
            build.define("HAVE_USLEEP", "1");
            build.define("HAVE_LOCALTIME_R", "1");
            build.define("HAVE_POSIX_FALLOCATE", "1");
        }
        _ => {}
    }

    // Suppress warnings from the amalgamation (third-party code)
    build.warnings(false);
    build.compile("sqlite3mc");
}
