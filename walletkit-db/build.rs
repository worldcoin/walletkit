//! Build script for walletkit-db.
//!
//! On non-WASM targets this downloads the sqlite3mc amalgamation from a pinned
//! upstream release (if not already cached) and compiles it into a static
//! library.
//!
//! On WASM targets compilation is skipped because `sqlite-wasm-rs` provides
//! the pre-compiled WASM binary.
//!
//! ## Patches applied to the sqlite3mc amalgamation
//!
//! After extraction, a targeted patch is applied to `sqlite3mc_amalgamation.c`
//! to fix a thread-safety bug in `sqlite3mc_cipher_name`.
//!
//! ### Bug: `sqlite3mc_cipher_name` uses a thread-unsafe `static` buffer
//!
//! The upstream sqlite3mc 2.2.7 implementation of `sqlite3mc_cipher_name`
//! returns a pointer to a `static char cipherName[]` local variable — a
//! process-wide buffer shared by all threads. When multiple threads call
//! `sqlite3_open_v2` concurrently (e.g. in parallel Rust test runs), each
//! call goes through `sqlite3mcConfigureFromUri` → `sqlite3mc_cipher_name`.
//! If two threads race on this function:
//!
//!   1. Thread A calls `sqlite3mc_cipher_name(3)`, sets the static buffer to
//!      `"chacha20"`, and stores the returned pointer.
//!   2. Thread B simultaneously calls `sqlite3mc_cipher_name(3)`, resets the
//!      buffer to `'\0'` and then to `"chacha20"`.
//!   3. Between steps 1 and 2, Thread A reads through the pointer and sees an
//!      empty string for the comparison in `sqlite3mcConfigureFromUri`, so the
//!      cipher-name lookup in `globalCodecParameterTable` fails.
//!   4. The error `DbError { message: "unknown cipher 'chacha20'" }` is
//!      returned from `sqlite3_open_v2`, causing an otherwise unrelated test
//!      (e.g. `test_null_handling`) to panic.
//!
//! The fix removes the static buffer and returns a pointer directly to the
//! stable `globalCodecDescriptorTable[j].m_name` entry, which lives for the
//! full lifetime of the process and is never mutated after `sqlite3mc_initialize`
//! completes.  Concurrent reads of stable memory are safe without any locking.
//!
//! This has been reported upstream:
//! <https://github.com/utelle/SQLite3MultipleCiphers/issues> (track the fix
//! there and remove this patch once a fixed version is pinned).

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

// Pinned sqlite3mc release.
const SQLITE3MC_VERSION: &str = "2.2.7";
const SQLITE_VERSION: &str = "3.51.2";
const DOWNLOAD_URL: &str = "https://github.com/utelle/SQLite3MultipleCiphers/releases/download/v2.2.7/sqlite3mc-2.2.7-sqlite-3.51.2-amalgamation.zip";
const EXPECTED_SHA256: &str =
    "8e84aadc53bc09bda9cd307745a178191e7783e1b6478d74ffbcdf6a04f98085";

/// Files we need from the zip archive.
const NEEDED_FILES: &[&str] = &["sqlite3mc_amalgamation.c", "sqlite3mc_amalgamation.h"];

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
        patch_thread_safe_cipher_name(&amalgamation_c);
    }

    compile(&amalgamation_c, &source_dir);
}

/// Downloads the pinned amalgamation zip using curl.
fn download(dest: &Path) {
    println!("cargo:warning=Downloading sqlite3mc {SQLITE3MC_VERSION} (SQLite {SQLITE_VERSION})...");
    let status = Command::new("curl")
        .args(["-fsSL", "-o"])
        .arg(dest)
        .arg(DOWNLOAD_URL)
        .status()
        .expect("failed to run curl -- is it installed?");
    assert!(status.success(), "curl failed with status {status}");
}

/// Verifies the SHA-256 checksum of the downloaded zip.
fn verify_checksum(zip_path: &Path) {
    let data = std::fs::read(zip_path).expect("failed to read zip for checksum");
    let hash = Sha256::digest(&data);
    let actual_hash = format!("{hash:x}");
    assert_eq!(
        actual_hash, EXPECTED_SHA256,
        "sqlite3mc checksum mismatch!\n  expected: {EXPECTED_SHA256}\n  actual:   {actual_hash}\n\
         The download may be corrupted or the pinned release has changed."
    );
}

/// Extracts the needed files from the zip into `dest_dir`.
fn extract(zip_path: &Path, dest_dir: &Path) {
    let file = std::fs::File::open(zip_path).expect("failed to open zip");
    let mut archive = zip::ZipArchive::new(file).expect("failed to read zip archive");

    for name in NEEDED_FILES {
        let mut entry = archive
            .by_name(name)
            .unwrap_or_else(|e| panic!("file {name} not found in zip: {e}"));
        let dest_path = dest_dir.join(name);
        let mut buf = Vec::with_capacity(usize::try_from(entry.size()).unwrap_or(0));
        entry
            .read_to_end(&mut buf)
            .unwrap_or_else(|e| panic!("failed to read {name} from zip: {e}"));
        std::fs::write(&dest_path, &buf)
            .unwrap_or_else(|e| panic!("failed to write {}: {e}", dest_path.display()));
    }
}

/// Patches `sqlite3mc_amalgamation.c` in-place to fix the thread-safety bug in
/// `sqlite3mc_cipher_name`.
///
/// The upstream implementation returns a pointer to a `static char cipherName[]`
/// buffer that is shared by all threads. Concurrent calls race on this buffer,
/// leading to intermittent `"unknown cipher 'chacha20'"` errors when `SQLite`
/// connections are opened from multiple threads simultaneously (the default for
/// Rust's `cargo test`).
///
/// The fix replaces the function body so it returns a pointer directly to the
/// stable `globalCodecDescriptorTable[j].m_name` entry instead of copying to a
/// shared static buffer.  That pointer is written once during
/// `sqlite3mc_initialize()` and never mutated, so concurrent reads are safe.
fn patch_thread_safe_cipher_name(amalgamation_c: &Path) {
    // The amalgamation ships with CRLF line endings, so the needle and
    // replacement must use the same line endings to avoid a mismatch.
    let old = "SQLITE_API const char*\r\nsqlite3mc_cipher_name(int cipherIndex)\r\n\
               {\r\n\
               \x20\x20static char cipherName[CIPHER_NAME_MAXLEN] = \"\";\r\n\
               \x20\x20int count;\r\n\
               \x20\x20int j;\r\n\
               #ifndef SQLITE_OMIT_AUTOINIT\r\n\
               \x20\x20if( sqlite3_initialize() ) return cipherName;\r\n\
               #endif\r\n\
               \x20\x20count = sqlite3mcGetGlobalCipherCount();\r\n\
               \x20\x20j = 0;\r\n\
               \x20\x20cipherName[0] = '\\0';\r\n\
               \x20\x20if (cipherIndex > 0 && cipherIndex <= count)\r\n\
               \x20\x20{\r\n\
               \x20\x20\x20\x20for (j = 0; j < count && globalCodecDescriptorTable[j].m_name[0] != 0; ++j)\r\n\
               \x20\x20\x20\x20{\r\n\
               \x20\x20\x20\x20\x20\x20if (cipherIndex == j + 1) break;\r\n\
               \x20\x20\x20\x20}\r\n\
               \x20\x20\x20\x20if (j < count && globalCodecDescriptorTable[j].m_name[0] != 0)\r\n\
               \x20\x20\x20\x20{\r\n\
               \x20\x20\x20\x20\x20\x20strncpy(cipherName, globalCodecDescriptorTable[j].m_name, CIPHER_NAME_MAXLEN - 1);\r\n\
               \x20\x20\x20\x20\x20\x20cipherName[CIPHER_NAME_MAXLEN - 1] = '\\0';\r\n\
               \x20\x20\x20\x20}\r\n\
               \x20\x20}\r\n\
               \x20\x20return cipherName;\r\n\
               }";

    // Thread-safe replacement: return a pointer to stable memory in
    // globalCodecDescriptorTable instead of copying into a shared static buffer.
    // globalCodecDescriptorTable[j].m_name points into globalCipherNameTable
    // which is written once at init time and never modified afterwards.
    let new = "SQLITE_API const char*\r\nsqlite3mc_cipher_name(int cipherIndex)\r\n\
               {\r\n\
               \x20\x20int count;\r\n\
               \x20\x20int j;\r\n\
               #ifndef SQLITE_OMIT_AUTOINIT\r\n\
               \x20\x20if( sqlite3_initialize() ) return \"\";\r\n\
               #endif\r\n\
               \x20\x20count = sqlite3mcGetGlobalCipherCount();\r\n\
               \x20\x20if (cipherIndex > 0 && cipherIndex <= count)\r\n\
               \x20\x20{\r\n\
               \x20\x20\x20\x20for (j = 0; j < count && globalCodecDescriptorTable[j].m_name[0] != 0; ++j)\r\n\
               \x20\x20\x20\x20{\r\n\
               \x20\x20\x20\x20\x20\x20if (cipherIndex == j + 1)\r\n\
               \x20\x20\x20\x20\x20\x20{\r\n\
               \x20\x20\x20\x20\x20\x20\x20\x20return globalCodecDescriptorTable[j].m_name;\r\n\
               \x20\x20\x20\x20\x20\x20}\r\n\
               \x20\x20\x20\x20}\r\n\
               \x20\x20}\r\n\
               \x20\x20return \"\";\r\n\
               }";

    let src = std::fs::read_to_string(amalgamation_c)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", amalgamation_c.display()));

    assert!(
        src.contains(old),
        "sqlite3mc_amalgamation.c: expected `sqlite3mc_cipher_name` function body not found.\n\
         The upstream source may have changed; review and update the patch in build.rs."
    );

    let patched = src.replacen(old, new, 1);
    std::fs::write(amalgamation_c, patched).unwrap_or_else(|e| {
        panic!("failed to write patched {}: {e}", amalgamation_c.display())
    });

    println!(
        "cargo:warning=Applied thread-safety patch to sqlite3mc_cipher_name \
         (upstream sqlite3mc issue — static buffer removed)"
    );
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
