//! Build script for walletkit-db.
//!
//! On non-WASM targets this downloads the sqlite3mc source archive from a
//! pinned upstream commit, generates the amalgamation using the bundled
//! `scripts/amalgamate.py`, and compiles it into a static library.
//!
//! On WASM targets compilation is skipped because `sqlite-wasm-rs` provides
//! the pre-compiled WASM binary.
//!
//! ## Why a commit SHA rather than a release tag?
//!
//! The thread-safety fix for `sqlite3mc_cipher_name` (upstream issue #228) was
//! committed to sqlite3mc `main` in commit `07a1a60` on 2026-03-18, five days
//! after the v2.3.1 release.  We pin directly to that commit rather than
//! waiting for the next release.
//!
//! The fix replaces the internal call to `sqlite3mc_cipher_name` (which writes
//! to a `static char[]` buffer) with a new `sqlite3mcFindCipherName` helper
//! that returns a stable pointer into `globalCodecDescriptorTable` memory,
//! making concurrent `sqlite3_open_v2` calls safe without any Rust-side locking.
//!
//! Upstream issue:  <https://github.com/utelle/SQLite3MultipleCiphers/issues/228>
//! Fix commit:      <https://github.com/utelle/SQLite3MultipleCiphers/commit/07a1a60>
//!
//! When the next sqlite3mc release that includes this commit is published,
//! switch back to the release-zip URL and update the constants accordingly.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

// Pinned sqlite3mc commit (contains the thread-safety fix for issue #228).
// The short form is used in human-readable messages and directory names; the
// full SHA is embedded in DOWNLOAD_URL and ARCHIVE_PREFIX below.
const SQLITE3MC_COMMIT_SHORT: &str = "07a1a60";
// SQLite version bundled in the source tree at this commit.
const SQLITE_VERSION: &str = "3.51.3";

const DOWNLOAD_URL: &str = "https://github.com/utelle/SQLite3MultipleCiphers/archive/\
    07a1a60ce6439467620e247c88e0449572e03cb5.zip";
const EXPECTED_SHA256: &str =
    "014d49636fea11fd598089f0ee4d19f022edc3aead0c769156444618eba6f051";

// Every path inside the GitHub source archive is prefixed with this directory.
const ARCHIVE_PREFIX: &str =
    "SQLite3MultipleCiphers-07a1a60ce6439467620e247c88e0449572e03cb5/";

fn main() {
    build_sqlite3mc();
}

fn build_sqlite3mc() {
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if target_arch == "wasm32" {
        return;
    }

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR not set"));
    let source_dir = out_dir.join(format!("sqlite3mc-{SQLITE3MC_COMMIT_SHORT}"));
    let amalgamation_c = source_dir.join("sqlite3mc_amalgamation.c");
    let amalgamation_h = source_dir.join("sqlite3mc_amalgamation.h");

    // Download, extract, and amalgamate if not already cached in OUT_DIR.
    if !amalgamation_c.exists() || !amalgamation_h.exists() {
        std::fs::create_dir_all(&source_dir).expect("failed to create source dir");
        let zip_path = out_dir.join("sqlite3mc-source.zip");
        download(&zip_path);
        verify_checksum(&zip_path);
        extract(&zip_path, &source_dir);
        amalgamate(&source_dir);
        assert!(
            amalgamation_c.exists(),
            "sqlite3mc_amalgamation.c not found after amalgamation"
        );
        assert!(
            amalgamation_h.exists(),
            "sqlite3mc_amalgamation.h not found after amalgamation"
        );
    }

    compile(&amalgamation_c, &source_dir);
}

/// Downloads the pinned source archive using curl.
fn download(dest: &Path) {
    println!(
        "cargo:warning=Downloading sqlite3mc commit {SQLITE3MC_COMMIT_SHORT} \
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
         The download may be corrupted or the pinned commit archive has changed."
    );
}

/// Extracts the source archive into `dest_dir`, stripping the top-level
/// archive prefix so that `dest_dir/src/`, `dest_dir/scripts/`, etc. are
/// created directly.
fn extract(zip_path: &Path, dest_dir: &Path) {
    let file = std::fs::File::open(zip_path).expect("failed to open zip");
    let mut archive = zip::ZipArchive::new(file).expect("failed to read zip archive");

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).expect("failed to read zip entry");
        let raw_name = entry.name().to_owned();

        // Strip the top-level directory prefix that GitHub adds to source archives.
        let Some(rel) = raw_name.strip_prefix(ARCHIVE_PREFIX) else {
            continue; // entry is outside the expected prefix — skip
        };
        if rel.is_empty() {
            continue; // the prefix directory entry itself
        }

        let dest_path = dest_dir.join(rel);
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

/// Runs `scripts/amalgamate.py` inside `source_dir` to produce
/// `sqlite3mc_amalgamation.c` and `sqlite3mc_amalgamation.h`.
///
/// The script is bundled in the upstream source tree and requires Python 3.
/// It reads `src/` (which includes the `SQLite` amalgamation and all sqlite3mc
/// cipher sources) and writes two self-contained amalgamation files.
fn amalgamate(source_dir: &Path) {
    for config in ["scripts/sqlite3mc.c.json", "scripts/sqlite3mc.h.json"] {
        let status = Command::new("python3")
            .current_dir(source_dir)
            .args(["scripts/amalgamate.py", "-c", config, "-s", "src"])
            .status()
            .expect("failed to run python3 -- is it installed?");
        assert!(
            status.success(),
            "amalgamate.py failed for {config} with status {status}"
        );
    }
    println!("cargo:warning=Generated sqlite3mc amalgamation from commit {SQLITE3MC_COMMIT_SHORT}");
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
