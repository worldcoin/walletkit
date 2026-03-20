//! Build script for walletkit-db.
//!
//! On non-WASM targets this downloads the sqlite3mc v2.3.2 amalgamation zip,
//! extracts the pre-built `sqlite3mc_amalgamation.c` / `.h`, and compiles them
//! into a static library.
//!
//! On WASM targets compilation is skipped because `sqlite-wasm-rs` provides
//! the pre-compiled WASM binary.

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

fn extract(zip_path: &Path, dest_dir: &Path) {
    let file = std::fs::File::open(zip_path).expect("failed to open zip");
    let mut archive = zip::ZipArchive::new(file).expect("failed to read zip archive");

    for name in ["sqlite3mc_amalgamation.c", "sqlite3mc_amalgamation.h"] {
        let mut entry = archive
            .by_name(name)
            .unwrap_or_else(|e| panic!("failed to find {name} in zip: {e}"));
        let mut buf = Vec::with_capacity(usize::try_from(entry.size()).unwrap_or(0));
        entry
            .read_to_end(&mut buf)
            .unwrap_or_else(|e| panic!("failed to read {name} from zip: {e}"));
        std::fs::write(dest_dir.join(name), &buf)
            .unwrap_or_else(|e| panic!("failed to write {name}: {e}"));
    }
}

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
        // Default cipher: ChaCha20-Poly1305
        .define("CODEC_TYPE", "CODEC_TYPE_CHACHA20")
        // Disable Argon2 threading (avoids pthread dep on some targets)
        .define("ARGON2_NO_THREADS", None)
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

    build.warnings(false); // third-party code
    build.compile("sqlite3mc");
}
