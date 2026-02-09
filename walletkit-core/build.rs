//! Build script for walletkit-core.
//!
//! On non-WASM targets this compiles the sqlite3mc (SQLite3 Multiple Ciphers)
//! amalgamation into a static library that the `db` module links against.
//! On WASM targets compilation is skipped because `sqlite-wasm-rs` provides
//! the pre-compiled WASM binary.

fn main() {
    #[cfg(feature = "storage")]
    build_sqlite3mc();
}

#[cfg(feature = "storage")]
fn build_sqlite3mc() {
    // On wasm32 targets, sqlite-wasm-rs provides the SQLite library.
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if target_arch == "wasm32" {
        return;
    }

    let mut build = cc::Build::new();

    build
        .file("sqlite3mc/sqlite3mc_amalgamation.c")
        .include("sqlite3mc")
        // Core SQLite configuration
        .define("SQLITE_CORE", None)
        .define("SQLITE_THREADSAFE", "1")
        .define("SQLITE_ENABLE_COLUMN_METADATA", None)
        .define("SQLITE_ENABLE_FTS5", None)
        .define("SQLITE_ENABLE_JSON1", None)
        .define("SQLITE_ENABLE_RTREE", None)
        .define("SQLITE_DEFAULT_WAL_SYNCHRONOUS", "1")
        .define("SQLITE_DQS", "0")
        // sqlite3mc cipher configuration – default to ChaCha20-Poly1305
        .define("CODEC_TYPE", "CODEC_TYPE_CHACHA20")
        // Disable Argon2 threading (not needed, avoids pthread dep on some targets)
        .define("ARGON2_NO_THREADS", None)
        // Optimizations
        .define("SQLITE_DEFAULT_MEMSTATUS", "0")
        .define("SQLITE_LIKE_DOESNT_MATCH_BLOBS", None)
        .define("SQLITE_OMIT_DEPRECATED", None)
        .define("SQLITE_OMIT_SHARED_CACHE", None);

    // Platform-specific flags
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    match target_os.as_str() {
        "android" => {
            build.define("HAVE_USLEEP", "1");
            build.define("HAVE_LOCALTIME_R", "1");
        }
        "ios" | "macos" => {
            build.define("HAVE_USLEEP", "1");
            build.define("HAVE_LOCALTIME_R", "1");
        }
        "linux" => {
            build.define("HAVE_USLEEP", "1");
            build.define("HAVE_LOCALTIME_R", "1");
            build.define("HAVE_POSIX_FALLOCATE", "1");
        }
        "windows" => {
            // Windows defaults are fine
        }
        _ => {}
    }

    // Suppress warnings from the amalgamation (it's third-party code)
    build.warnings(false);

    build.compile("sqlite3mc");
}
