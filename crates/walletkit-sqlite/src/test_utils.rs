//! Shared test helpers for crates built on `walletkit-sqlite`.

use std::sync::OnceLock;

use crate::Connection;

/// Ensures sqlite3mc's global codec registration is complete before any test
/// body runs.
///
/// sqlite3mc registers its cipher implementations the first time
/// `sqlite3_open_v2` is called. When the test binary runs all tests in
/// parallel threads, two threads can race inside that one-time
/// initialization and one of them sees an "unknown cipher 'chacha20'"
/// error even though chacha20 is compiled in.
///
/// Calling this at the start of every test ensures exactly one thread
/// performs the first open (all others block on the `OnceLock`) so that
/// by the time any test-specific code runs, sqlite3mc is fully initialized.
///
/// # Panics
///
/// Panics if sqlite3mc cannot open an in-memory database.
pub fn init_sqlite() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        drop(
            Connection::open(std::path::Path::new(":memory:"), false)
                .expect("sqlite3mc pre-init"),
        );
    });
}
