//! Shared test helpers. `#[cfg(test)]` only.

use std::sync::OnceLock;

use walletkit_sqlite::Connection;

/// Initializes sqlite3mc once before tests execute database operations.
pub fn init_sqlite() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        drop(
            Connection::open(std::path::Path::new(":memory:"), false)
                .expect("sqlite3mc pre-init"),
        );
    });
}
