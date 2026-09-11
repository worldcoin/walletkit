//! Native link-order regression probe using disposable, synthetic database data.

use secrecy::SecretBox;
use walletkit_sqlite::{cipher, Connection};

/// Exercises encrypted storage in a host that also links an unrelated `SQLite`.
/// Returns zero on success; reports an actionable error and returns one otherwise.
#[no_mangle]
pub extern "C" fn walletkit_native_link_probe() -> i32 {
    match probe() {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("WalletKit SQLite link regression: {error}");
            1
        }
    }
}

fn probe() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("encrypted.sqlite");
    let key = SecretBox::init_with(|| [0xAB; 32]);

    {
        let conn = cipher::open_encrypted(&path, &key, false)?;
        let cipher =
            conn.query_row("PRAGMA cipher", &[], |row| Ok(row.column_text(0)))?;
        if cipher != "chacha20" {
            return Err("WalletKit did not select its chacha20 cipher".into());
        }
        conn.execute_batch("CREATE TABLE probe (value TEXT); INSERT INTO probe VALUES ('synthetic-test-record');")?;
    }

    let original_bytes = std::fs::read(&path)?;
    if original_bytes.starts_with(b"SQLite format 3\0") {
        return Err("encrypted database has a plaintext SQLite header".into());
    }
    let wrong_key = SecretBox::init_with(|| [0xCD; 32]);
    if cipher::open_encrypted(&path, &wrong_key, false).is_ok() {
        return Err("encrypted database accepted the wrong key".into());
    }
    if std::fs::read(&path)? != original_bytes {
        return Err("failed wrong-key open modified the database".into());
    }
    {
        let conn = cipher::open_encrypted(&path, &key, false)?;
        let value = conn
            .query_row("SELECT value FROM probe", &[], |row| Ok(row.column_text(0)))?;
        if value != "synthetic-test-record" {
            return Err("correct-key reopen did not preserve the record".into());
        }
    }

    // Recover databases previously written as plaintext when host SQLite won
    // symbol resolution. The migration must retain the data and encrypt it
    // with WalletKit's supplied key.
    let plaintext_path = dir.path().join("plaintext.sqlite");
    {
        let conn = Connection::open(&plaintext_path, false)?;
        conn.execute_batch("PRAGMA journal_mode = WAL;")?;
        conn.execute_batch("CREATE TABLE existing (value TEXT); INSERT INTO existing VALUES ('preserve-me');")?;
    }
    if !std::fs::read(&plaintext_path)?.starts_with(b"SQLite format 3\0") {
        return Err("plaintext migration fixture was not plaintext".into());
    }
    {
        let conn = cipher::open_encrypted(&plaintext_path, &key, false)?;
        let value = conn.query_row("SELECT value FROM existing", &[], |row| {
            Ok(row.column_text(0))
        })?;
        if value != "preserve-me" {
            return Err("plaintext migration did not preserve the record".into());
        }
    }
    if std::fs::read(&plaintext_path)?.starts_with(b"SQLite format 3\0") {
        return Err("plaintext migration did not encrypt the database".into());
    }
    if cipher::open_encrypted(&plaintext_path, &wrong_key, false).is_ok() {
        return Err("migrated database accepted the wrong key".into());
    }
    println!(
        "PASS: engine isolation, encrypted reopen, plaintext migration, and wrong-key rejection"
    );
    Ok(())
}
