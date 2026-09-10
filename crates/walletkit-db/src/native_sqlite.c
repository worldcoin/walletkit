/*
 * Keep SQLite's C API local to this translation unit. Visibility attributes alone
 * do not prevent a static-library consumer from resolving sqlite3_* against a
 * different SQLite implementation. Only the WalletKit-prefixed wrappers below
 * cross the Rust FFI boundary; every handle stays with its creating engine.
 *
 * Compile the unchanged, checksum-verified amalgamation with the existing
 * cipher/settings. This changes linkage only, not encryption or disk formats.
 */
#define SQLITE_API static
#define SQLITE_EXTERN
#include "sqlite3mc_amalgamation.c"

int walletkit_sqlite3_open_v2(const char *filename, sqlite3 **db, int flags, const char *vfs) {
    return sqlite3_open_v2(filename, db, flags, vfs);
}

int walletkit_sqlite3_close_v2(sqlite3 *db) {
    return sqlite3_close_v2(db);
}

int walletkit_sqlite3_exec(sqlite3 *db, const char *sql, int (*callback)(void *, int, char **, char **), void *arg, char **error) {
    return sqlite3_exec(db, sql, callback, arg, error);
}

void walletkit_sqlite3_free(void *pointer) {
    sqlite3_free(pointer);
}

int walletkit_sqlite3_prepare_v2(sqlite3 *db, const char *sql, int length, sqlite3_stmt **statement, const char **tail) {
    return sqlite3_prepare_v2(db, sql, length, statement, tail);
}

int walletkit_sqlite3_step(sqlite3_stmt *statement) {
    return sqlite3_step(statement);
}

int walletkit_sqlite3_reset(sqlite3_stmt *statement) {
    return sqlite3_reset(statement);
}

int walletkit_sqlite3_finalize(sqlite3_stmt *statement) {
    return sqlite3_finalize(statement);
}

int walletkit_sqlite3_bind_int64(sqlite3_stmt *statement, int index, sqlite3_int64 value) {
    return sqlite3_bind_int64(statement, index, value);
}

int walletkit_sqlite3_bind_blob(sqlite3_stmt *statement, int index, const void *value, int length, sqlite3_destructor_type destructor) {
    return sqlite3_bind_blob(statement, index, value, length, destructor);
}

int walletkit_sqlite3_bind_text(sqlite3_stmt *statement, int index, const char *value, int length, sqlite3_destructor_type destructor) {
    return sqlite3_bind_text(statement, index, value, length, destructor);
}

int walletkit_sqlite3_bind_null(sqlite3_stmt *statement, int index) {
    return sqlite3_bind_null(statement, index);
}

sqlite3_int64 walletkit_sqlite3_column_int64(sqlite3_stmt *statement, int column) {
    return sqlite3_column_int64(statement, column);
}

const void * walletkit_sqlite3_column_blob(sqlite3_stmt *statement, int column) {
    return sqlite3_column_blob(statement, column);
}

int walletkit_sqlite3_column_bytes(sqlite3_stmt *statement, int column) {
    return sqlite3_column_bytes(statement, column);
}

const unsigned char * walletkit_sqlite3_column_text(sqlite3_stmt *statement, int column) {
    return sqlite3_column_text(statement, column);
}

int walletkit_sqlite3_column_type(sqlite3_stmt *statement, int column) {
    return sqlite3_column_type(statement, column);
}

int walletkit_sqlite3_column_count(sqlite3_stmt *statement) {
    return sqlite3_column_count(statement);
}

const char * walletkit_sqlite3_errmsg(sqlite3 *db) {
    return sqlite3_errmsg(db);
}

int walletkit_sqlite3_changes(sqlite3 *db) {
    return sqlite3_changes(db);
}

sqlite3_int64 walletkit_sqlite3_last_insert_rowid(sqlite3 *db) {
    return sqlite3_last_insert_rowid(db);
}

