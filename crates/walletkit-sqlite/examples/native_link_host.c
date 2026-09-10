#include <sqlite3.h>
#include <stdio.h>

extern int walletkit_native_link_probe(void);

int main(void) {
    sqlite3 *db = NULL;
    sqlite3_stmt *statement = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
        fprintf(stderr, "Host SQLite open failed\n");
        sqlite3_close(db);
        return 1;
    }
    if (sqlite3_prepare_v2(db, "PRAGMA cipher", -1, &statement, NULL) != SQLITE_OK ||
        sqlite3_step(statement) != SQLITE_DONE) {
        fprintf(stderr, "WalletKit replaced the host's SQLite engine\n");
        sqlite3_finalize(statement);
        sqlite3_close(db);
        return 1;
    }
    sqlite3_finalize(statement);
    printf("Host SQLite: %s; cipher unavailable as expected\n", sqlite3_libversion());
    int result = walletkit_native_link_probe();
    if (sqlite3_exec(db, "CREATE TABLE host (id INTEGER); INSERT INTO host VALUES (1);",
                     NULL, NULL, NULL) != SQLITE_OK || sqlite3_changes(db) != 1) {
        fprintf(stderr, "Host SQLite failed after WalletKit used its own engine\n");
        result = 1;
    }
    if (sqlite3_close(db) != SQLITE_OK) {
        fprintf(stderr, "Host SQLite close failed\n");
        result = 1;
    }
    return result;
}
