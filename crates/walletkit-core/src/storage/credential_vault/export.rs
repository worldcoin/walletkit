//! Snapshot export of credentials and the blobs their links name.

use std::path::Path;

use walletkit_sqlite::params;

use super::{map_db_err, CredentialVault};
use crate::storage::{BlobId, StorageError, StorageResult};

impl CredentialVault {
    pub(crate) fn export_selected_plaintext(
        &self,
        dest: &Path,
        credential_ids: Option<&[u64]>,
    ) -> StorageResult<Vec<BlobId>> {
        if credential_ids.is_some_and(<[u64]>::is_empty) {
            return Err(StorageError::InvalidInput(
                "credential selection must not be empty".to_owned(),
            ));
        }
        if dest.exists() {
            std::fs::remove_file(dest).map_err(|e| {
                StorageError::VaultDb(format!("failed to remove stale backup: {e}"))
            })?;
        }
        let conn = self.vault.connection();
        conn.execute(
            "ATTACH DATABASE ?1 AS backup KEY ''",
            params![dest.to_string_lossy().as_ref()],
        )
        .map_err(|e| map_db_err(&e))?;
        let result = (|| {
            let tx = conn.transaction().map_err(|e| map_db_err(&e))?;
            tx.execute_batch(
                "CREATE TABLE backup.credential_records AS
                 SELECT * FROM main.credential_records WHERE 0",
            )
            .map_err(|e| map_db_err(&e))?;
            if let Some(ids) = credential_ids {
                let mut ids = ids.to_vec();
                ids.sort_unstable();
                ids.dedup();
                let mut unknown = Vec::new();
                for id in ids {
                    let inserted = if let Ok(id) = i64::try_from(id) {
                        tx.execute(
                            "INSERT INTO backup.credential_records
                             SELECT * FROM main.credential_records WHERE credential_id = ?1",
                            params![id],
                        )
                        .map_err(|e| map_db_err(&e))?
                    } else {
                        0
                    };
                    if inserted == 0 {
                        unknown.push(id);
                    }
                }
                if !unknown.is_empty() {
                    return Err(StorageError::InvalidInput(format!(
                        "unknown credential ids: {unknown:?}"
                    )));
                }
            } else {
                tx.execute_batch(
                    "INSERT INTO backup.credential_records SELECT * FROM main.credential_records",
                )
                .map_err(|e| map_db_err(&e))?;
            }
            tx.execute_batch(
                "CREATE TABLE backup.blob_objects AS SELECT * FROM main.blob_objects
                 WHERE content_id IN (
                     SELECT credential_blob_cid FROM backup.credential_records
                     UNION SELECT associated_data_cid FROM backup.credential_records);
                 CREATE TABLE backup.credential_blob_refs AS SELECT * FROM main.credential_blob_refs
                 WHERE credential_id IN (SELECT credential_id FROM backup.credential_records);
                 CREATE TABLE backup.blobs AS
                 SELECT blob_id, kind, data, created_at, updated_at FROM main.blobs
                 WHERE blob_id IN (SELECT blob_id FROM backup.credential_blob_refs)
                 ORDER BY blob_id;",
            )
            .map_err(|e| map_db_err(&e))?;
            let mut missing = Vec::new();
            {
                let mut refs = tx.prepare(
                    "SELECT DISTINCT blob_id FROM backup.credential_blob_refs r
                     WHERE NOT EXISTS (SELECT 1 FROM main.blobs b WHERE b.blob_id = r.blob_id)
                     ORDER BY blob_id",
                ).map_err(|e| map_db_err(&e))?;
                while let walletkit_sqlite::StepResult::Row(row) =
                    refs.step().map_err(|e| map_db_err(&e))?
                {
                    missing.push(BlobId::from_bytes(row.column_blob(0))?);
                }
            }
            tx.commit().map_err(|e| map_db_err(&e))?;
            Ok(missing)
        })();
        let detach = conn
            .execute_batch("DETACH DATABASE backup")
            .map_err(|e| map_db_err(&e));
        match (result, detach) {
            (Err(err), Err(detach)) => Err(StorageError::VaultDb(format!(
                "{err}; failed to detach export: {detach}"
            ))),
            (Err(err), _) | (_, Err(err)) => Err(err),
            (Ok(missing), Ok(())) => Ok(missing),
        }
    }
}
