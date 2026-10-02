use crate::storage::error::{StorageError, StorageResult};
use crate::storage::types::{
    ActivityEntry, ActivityMetadata, ActivityOutcome, ActivityQuery, ProtocolVersion,
};
use crate::storage::ActivityFailureReason;
use walletkit_sqlite::{params, Connection, Row, StepResult, Value};

use super::util::{map_db_err, to_i64, to_u64};

pub(super) fn record(
    conn: &Connection,
    entry: &ActivityEntry,
    now: u64,
) -> StorageResult<u64> {
    match (entry.outcome, entry.failure_reason) {
        (ActivityOutcome::Failed, None) => {
            return Err(StorageError::ActivityInvalidRecord(
                "failure_reason must be present when outcome is Failed".to_string(),
            ));
        }
        (outcome, Some(_)) if outcome != ActivityOutcome::Failed => {
            return Err(StorageError::ActivityInvalidRecord(
                "failure_reason must be absent unless outcome is Failed".to_string(),
            ));
        }
        _ => {}
    }

    let now_i64 = to_i64(now, "now")?;
    let tx = conn
        .transaction_immediate()
        .map_err(|err| map_db_err(&err))?;

    let entry_id = tx
        .query_row(
            "INSERT INTO activity_entries (
                client_id, protocol, created_at,
                outcome, rp_id, app_identifier, failure_reason
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            RETURNING entry_id",
            params![
                entry.client_id.as_str(),
                entry.protocol.as_i64(),
                now_i64,
                entry.outcome.to_string(),
                entry.rp_id.cast_signed(),
                entry.app_identifier.as_str(),
                entry
                    .failure_reason
                    .map(|v| v.to_string())
                    .unwrap_or_default(),
            ],
            |stmt| Ok(stmt.column_i64(0)),
        )
        .map_err(|err| map_db_err(&err))?;

    for issuer_schema_id in &entry.issuer_schema_ids {
        tx.execute(
            "INSERT OR IGNORE INTO activity_issuer_schema_ids (entry_id, issuer_schema_id)
             VALUES (?1, ?2)",
            params![
                entry_id,
                to_i64(*issuer_schema_id, "issuer_schema_id")?,
            ],
        )
        .map_err(|err| map_db_err(&err))?;
    }

    tx.commit().map_err(|err| map_db_err(&err))?;

    to_u64(entry_id, "entry_id")
}

/// Lists activity entries, most recent first.
///
/// When [`ActivityQuery::issuer_schema_id`] is set, only entries that include
/// that issuer schema id are returned.
pub(super) fn list(
    conn: &Connection,
    query: ActivityQuery,
    limit: u32,
    offset: u32,
) -> StorageResult<Vec<ActivityEntry>> {
    let limit_i64 = i64::from(limit);
    let offset_i64 = i64::from(offset);
    let issuer_schema_id = query
        .issuer_schema_id
        .map(|value| to_i64(value, "issuer_schema_id"))
        .transpose()?;

    let sql = "SELECT e.entry_id, e.client_id, e.protocol, e.created_at, e.outcome,
                      e.rp_id, e.app_identifier, e.failure_reason,
                      (SELECT GROUP_CONCAT(s.issuer_schema_id)
                       FROM activity_issuer_schema_ids s
                       WHERE s.entry_id = e.entry_id)
                FROM activity_entries e
                WHERE ?1 IS NULL OR EXISTS (
                    SELECT 1 FROM activity_issuer_schema_ids f
                    WHERE f.entry_id = e.entry_id AND f.issuer_schema_id = ?1
                )
                ORDER BY e.created_at DESC, e.entry_id DESC
                LIMIT ?2 OFFSET ?3";

    let mut entries = Vec::new();

    let mut stmt = conn.prepare(sql).map_err(|err| map_db_err(&err))?;

    stmt.bind_values(params![
        issuer_schema_id.map_or(Value::Null, Value::Integer),
        limit_i64,
        offset_i64,
    ])
    .map_err(|err| map_db_err(&err))?;

    while let StepResult::Row(row) = stmt.step().map_err(|err| map_db_err(&err))? {
        entries.push(map_entry(&row)?);
    }

    Ok(entries)
}

/// Returns aggregate activity metadata.
pub(super) fn metadata(conn: &Connection) -> StorageResult<ActivityMetadata> {
    let total_count = conn
        .query_row("SELECT COUNT(*) FROM activity_entries", &[], |stmt| {
            Ok(stmt.column_i64(0))
        })
        .map_err(|err| map_db_err(&err))?;

    Ok(ActivityMetadata {
        total_count: to_u64(total_count, "total_count")?,
    })
}

pub(super) fn clear(conn: &Connection) -> StorageResult<u64> {
    let deleted = conn
        .execute("DELETE FROM activity_entries", &[])
        .map_err(|err| map_db_err(&err))?;

    Ok(deleted as u64)
}

fn decode_issuer_schema_ids(joined: &str) -> StorageResult<Vec<u64>> {
    if joined.is_empty() {
        return Ok(Vec::new());
    }

    let mut ids = joined
        .split(',')
        .map(|value| {
            value.parse::<i64>().map(i64::cast_unsigned).map_err(|_| {
                StorageError::ActivityDb(format!("invalid issuer_schema_id: {value}"))
            })
        })
        .collect::<StorageResult<Vec<_>>>()?;

    ids.sort_unstable();
    Ok(ids)
}

fn map_entry(row: &Row<'_, '_>) -> StorageResult<ActivityEntry> {
    let id = to_u64(row.column_i64(0), "entry_id")?;
    let client_id = row.column_text(1);
    let protocol = ProtocolVersion::try_from(row.column_i64(2))?;
    let timestamp = to_u64(row.column_i64(3), "created_at")?;
    let outcome_text = row.column_text(4);
    let outcome: ActivityOutcome = outcome_text.parse().map_err(|_| {
        StorageError::ActivityDb(format!("invalid outcome: {outcome_text}"))
    })?;
    let rp_id = row.column_i64(5).cast_unsigned();
    let app_identifier = row.column_text(6);
    let failure_reason_text = row.column_text(7);
    let issuer_schema_ids = decode_issuer_schema_ids(&row.column_text(8))?;

    let failure_reason = if failure_reason_text.is_empty() {
        None
    } else {
        Some(
            failure_reason_text
                .parse::<ActivityFailureReason>()
                .map_err(|_| {
                    StorageError::ActivityDb("invalid failure_reason in db".to_string())
                })?,
        )
    };

    Ok(ActivityEntry {
        id: Some(id),
        client_id,
        protocol,
        timestamp: Some(timestamp),
        outcome,
        rp_id,
        app_identifier,
        issuer_schema_ids,
        failure_reason,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::cache::CacheDb;
    use secrecy::SecretBox;
    use std::fs;
    use std::path::{Path, PathBuf};
    use uuid::Uuid;

    fn temp_cache_path() -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "walletkit-cache-activity-{}.sqlite",
            Uuid::new_v4()
        ));
        path
    }

    fn cleanup_cache_files(path: &Path) {
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite-shm"));
    }

    fn sample_entry() -> ActivityEntry {
        ActivityEntry {
            id: None,
            rp_id: 1,
            app_identifier: "app_test".to_string(),
            client_id: "request-uuid-1".to_string(),
            protocol: ProtocolVersion::V3,
            timestamp: None,
            issuer_schema_ids: vec![10],
            outcome: ActivityOutcome::Completed,
            failure_reason: None,
        }
    }

    #[test]
    fn test_record_and_list_activity() {
        let path = temp_cache_path();
        let key = SecretBox::init_with(|| [0x42u8; 32]);
        let db = CacheDb::new(&path, &key).expect("create cache");

        let entry_id = db
            .record_activity(&sample_entry(), 1000)
            .expect("record activity");

        let entries = db
            .list_activities(ActivityQuery::default(), 10, 0)
            .expect("list activities");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, Some(entry_id));
        assert_eq!(entries[0].outcome, ActivityOutcome::Completed);
        assert_eq!(entries[0].issuer_schema_ids.len(), 1);

        cleanup_cache_files(&path);
    }

    #[test]
    fn test_clear_activities_removes_issuer_schema_associations() {
        let path = temp_cache_path();
        let key = SecretBox::init_with(|| [0x08u8; 32]);
        let db = CacheDb::new(&path, &key).expect("create cache");

        db.record_activity(&sample_entry(), 1000)
            .expect("record activity");
        db.clear_activities().expect("clear activities");

        let entries = db
            .list_activities(
                ActivityQuery {
                    issuer_schema_id: Some(10),
                },
                10,
                0,
            )
            .expect("list filtered");
        assert!(
            entries.is_empty(),
            "clearing activity must remove issuer-schema associations"
        );

        cleanup_cache_files(&path);
    }

    #[test]
    fn test_list_activities_filters_by_issuer_schema_id() {
        let path = temp_cache_path();
        let key = SecretBox::init_with(|| [0x04u8; 32]);
        let db = CacheDb::new(&path, &key).expect("create cache");

        let with_schemas = |ids: Vec<u64>| ActivityEntry {
            issuer_schema_ids: ids,
            ..sample_entry()
        };

        db.record_activity(&with_schemas(vec![10]), 1000)
            .expect("record");
        db.record_activity(&with_schemas(vec![20]), 1001)
            .expect("record");
        db.record_activity(&with_schemas(vec![10, 20]), 1002)
            .expect("record");
        db.record_activity(&with_schemas(vec![]), 1003)
            .expect("record");

        let filtered = |issuer_schema_id| {
            db.list_activities(ActivityQuery { issuer_schema_id }, 10, 0)
                .expect("list filtered")
        };

        let schema_10 = filtered(Some(10));
        assert_eq!(schema_10.len(), 2);
        assert!(schema_10.iter().all(|e| e.issuer_schema_ids.contains(&10)));

        assert_eq!(filtered(Some(20)).len(), 2);
        assert!(filtered(Some(30)).is_empty());

        let all = db
            .list_activities(ActivityQuery::default(), 10, 0)
            .expect("list all");
        assert_eq!(all.len(), 4, "an unset filter returns every entry");

        cleanup_cache_files(&path);
    }

    #[test]
    fn test_record_activity_failed_requires_failure_reason() {
        let path = temp_cache_path();
        let key = SecretBox::init_with(|| [0x02u8; 32]);
        let db = CacheDb::new(&path, &key).expect("create cache");

        let entry = ActivityEntry {
            outcome: ActivityOutcome::Failed,
            failure_reason: None,
            ..sample_entry()
        };

        let err = db
            .record_activity(&entry, 1000)
            .expect_err("Failed without failure_reason should be rejected");

        assert!(matches!(err, StorageError::ActivityInvalidRecord(_)));

        cleanup_cache_files(&path);
    }

    #[test]
    fn test_record_activity_rejects_failure_reason_without_failed_outcome() {
        let path = temp_cache_path();
        let key = SecretBox::init_with(|| [0x03u8; 32]);
        let db = CacheDb::new(&path, &key).expect("create cache");

        let entry = ActivityEntry {
            outcome: ActivityOutcome::Completed,
            failure_reason: Some(ActivityFailureReason::NetworkError),
            ..sample_entry()
        };

        let err = db
            .record_activity(&entry, 1000)
            .expect_err("failure_reason without Failed outcome should be rejected");

        assert!(matches!(err, StorageError::ActivityInvalidRecord(_)));

        cleanup_cache_files(&path);
    }

    #[test]
    fn test_list_activities_paginates_with_offset() {
        let path = temp_cache_path();
        let key = SecretBox::init_with(|| [0x05u8; 32]);
        let db = CacheDb::new(&path, &key).expect("create cache");

        for i in 0..5u64 {
            db.record_activity(&sample_entry(), 1000 + i)
                .expect("record activity");
        }

        let page1 = db
            .list_activities(ActivityQuery::default(), 2, 0)
            .expect("list page 1");
        let page2 = db
            .list_activities(ActivityQuery::default(), 2, 2)
            .expect("list page 2");
        let page3 = db
            .list_activities(ActivityQuery::default(), 2, 4)
            .expect("list page 3");

        assert_eq!(page1.len(), 2);
        assert_eq!(page2.len(), 2);
        assert_eq!(page3.len(), 1);

        assert_eq!(page1[0].timestamp, Some(1004));
        assert_eq!(page1[1].timestamp, Some(1003));
        assert_eq!(page2[0].timestamp, Some(1002));
        assert_eq!(page3[0].timestamp, Some(1000));

        cleanup_cache_files(&path);
    }

    #[test]
    fn test_activity_metadata_total_count() {
        let path = temp_cache_path();
        let key = SecretBox::init_with(|| [0x06u8; 32]);
        let db = CacheDb::new(&path, &key).expect("create cache");

        assert_eq!(db.activity_metadata().expect("metadata").total_count, 0);

        db.record_activity(&sample_entry(), 1000)
            .expect("record activity");
        db.record_activity(&sample_entry(), 1001)
            .expect("record activity");

        assert_eq!(db.activity_metadata().expect("metadata").total_count, 2);

        cleanup_cache_files(&path);
    }

    #[test]
    fn test_activity_survives_cache_reopen() {
        let path = temp_cache_path();
        let key = SecretBox::init_with(|| [0x07u8; 32]);
        let db = CacheDb::new(&path, &key).expect("create cache");
        db.record_activity(&sample_entry(), 1000)
            .expect("record activity");
        drop(db);

        let db = CacheDb::new(&path, &key).expect("reopen cache");
        let entries = db
            .list_activities(ActivityQuery::default(), 10, 0)
            .expect("list after reopen");
        assert_eq!(
            entries.len(),
            1,
            "activity history must survive a cache reopen"
        );

        cleanup_cache_files(&path);
    }
}
