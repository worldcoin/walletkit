use crate::storage::error::{StorageError, StorageResult};
use crate::storage::types::{
    ActivityEntry, ActivityFailureReason, ActivityMetadata, ActivityOutcome,
    ActivityQuery, ProtocolVersion,
};
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

    let failure_reason_value = entry.failure_reason.map_or(Value::Null, |reason| {
        Value::Integer(failure_reason_to_i64(reason))
    });

    let entry_id = conn
        .query_row(
            "INSERT INTO activity_entries (
                client_id, protocol, created_at,
                outcome, app_identifier, issuer_schema_ids, failure_reason
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            RETURNING entry_id",
            params![
                entry.client_id.as_str(),
                entry.protocol.as_i64(),
                now_i64,
                entry.outcome.to_string(),
                entry.rp_id.to_string(),
                encode_issuer_schema_ids(&entry.issuer_schema_ids),
                failure_reason_value,
            ],
            |stmt| Ok(stmt.column_i64(0)),
        )
        .map_err(|err| map_db_err(&err))?;

    to_u64(entry_id, "entry_id")
}

/// Lists activity entries, most recent first.
pub(super) fn list(
    conn: &Connection,
    query: ActivityQuery,
    limit: u32,
    offset: u32,
) -> StorageResult<Vec<ActivityEntry>> {
    let _ = query;
    let limit_i64 = i64::from(limit);
    let offset_i64 = i64::from(offset);

    let sql = "SELECT entry_id, client_id, protocol, created_at, outcome,
                       app_identifier, issuer_schema_ids, failure_reason
                FROM activity_entries
                ORDER BY created_at DESC, entry_id DESC
                LIMIT ?1 OFFSET ?2";

    let mut entries = Vec::new();

    let mut stmt = conn.prepare(sql).map_err(|err| map_db_err(&err))?;

    stmt.bind_values(params![limit_i64, offset_i64])
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

fn encode_issuer_schema_ids(issuer_schema_ids: &[u64]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(issuer_schema_ids.len() * 8);
    for id in issuer_schema_ids {
        bytes.extend_from_slice(&id.to_be_bytes());
    }
    bytes
}

fn decode_issuer_schema_ids(bytes: &[u8]) -> StorageResult<Vec<u64>> {
    if !bytes.len().is_multiple_of(8) {
        return Err(StorageError::ActivityDb(format!(
            "invalid issuer_schema_ids blob length: {}",
            bytes.len()
        )));
    }

    Ok(bytes
        .chunks_exact(8)
        .map(|chunk| {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(chunk);
            u64::from_be_bytes(buf)
        })
        .collect())
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
    let rp_id = parse_rp_id(&row.column_text(5))?;
    let issuer_schema_ids = decode_issuer_schema_ids(&row.column_blob(6))?;
    let failure_reason = if row.is_column_null(7) {
        None
    } else {
        Some(i64_to_failure_reason(row.column_i64(7))?)
    };

    Ok(ActivityEntry {
        id: Some(id),
        client_id,
        protocol,
        timestamp: Some(timestamp),
        outcome,
        rp_id,
        issuer_schema_ids,
        failure_reason,
    })
}

fn parse_rp_id(text: &str) -> StorageResult<u64> {
    text.parse().map_err(|_| {
        StorageError::ActivityDb(format!("invalid app_identifier: {text}"))
    })
}

const fn failure_reason_to_i64(reason: ActivityFailureReason) -> i64 {
    match reason {
        ActivityFailureReason::NetworkError => 1,
        ActivityFailureReason::Timeout => 2,
        ActivityFailureReason::DeviceAuthenticationFailed => 3,
        ActivityFailureReason::ProofGenerationFailed => 4,
        ActivityFailureReason::RelyingPartyRejected => 5,
    }
}

fn i64_to_failure_reason(value: i64) -> StorageResult<ActivityFailureReason> {
    match value {
        1 => Ok(ActivityFailureReason::NetworkError),
        2 => Ok(ActivityFailureReason::Timeout),
        3 => Ok(ActivityFailureReason::DeviceAuthenticationFailed),
        4 => Ok(ActivityFailureReason::ProofGenerationFailed),
        5 => Ok(ActivityFailureReason::RelyingPartyRejected),
        other => Err(StorageError::ActivityDb(format!(
            "invalid failure reason: {other}"
        ))),
    }
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
