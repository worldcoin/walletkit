//! Encrypted credential-activity database.
//!
//! A device-local, chronological log of proof-share request outcomes. Wraps
//! [`walletkit_db::Vault`], reusing the same shared `K_intermediate` as the
//! credential vault and cache (see `crate::storage` module docs).

use std::collections::HashMap;
use std::path::Path;

use crate::storage::error::{StorageError, StorageResult};
use crate::storage::types::{
    CredentialActivityCredential, CredentialActivityCredentialSource,
    CredentialActivityCredentialType, CredentialActivityEntry,
    CredentialActivityFailureReason, CredentialActivityFinalization,
    CredentialActivityMetadata, CredentialActivityOutcome, CredentialActivityProofKind,
    CredentialActivityProtocol, CredentialActivityQuery, NewCredentialActivityEntry,
};
use secrecy::SecretBox;
use walletkit_db::{params, DbError, Row, StepResult, Transaction, Value, Vault};

/// Encrypted credential-activity database wrapper around [`walletkit_db::Vault`].
#[derive(Debug)]
pub struct CredentialActivity {
    vault: Vault,
}

impl CredentialActivity {
    /// Opens or rebuilds the encrypted credential-activity database at
    /// `path`, applying any pending migrations.
    ///
    /// Returns the wrapper plus `Some((from_version, to_version))` if one or
    /// more migrations actually ran (`None` on a fresh or already-current
    /// database).
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be opened, keyed, migrated, or
    /// rebuilt.
    pub fn new(
        path: &Path,
        k_intermediate: &SecretBox<[u8; 32]>,
    ) -> StorageResult<(Self, Option<(u32, u32)>)> {
        let (vault, (from, to)) =
            super::maintenance::open_or_rebuild(path, k_intermediate)?;

        let migrated = if from == to {
            None
        } else {
            Some((
                to_u32(from, "schema_version_from")?,
                to_u32(to, "schema_version_to")?,
            ))
        };

        Ok((Self { vault }, migrated))
    }

    /// Records the start of a proof-share request (approval screen shown).
    ///
    /// Returns the new entry's ID, to be passed to
    /// [`finalize_activity`](Self::finalize_activity) once the request
    /// reaches a terminal outcome.
    ///
    /// # Errors
    ///
    /// Returns an error if the insert fails.
    pub fn record_activity_started(
        &self,
        entry: &NewCredentialActivityEntry,
        now: u64,
    ) -> StorageResult<u64> {
        let now_i64 = to_i64(now, "now")?;
        let conn = self.vault.connection();
        let tx = conn.transaction().map_err(|err| map_db_err(&err))?;

        let request_id_value = entry
            .request_id
            .as_deref()
            .map_or(Value::Null, |v| Value::Text(v.to_string()));

        let entry_id = tx
            .query_row(
                "INSERT INTO activity_entries (
                    client_id, request_id, protocol, created_at, updated_at, app_identifier
                ) VALUES (?1, ?2, ?3, ?4, ?4, ?5)
                RETURNING entry_id",
                params![
                    entry.client_id.as_str(),
                    request_id_value,
                    protocol_to_text(entry.protocol),
                    now_i64,
                    entry.app_identifier.as_str(),
                ],
                |stmt| Ok(stmt.column_i64(0)),
            )
            .map_err(|err| map_db_err(&err))?;

        insert_credentials(&tx, entry_id, &entry.credentials)?;

        tx.commit().map_err(|err| map_db_err(&err))?;

        to_u64(entry_id, "entry_id")
    }

    /// Finalizes a previously started proof-share request, identified by the
    /// most recent entry matching `finalization.client_id`.
    ///
    /// On [`CredentialActivityOutcome::Shared`], replaces whatever
    /// credentials were recorded at start with the final set in
    /// `finalization.credentials`. On any other outcome, the
    /// originally-recorded credentials are left untouched — preserving the
    /// audit record of what was requested even when nothing was ultimately
    /// shared. Calling this again for the same `client_id` (e.g. a retried
    /// finalize action) re-targets the same entry and simply overwrites it,
    /// matching the prior entry_id-keyed behavior — it does not require the
    /// entry to still be pending.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::CredentialActivityEntryNotFound`] if no entry
    /// matches `client_id`,
    /// [`StorageError::CredentialActivityInvalidFinalization`] if
    /// `failure_reason` is present without `outcome` being
    /// [`CredentialActivityOutcome::Failed`] (or vice versa), or another
    /// error if the update fails.
    pub fn finalize_activity(
        &self,
        finalization: &CredentialActivityFinalization,
        now: u64,
    ) -> StorageResult<()> {
        match (finalization.outcome, finalization.failure_reason) {
            (CredentialActivityOutcome::Failed, None) => {
                return Err(StorageError::CredentialActivityInvalidFinalization(
                    "failure_reason must be present when outcome is Failed".to_string(),
                ));
            }
            (outcome, Some(_)) if outcome != CredentialActivityOutcome::Failed => {
                return Err(StorageError::CredentialActivityInvalidFinalization(
                    "failure_reason must be absent unless outcome is Failed"
                        .to_string(),
                ));
            }
            _ => {}
        }

        let now_i64 = to_i64(now, "now")?;
        let conn = self.vault.connection();
        let tx = conn.transaction().map_err(|err| map_db_err(&err))?;

        // Resolves client_id to the numeric primary key up front, inside the
        // same transaction as the update below, so the two never disagree.
        // `client_id` is generated fresh per request, so this should always
        // resolve to exactly one entry; ORDER BY + LIMIT is a defensive
        // tie-breaker, not a real disambiguation need.
        let entry_id_i64 = tx
            .query_row_optional(
                "SELECT entry_id FROM activity_entries
                 WHERE client_id = ?1
                 ORDER BY entry_id DESC LIMIT 1",
                params![finalization.client_id.as_str()],
                |row| Ok(row.column_i64(0)),
            )
            .map_err(|err| map_db_err(&err))?
            .ok_or_else(|| StorageError::CredentialActivityEntryNotFound {
                client_id: finalization.client_id.clone(),
            })?;

        let failure_reason_value =
            finalization.failure_reason.map_or(Value::Null, |reason| {
                Value::Integer(failure_reason_to_i64(reason))
            });

        tx.execute(
            "UPDATE activity_entries
             SET outcome = ?1, failure_reason = ?2, protocol = ?3, updated_at = ?4
             WHERE entry_id = ?5",
            params![
                outcome_to_text(finalization.outcome),
                failure_reason_value,
                protocol_to_text(finalization.protocol),
                now_i64,
                entry_id_i64,
            ],
        )
        .map_err(|err| map_db_err(&err))?;

        if finalization.outcome == CredentialActivityOutcome::Shared {
            tx.execute(
                "DELETE FROM activity_credentials WHERE entry_id = ?1",
                params![entry_id_i64],
            )
            .map_err(|err| map_db_err(&err))?;

            insert_credentials(&tx, entry_id_i64, &finalization.credentials)?;
        }
        tx.commit().map_err(|err| map_db_err(&err))?;

        Ok(())
    }

    /// Lists activity entries, most recent first.
    ///
    /// `query` is currently unused — [`CredentialActivityQuery`] is a
    /// placeholder for filtering/sorting options that aren't needed yet.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn list_activities(
        &self,
        query: Option<&CredentialActivityQuery>,
        limit: u32,
        offset: u32,
    ) -> StorageResult<Vec<CredentialActivityEntry>> {
        let _ = query;
        let limit_i64 = to_i64(u64::from(limit), "limit")?;
        let offset_i64 = to_i64(u64::from(offset), "offset")?;

        // Both queries below run inside one transaction so a concurrent
        // finalize from another handle on this file can't be interleaved
        // between them and produce an entry paired with the wrong
        // credential set.
        let conn = self.vault.connection();
        let tx = conn.transaction().map_err(|err| map_db_err(&err))?;

        let sql = "SELECT entry_id, client_id, request_id, protocol, created_at,
                           updated_at, outcome, app_identifier, failure_reason
                    FROM activity_entries
                    ORDER BY created_at DESC, entry_id DESC
                    LIMIT ?1 OFFSET ?2";

        let mut entries = Vec::new();

        // Block ensures correct borrowing of tx
        {
            let mut stmt = tx.prepare(sql).map_err(|err| map_db_err(&err))?;

            stmt.bind_values(params![limit_i64, offset_i64])
                .map_err(|err| map_db_err(&err))?;

            while let StepResult::Row(row) =
                stmt.step().map_err(|err| map_db_err(&err))?
            {
                entries.push(map_entry(&row)?);
            }
        }

        let entry_ids: Vec<u64> = entries.iter().map(|entry| entry.entry_id).collect();
        let mut credentials_by_entry = fetch_credentials_by_entry(&tx, &entry_ids)?;
        for entry in &mut entries {
            entry.credentials = credentials_by_entry
                .remove(&entry.entry_id)
                .unwrap_or_default();
        }

        tx.commit().map_err(|err| map_db_err(&err))?;

        Ok(entries)
    }

    /// Returns aggregate activity metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn activity_metadata(&self) -> StorageResult<CredentialActivityMetadata> {
        let total_count = self
            .vault
            .connection()
            .query_row("SELECT COUNT(*) FROM activity_entries", &[], |stmt| {
                Ok(stmt.column_i64(0))
            })
            .map_err(|err| map_db_err(&err))?;

        Ok(CredentialActivityMetadata {
            total_count: to_u64(total_count, "total_count")?,
        })
    }

    /// Marks any entry left `outcome IS NULL` as
    /// [`CredentialActivityOutcome::Incomplete`], except `client_id`s in
    /// `exclude_client_ids`. Called by
    /// [`CredentialActivityStore::reconcile_incomplete`](super::CredentialActivityStore::reconcile_incomplete).
    ///
    /// # Errors
    ///
    /// Returns an error if the update fails.
    pub fn reconcile_incomplete(
        &self,
        now: u64,
        exclude_client_ids: &[String],
    ) -> StorageResult<()> {
        let now_i64 = to_i64(now, "now")?;

        if exclude_client_ids.is_empty() {
            self.vault
                .connection()
                .execute(
                    "UPDATE activity_entries
                     SET outcome = ?1, updated_at = ?2
                     WHERE outcome IS NULL",
                    params![
                        outcome_to_text(CredentialActivityOutcome::Incomplete),
                        now_i64,
                    ],
                )
                .map_err(|err| map_db_err(&err))?;

            return Ok(());
        }

        // `walletkit_db::Value` has no array/list variant, so a variable-length `NOT IN`
        // clause has to be built with one placeholder per excluded id rather than bound
        // as a single value.
        let placeholders = (0..exclude_client_ids.len())
            .map(|i| format!("?{}", i + 3))
            .collect::<Vec<_>>()
            .join(", ");

        let sql = format!(
            "UPDATE activity_entries
             SET outcome = ?1, updated_at = ?2
             WHERE outcome IS NULL AND client_id NOT IN ({placeholders})"
        );

        let mut bind_values = vec![
            Value::Text(
                outcome_to_text(CredentialActivityOutcome::Incomplete).to_string(),
            ),
            Value::Integer(now_i64),
        ];

        bind_values.extend(exclude_client_ids.iter().cloned().map(Value::Text));

        self.vault
            .connection()
            .execute(&sql, &bind_values)
            .map_err(|err| map_db_err(&err))?;

        Ok(())
    }
}

/// Eager-loads credentials for a page of entries in one query (rather than one
/// query per entry), grouped by `entry_id`. An entry with no matching key simply
/// has no credentials.
///
/// Takes `tx` rather than a `&CredentialActivity` so callers (namely
/// [`CredentialActivity::list_activities`]) can run it inside the same
/// transaction as their entries query, for a consistent snapshot.
fn fetch_credentials_by_entry(
    tx: &Transaction<'_>,
    entry_ids: &[u64],
) -> StorageResult<HashMap<u64, Vec<CredentialActivityCredential>>> {
    let mut credentials_by_entry = HashMap::new();
    if entry_ids.is_empty() {
        return Ok(credentials_by_entry);
    }

    // `walletkit_db::Value` has no array/list variant, so a variable-length `IN`
    // clause has to be built with one placeholder per id rather than bound as a
    // single value.
    let placeholders = (0..entry_ids.len())
        .map(|i| format!("?{}", i + 1))
        .collect::<Vec<_>>()
        .join(", ");

    let sql = format!(
        "SELECT entry_id, credential_type, credential_source, proof_kind,
                issuer_schema_id, credential_id
         FROM activity_credentials
         WHERE entry_id IN ({placeholders})"
    );

    let bind_values = entry_ids
        .iter()
        .map(|id| to_i64(*id, "entry_id").map(Value::Integer))
        .collect::<StorageResult<Vec<_>>>()?;

    let mut stmt = tx.prepare(&sql).map_err(|err| map_db_err(&err))?;

    stmt.bind_values(&bind_values)
        .map_err(|err| map_db_err(&err))?;

    while let StepResult::Row(row) = stmt.step().map_err(|err| map_db_err(&err))? {
        let entry_id = to_u64(row.column_i64(0), "entry_id")?;
        let credential = map_credential(&row)?;
        credentials_by_entry
            .entry(entry_id)
            .or_insert_with(Vec::new)
            .push(credential);
    }

    Ok(credentials_by_entry)
}

fn insert_credentials(
    tx: &Transaction<'_>,
    entry_id: i64,
    credentials: &[CredentialActivityCredential],
) -> StorageResult<()> {
    for credential in credentials {
        let issuer_schema_id_value = match credential.issuer_schema_id {
            Some(v) => Value::Integer(to_i64(v, "issuer_schema_id")?),
            None => Value::Null,
        };

        let credential_id_value = match credential.credential_id {
            Some(v) => Value::Integer(to_i64(v, "credential_id")?),
            None => Value::Null,
        };

        tx.execute(
            "INSERT INTO activity_credentials (
                entry_id, credential_type, credential_source, proof_kind,
                issuer_schema_id, credential_id
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                entry_id,
                credential_type_to_i64(credential.credential_type),
                credential_source_to_i64(credential.credential_source),
                proof_kind_to_i64(credential.proof_kind),
                issuer_schema_id_value,
                credential_id_value,
            ],
        )
        .map_err(|err| map_db_err(&err))?;
    }

    Ok(())
}

fn map_entry(row: &Row<'_, '_>) -> StorageResult<CredentialActivityEntry> {
    let entry_id = to_u64(row.column_i64(0), "entry_id")?;
    let client_id = row.column_text(1);
    let request_id = opt_text(row, 2);
    let protocol = text_to_protocol(&row.column_text(3))?;
    let created_at = to_u64(row.column_i64(4), "created_at")?;
    let updated_at = to_u64(row.column_i64(5), "updated_at")?;
    let outcome = opt_text(row, 6).map(|t| text_to_outcome(&t)).transpose()?;
    let app_identifier = row.column_text(7);
    let failure_reason = if row.is_column_null(8) {
        None
    } else {
        Some(i64_to_failure_reason(row.column_i64(8))?)
    };

    Ok(CredentialActivityEntry {
        entry_id,
        client_id,
        request_id,
        protocol,
        created_at,
        updated_at,
        outcome,
        app_identifier,
        credentials: Vec::new(),
        failure_reason,
    })
}

/// Maps a row from `fetch_credentials_by_entry`'s query, which selects `entry_id`
/// first (column 0) followed by these fields (columns 1-5).
fn map_credential(row: &Row<'_, '_>) -> StorageResult<CredentialActivityCredential> {
    let credential_type = i64_to_credential_type(row.column_i64(1))?;
    let credential_source = i64_to_credential_source(row.column_i64(2))?;
    let proof_kind = i64_to_proof_kind(row.column_i64(3))?;
    let issuer_schema_id = if row.is_column_null(4) {
        None
    } else {
        Some(to_u64(row.column_i64(4), "issuer_schema_id")?)
    };

    let credential_id = if row.is_column_null(5) {
        None
    } else {
        Some(to_u64(row.column_i64(5), "credential_id")?)
    };

    Ok(CredentialActivityCredential {
        credential_type,
        credential_source,
        proof_kind,
        issuer_schema_id,
        credential_id,
    })
}

fn opt_text(row: &Row<'_, '_>, idx: usize) -> Option<String> {
    if row.is_column_null(idx) {
        None
    } else {
        Some(row.column_text(idx))
    }
}

const fn protocol_to_text(protocol: CredentialActivityProtocol) -> &'static str {
    match protocol {
        CredentialActivityProtocol::V3 => "v3",
        CredentialActivityProtocol::V4 => "v4",
    }
}

fn text_to_protocol(text: &str) -> StorageResult<CredentialActivityProtocol> {
    match text {
        "v3" => Ok(CredentialActivityProtocol::V3),
        "v4" => Ok(CredentialActivityProtocol::V4),
        other => Err(StorageError::CredentialActivityDb(format!(
            "invalid protocol: {other}"
        ))),
    }
}

const fn outcome_to_text(outcome: CredentialActivityOutcome) -> &'static str {
    match outcome {
        CredentialActivityOutcome::Shared => "shared",
        CredentialActivityOutcome::Declined => "declined",
        CredentialActivityOutcome::Cancelled => "cancelled",
        CredentialActivityOutcome::Failed => "failed",
        CredentialActivityOutcome::Incomplete => "incomplete",
    }
}

fn text_to_outcome(text: &str) -> StorageResult<CredentialActivityOutcome> {
    match text {
        "shared" => Ok(CredentialActivityOutcome::Shared),
        "declined" => Ok(CredentialActivityOutcome::Declined),
        "cancelled" => Ok(CredentialActivityOutcome::Cancelled),
        "failed" => Ok(CredentialActivityOutcome::Failed),
        "incomplete" => Ok(CredentialActivityOutcome::Incomplete),
        other => Err(StorageError::CredentialActivityDb(format!(
            "invalid outcome: {other}"
        ))),
    }
}

const fn failure_reason_to_i64(reason: CredentialActivityFailureReason) -> i64 {
    match reason {
        CredentialActivityFailureReason::NetworkError => 1,
        CredentialActivityFailureReason::Timeout => 2,
        CredentialActivityFailureReason::DeviceAuthenticationFailed => 3,
        CredentialActivityFailureReason::ProofGenerationFailed => 4,
        CredentialActivityFailureReason::RelyingPartyRejected => 5,
    }
}

fn i64_to_failure_reason(value: i64) -> StorageResult<CredentialActivityFailureReason> {
    match value {
        1 => Ok(CredentialActivityFailureReason::NetworkError),
        2 => Ok(CredentialActivityFailureReason::Timeout),
        3 => Ok(CredentialActivityFailureReason::DeviceAuthenticationFailed),
        4 => Ok(CredentialActivityFailureReason::ProofGenerationFailed),
        5 => Ok(CredentialActivityFailureReason::RelyingPartyRejected),
        other => Err(StorageError::CredentialActivityDb(format!(
            "invalid failure reason: {other}"
        ))),
    }
}

const fn credential_type_to_i64(value: CredentialActivityCredentialType) -> i64 {
    match value {
        CredentialActivityCredentialType::Human => 0,
        CredentialActivityCredentialType::Document => 1,
        CredentialActivityCredentialType::Face => 2,
        CredentialActivityCredentialType::Device => 3,
    }
}

fn i64_to_credential_type(
    value: i64,
) -> StorageResult<CredentialActivityCredentialType> {
    match value {
        0 => Ok(CredentialActivityCredentialType::Human),
        1 => Ok(CredentialActivityCredentialType::Document),
        2 => Ok(CredentialActivityCredentialType::Face),
        3 => Ok(CredentialActivityCredentialType::Device),
        other => Err(StorageError::CredentialActivityDb(format!(
            "invalid credential type: {other}"
        ))),
    }
}

const fn credential_source_to_i64(value: CredentialActivityCredentialSource) -> i64 {
    match value {
        CredentialActivityCredentialSource::Orb => 0,
        CredentialActivityCredentialSource::Document => 1,
        CredentialActivityCredentialSource::SecureDocument => 2,
        CredentialActivityCredentialSource::Passport => 3,
        CredentialActivityCredentialSource::Mnc => 4,
        CredentialActivityCredentialSource::Device => 5,
        CredentialActivityCredentialSource::Selfie => 6,
    }
}

fn i64_to_credential_source(
    value: i64,
) -> StorageResult<CredentialActivityCredentialSource> {
    match value {
        0 => Ok(CredentialActivityCredentialSource::Orb),
        1 => Ok(CredentialActivityCredentialSource::Document),
        2 => Ok(CredentialActivityCredentialSource::SecureDocument),
        3 => Ok(CredentialActivityCredentialSource::Passport),
        4 => Ok(CredentialActivityCredentialSource::Mnc),
        5 => Ok(CredentialActivityCredentialSource::Device),
        6 => Ok(CredentialActivityCredentialSource::Selfie),
        other => Err(StorageError::CredentialActivityDb(format!(
            "invalid credential source: {other}"
        ))),
    }
}

const fn proof_kind_to_i64(value: CredentialActivityProofKind) -> i64 {
    match value {
        CredentialActivityProofKind::UniqueHuman => 0,
        CredentialActivityProofKind::DocumentProof => 1,
        CredentialActivityProofKind::SelfieProof => 2,
    }
}

fn i64_to_proof_kind(value: i64) -> StorageResult<CredentialActivityProofKind> {
    match value {
        0 => Ok(CredentialActivityProofKind::UniqueHuman),
        1 => Ok(CredentialActivityProofKind::DocumentProof),
        2 => Ok(CredentialActivityProofKind::SelfieProof),
        other => Err(StorageError::CredentialActivityDb(format!(
            "invalid proof kind: {other}"
        ))),
    }
}

fn to_i64(value: u64, label: &str) -> StorageResult<i64> {
    i64::try_from(value).map_err(|_| {
        StorageError::CredentialActivityDb(format!(
            "{label} out of range for i64: {value}"
        ))
    })
}

fn to_u64(value: i64, label: &str) -> StorageResult<u64> {
    u64::try_from(value).map_err(|_| {
        StorageError::CredentialActivityDb(format!(
            "{label} out of range for u64: {value}"
        ))
    })
}

fn to_u32(value: i64, label: &str) -> StorageResult<u32> {
    u32::try_from(value).map_err(|_| {
        StorageError::CredentialActivityDb(format!(
            "{label} out of range for u32: {value}"
        ))
    })
}

fn map_db_err(err: &DbError) -> StorageError {
    StorageError::CredentialActivityDb(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretBox;
    use std::fs;
    use std::path::{Path, PathBuf};
    use uuid::Uuid;

    fn temp_activity_path() -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("walletkit-activity-{}.sqlite", Uuid::new_v4()));
        path
    }

    fn cleanup_activity_files(path: &Path) {
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite-shm"));
    }

    fn sample_entry() -> NewCredentialActivityEntry {
        NewCredentialActivityEntry {
            app_identifier: "app_worldcoin".to_string(),
            client_id: "request-uuid-1".to_string(),
            request_id: None,
            protocol: CredentialActivityProtocol::V3,
            credentials: vec![CredentialActivityCredential {
                credential_type: CredentialActivityCredentialType::Document,
                credential_source: CredentialActivityCredentialSource::Document,
                proof_kind: CredentialActivityProofKind::DocumentProof,
                issuer_schema_id: None,
                credential_id: None,
            }],
        }
    }

    #[test]
    fn test_activity_create_and_open() {
        let path = temp_activity_path();
        let key = SecretBox::init_with(|| [0x42u8; 32]);
        let (db, migrated) =
            CredentialActivity::new(&path, &key).expect("create activity db");

        assert_eq!(
            migrated,
            Some((0, 1)),
            "fresh database should migrate 0 -> 1"
        );

        drop(db);

        let (_db, migrated_again) =
            CredentialActivity::new(&path, &key).expect("reopen activity db");

        assert_eq!(
            migrated_again, None,
            "reopening an up-to-date database should report no migration"
        );

        cleanup_activity_files(&path);
    }

    #[test]
    fn test_record_activity_v3_has_null_request_id() {
        let path = temp_activity_path();
        let key = SecretBox::init_with(|| [0x01u8; 32]);
        let (db, _) = CredentialActivity::new(&path, &key).expect("create activity db");

        let entry_id = db
            .record_activity_started(&sample_entry(), 1000)
            .expect("record activity");

        let entries = db.list_activities(None, 10, 0).expect("list activities");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].entry_id, entry_id);
        assert_eq!(entries[0].request_id, None);
        assert_eq!(entries[0].outcome, None, "pending entry has no outcome yet");
        assert_eq!(entries[0].credentials.len(), 1);

        cleanup_activity_files(&path);
    }

    #[test]
    fn test_finalize_activity_replaces_credentials() {
        let path = temp_activity_path();
        let key = SecretBox::init_with(|| [0x02u8; 32]);
        let (db, _) = CredentialActivity::new(&path, &key).expect("create activity db");

        db.record_activity_started(&sample_entry(), 1000)
            .expect("record activity");

        let finalization = CredentialActivityFinalization {
            client_id: sample_entry().client_id,
            outcome: CredentialActivityOutcome::Shared,
            failure_reason: None,
            protocol: CredentialActivityProtocol::V3,
            credentials: vec![
                CredentialActivityCredential {
                    credential_type: CredentialActivityCredentialType::Face,
                    credential_source:
                        CredentialActivityCredentialSource::SecureDocument,
                    proof_kind: CredentialActivityProofKind::SelfieProof,
                    issuer_schema_id: Some(42),
                    credential_id: Some(7),
                },
                CredentialActivityCredential {
                    credential_type: CredentialActivityCredentialType::Device,
                    credential_source:
                        CredentialActivityCredentialSource::SecureDocument,
                    proof_kind: CredentialActivityProofKind::UniqueHuman,
                    issuer_schema_id: Some(43),
                    credential_id: Some(8),
                },
            ],
        };

        db.finalize_activity(&finalization, 1100)
            .expect("finalize activity");

        let entries = db.list_activities(None, 10, 0).expect("list activities");
        assert_eq!(entries.len(), 1);

        let entry = &entries[0];
        assert_eq!(entry.outcome, Some(CredentialActivityOutcome::Shared));
        assert_eq!(entry.updated_at, 1100);
        assert_eq!(
            entry.credentials.len(),
            2,
            "finalize should replace, not append, credentials"
        );
        assert!(entry.credentials.iter().all(|c| c.credential_id.is_some()));

        cleanup_activity_files(&path);
    }

    #[test]
    fn test_finalize_activity_preserves_credentials_on_non_shared_outcome() {
        let path = temp_activity_path();
        let key = SecretBox::init_with(|| [0x0Bu8; 32]);
        let (db, _) = CredentialActivity::new(&path, &key).expect("create activity db");

        // `sample_entry()` records one credential at start.
        db.record_activity_started(&sample_entry(), 1000)
            .expect("record activity");

        db.finalize_activity(
            &CredentialActivityFinalization {
                client_id: sample_entry().client_id,
                outcome: CredentialActivityOutcome::Declined,
                failure_reason: None,
                protocol: CredentialActivityProtocol::V3,
                credentials: vec![],
            },
            1100,
        )
        .expect("finalize activity");

        let entries = db.list_activities(None, 10, 0).expect("list activities");
        assert_eq!(
            entries[0].outcome,
            Some(CredentialActivityOutcome::Declined)
        );
        assert_eq!(
            entries[0].credentials.len(),
            1,
            "declining should preserve the originally-requested credential, not erase it"
        );

        cleanup_activity_files(&path);
    }

    #[test]
    fn test_finalize_activity_rejects_failed_without_failure_reason() {
        let path = temp_activity_path();
        let key = SecretBox::init_with(|| [0x0Cu8; 32]);
        let (db, _) = CredentialActivity::new(&path, &key).expect("create activity db");

        db.record_activity_started(&sample_entry(), 1000)
            .expect("record activity");

        let err = db
            .finalize_activity(
                &CredentialActivityFinalization {
                    client_id: sample_entry().client_id,
                    outcome: CredentialActivityOutcome::Failed,
                    failure_reason: None,
                    protocol: CredentialActivityProtocol::V3,
                    credentials: vec![],
                },
                1100,
            )
            .expect_err("Failed without failure_reason should be rejected");

        assert!(matches!(
            err,
            StorageError::CredentialActivityInvalidFinalization(_)
        ));

        cleanup_activity_files(&path);
    }

    #[test]
    fn test_finalize_activity_rejects_failure_reason_without_failed_outcome() {
        let path = temp_activity_path();
        let key = SecretBox::init_with(|| [0x0Du8; 32]);
        let (db, _) = CredentialActivity::new(&path, &key).expect("create activity db");

        db.record_activity_started(&sample_entry(), 1000)
            .expect("record activity");

        let err = db
            .finalize_activity(
                &CredentialActivityFinalization {
                    client_id: sample_entry().client_id,
                    outcome: CredentialActivityOutcome::Shared,
                    failure_reason: Some(CredentialActivityFailureReason::NetworkError),
                    protocol: CredentialActivityProtocol::V3,
                    credentials: vec![],
                },
                1100,
            )
            .expect_err("failure_reason without Failed outcome should be rejected");

        assert!(matches!(
            err,
            StorageError::CredentialActivityInvalidFinalization(_)
        ));

        cleanup_activity_files(&path);
    }

    #[test]
    fn test_finalize_activity_unknown_entry_fails() {
        let path = temp_activity_path();
        let key = SecretBox::init_with(|| [0x03u8; 32]);
        let (db, _) = CredentialActivity::new(&path, &key).expect("create activity db");

        let finalization = CredentialActivityFinalization {
            client_id: "no-such-request".to_string(),
            outcome: CredentialActivityOutcome::Failed,
            failure_reason: Some(CredentialActivityFailureReason::NetworkError),
            protocol: CredentialActivityProtocol::V4,
            credentials: vec![],
        };

        let err = db
            .finalize_activity(&finalization, 1000)
            .expect_err("unknown entry should fail");

        assert!(matches!(
            err,
            StorageError::CredentialActivityEntryNotFound { client_id }
                if client_id == "no-such-request"
        ));

        cleanup_activity_files(&path);
    }

    #[test]
    fn test_finalize_activity_is_idempotent() {
        let path = temp_activity_path();
        let key = SecretBox::init_with(|| [0x04u8; 32]);
        let (db, _) = CredentialActivity::new(&path, &key).expect("create activity db");

        db.record_activity_started(&sample_entry(), 1000)
            .expect("record activity");

        let finalization = CredentialActivityFinalization {
            client_id: sample_entry().client_id,
            outcome: CredentialActivityOutcome::Declined,
            failure_reason: None,
            protocol: CredentialActivityProtocol::V3,
            credentials: vec![],
        };

        db.finalize_activity(&finalization, 1100)
            .expect("first finalize");

        db.finalize_activity(&finalization, 1200)
            .expect("second finalize should not error");

        let entries = db.list_activities(None, 10, 0).expect("list activities");

        assert_eq!(
            entries[0].outcome,
            Some(CredentialActivityOutcome::Declined)
        );
        assert_eq!(entries[0].updated_at, 1200);

        cleanup_activity_files(&path);
    }

    #[test]
    fn test_list_activities_paginates_with_offset() {
        let path = temp_activity_path();
        let key = SecretBox::init_with(|| [0x05u8; 32]);
        let (db, _) = CredentialActivity::new(&path, &key).expect("create activity db");

        for i in 0..5u64 {
            db.record_activity_started(&sample_entry(), 1000 + i)
                .expect("record activity");
        }

        let page1 = db.list_activities(None, 2, 0).expect("list page 1");
        let page2 = db.list_activities(None, 2, 2).expect("list page 2");
        let page3 = db.list_activities(None, 2, 4).expect("list page 3");

        assert_eq!(page1.len(), 2);
        assert_eq!(page2.len(), 2);
        assert_eq!(page3.len(), 1);

        // Most recent first: page1's newest entry was recorded at 1004.
        assert_eq!(page1[0].created_at, 1004);
        assert_eq!(page1[1].created_at, 1003);
        assert_eq!(page2[0].created_at, 1002);
        assert_eq!(page3[0].created_at, 1000);

        cleanup_activity_files(&path);
    }

    #[test]
    fn test_activity_metadata_total_count() {
        let path = temp_activity_path();
        let key = SecretBox::init_with(|| [0x06u8; 32]);
        let (db, _) = CredentialActivity::new(&path, &key).expect("create activity db");

        assert_eq!(db.activity_metadata().expect("metadata").total_count, 0);

        db.record_activity_started(&sample_entry(), 1000)
            .expect("record activity");

        db.record_activity_started(&sample_entry(), 1001)
            .expect("record activity");

        assert_eq!(db.activity_metadata().expect("metadata").total_count, 2);

        cleanup_activity_files(&path);
    }

    #[test]
    fn test_reconcile_marks_pending_as_incomplete_on_open() {
        let path = temp_activity_path();
        let key = SecretBox::init_with(|| [0x07u8; 32]);
        let (db, _) = CredentialActivity::new(&path, &key).expect("create activity db");

        let entry_id = db
            .record_activity_started(&sample_entry(), 1000)
            .expect("record activity");

        // Simulate the app being killed before finalize ran, then reconciling on
        // the next `CredentialStore::init` (in production this is called by the
        // caller right after opening; here we call it directly).
        db.reconcile_incomplete(2000, &[]).expect("reconcile");

        let entries = db.list_activities(None, 10, 0).expect("list activities");

        assert_eq!(entries[0].entry_id, entry_id);
        assert_eq!(
            entries[0].outcome,
            Some(CredentialActivityOutcome::Incomplete)
        );
        assert_eq!(entries[0].updated_at, 2000);

        cleanup_activity_files(&path);
    }

    #[test]
    fn test_reconcile_incomplete_skips_excluded_client_ids() {
        let path = temp_activity_path();
        let key = SecretBox::init_with(|| [0x0Au8; 32]);
        let (db, _) = CredentialActivity::new(&path, &key).expect("create activity db");

        let excluded_entry = NewCredentialActivityEntry {
            client_id: "resume-me".to_string(),
            ..sample_entry()
        };
        let other_entry = NewCredentialActivityEntry {
            client_id: "abandon-me".to_string(),
            ..sample_entry()
        };

        let excluded_id = db
            .record_activity_started(&excluded_entry, 1000)
            .expect("record excluded");

        let other_id = db
            .record_activity_started(&other_entry, 1000)
            .expect("record other");

        db.reconcile_incomplete(2000, &["resume-me".to_string()])
            .expect("reconcile");

        let entries = db.list_activities(None, 10, 0).expect("list activities");
        let excluded = entries
            .iter()
            .find(|e| e.entry_id == excluded_id)
            .expect("excluded entry present");

        let other = entries
            .iter()
            .find(|e| e.entry_id == other_id)
            .expect("other entry present");

        assert_eq!(
            excluded.outcome, None,
            "excluded client_id should stay pending, not become Incomplete"
        );
        assert_eq!(
            other.outcome,
            Some(CredentialActivityOutcome::Incomplete),
            "non-excluded pending entry should still be reconciled"
        );

        cleanup_activity_files(&path);
    }

    #[test]
    fn test_reconcile_does_not_touch_finalized_entries() {
        let path = temp_activity_path();
        let key = SecretBox::init_with(|| [0x08u8; 32]);
        let (db, _) = CredentialActivity::new(&path, &key).expect("create activity db");

        db.record_activity_started(&sample_entry(), 1000)
            .expect("record activity");

        db.finalize_activity(
            &CredentialActivityFinalization {
                client_id: sample_entry().client_id,
                outcome: CredentialActivityOutcome::Shared,
                failure_reason: None,
                protocol: CredentialActivityProtocol::V3,
                credentials: vec![],
            },
            1100,
        )
        .expect("finalize");

        db.reconcile_incomplete(2000, &[]).expect("reconcile");

        let entries = db.list_activities(None, 10, 0).expect("list activities");

        assert_eq!(entries[0].outcome, Some(CredentialActivityOutcome::Shared));
        assert_eq!(
            entries[0].updated_at, 1100,
            "reconcile must not touch already-finalized entries"
        );

        cleanup_activity_files(&path);
    }

    #[test]
    fn test_activity_rebuild_on_corruption() {
        let path = temp_activity_path();
        let key = SecretBox::init_with(|| [0x09u8; 32]);
        let (db, _) = CredentialActivity::new(&path, &key).expect("create activity db");
        db.record_activity_started(&sample_entry(), 1000)
            .expect("record activity");

        drop(db);

        fs::write(&path, b"corrupt").expect("corrupt activity file");

        let (db, migrated) =
            CredentialActivity::new(&path, &key).expect("rebuild activity db");

        assert_eq!(
            migrated,
            Some((0, 1)),
            "rebuilt database is fresh and should report a migration"
        );

        let entries = db.list_activities(None, 10, 0).expect("list activities");
        assert!(
            entries.is_empty(),
            "rebuilt database should be empty, not error"
        );

        cleanup_activity_files(&path);
    }
}
