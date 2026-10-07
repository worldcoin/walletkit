package org.world.walletkit

class CredentialStore internal constructor(
    internal val handle: NativeHandle,
) : AutoCloseable {
    override fun close() = handle.close()

    fun storagePaths(): StoragePaths = StoragePaths(NativeHandle(NativeBridge.credentialStoreStoragePaths(handle)))

    fun initialize(
        leafIndex: ULong,
        now: ULong,
    ): Unit = NativeBridge.credentialStoreInitialize(handle, leafIndex.toLong(), now.toLong())

    fun listCredentials(
        issuerSchemaId: ULong?,
        now: ULong,
    ): List<CredentialRecord> =
        NativeReader.decode(NativeBridge.credentialStoreListCredentials(handle, issuerSchemaId?.toLong(), now.toLong())) {
            list { readCredentialRecord() }
        }

    fun fetchCredential(
        issuerSchemaId: ULong,
        now: ULong,
    ): Credential? =
        NativeBridge.credentialStoreFetchCredential(handle, issuerSchemaId.toLong(), now.toLong()).let {
            if (it ==
                0L
            ) {
                null
            } else {
                Credential(NativeHandle(it))
            }
        }

    fun deleteCredential(credentialId: ULong): Unit = NativeBridge.credentialStoreDeleteCredential(handle, credentialId.toLong())

    fun storeCredential(
        credential: Credential,
        blindingFactor: FieldElement,
        expiresAt: ULong,
        associatedData: ByteArray?,
        now: ULong,
    ): ULong =
        NativeBridge
            .credentialStoreStoreCredential(
                handle,
                credential.handle,
                blindingFactor.handle,
                expiresAt.toLong(),
                associatedData,
                now.toLong(),
            ).toULong()

    /** Permanently deletes all stored credentials. Require an explicit user recovery/reset decision before calling. */
    fun dangerDeleteAllCredentials(): ULong = NativeBridge.credentialStoreDangerDeleteAllCredentials(handle).toULong()

    fun recordActivity(
        entry: ActivityEntry,
        now: ULong,
    ): ULong = NativeBridge.credentialStoreRecordActivity(handle, NativeWriter.encode { writeActivityEntry(entry) }, now.toLong()).toULong()

    fun listActivities(
        query: ActivityQuery,
        limit: UInt,
        offset: UInt,
    ): List<ActivityEntry> =
        NativeReader.decode(
            NativeBridge.credentialStoreListActivities(handle, query.issuerSchemaId?.toLong(), limit.toInt(), offset.toInt()),
        ) {
            list { readActivityEntry() }
        }

    fun activityMetadata(): ActivityMetadata = ActivityMetadata(NativeBridge.credentialStoreActivityMetadata(handle).toULong())

    fun clearActivities(): ULong = NativeBridge.credentialStoreClearActivities(handle).toULong()

    /** Deletes the key envelope, vault, and cache. The store becomes uninitialized. Use only for logout or account deletion. */
    fun destroyStorage(): Unit = NativeBridge.credentialStoreDestroyStorage(handle)

    /** Exports the vault for backup. The host owns secure persistence/upload of the returned bytes; never log the payload. */
    fun exportVaultForBackup(): ByteArray = NativeBridge.credentialStoreExportVaultForBackup(handle)

    fun importVaultFromBackup(backupBytes: ByteArray): Unit = NativeBridge.credentialStoreImportVaultFromBackup(handle, backupBytes)

    fun mergeVaultFromBackup(backupBytes: ByteArray): ULong =
        NativeBridge.credentialStoreMergeVaultFromBackup(handle, backupBytes).toULong()

    fun setVaultChangedListener(listener: VaultChangedListener): Unit =
        NativeBridge.credentialStoreSetVaultChangedListener(handle, listener)

    fun setActivityChangedListener(listener: ActivityChangedListener): Unit =
        NativeBridge.credentialStoreSetActivityChangedListener(handle, listener)

    companion object {
        fun newWithComponents(
            paths: StoragePaths,
            keystore: DeviceKeystore,
            blobStore: AtomicBlobStore,
        ): CredentialStore = CredentialStore(NativeHandle(NativeBridge.credentialStoreNewWithComponents(paths.handle, keystore, blobStore)))
    }
}
