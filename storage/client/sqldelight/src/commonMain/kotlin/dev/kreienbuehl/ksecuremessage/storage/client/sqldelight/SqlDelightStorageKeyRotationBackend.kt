package dev.kreienbuehl.ksecuremessage.storage.client.sqldelight

import app.cash.sqldelight.async.coroutines.awaitAsList
import app.cash.sqldelight.async.coroutines.awaitAsOne
import app.cash.sqldelight.async.coroutines.awaitAsOneOrNull
import app.cash.sqldelight.db.SqlDriver
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.LogicalMessageId
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageEncryptionException
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageEncryptionKey
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyId
import dev.kreienbuehl.ksecuremessage.storage.rotation.StorageKeyRotationBackend
import dev.kreienbuehl.ksecuremessage.storage.rotation.StorageKeyRotationPhase
import dev.kreienbuehl.ksecuremessage.storage.rotation.StorageKeyRotationState
import dev.kreienbuehl.ksecuremessage.storage.client.sqldelight.db.ClientStateQueries
import dev.kreienbuehl.ksecuremessage.storage.client.sqldelight.db.SelectStorageEncryption

/**
 * The storage key rotation backend of [SqlDelightClientStorage]: the rotation
 * state in the `storage_encryption` row, the re-encryption batches over the
 * sealed tables and the key reference scan over [SEALED_COLUMNS]. The state
 * machine itself is [dev.kreienbuehl.ksecuremessage.storage.rotation.StorageKeyRotationManager].
 */
internal class SqlDelightStorageKeyRotationBackend(
    private val storage: SqlDelightClientStorage,
    private val driver: SqlDriver,
    private val queries: ClientStateQueries,
) : StorageKeyRotationBackend {
    override suspend fun <T> exclusive(block: suspend () -> T): T = storage.rotationStep(block)

    override suspend fun state(): StorageKeyRotationState =
        storage.lockedTransaction { rotationState(queries.selectStorageEncryption().awaitAsOne()) }

    override suspend fun remainingRecords(): Long =
        storage.lockedTransaction { queries.countRecordsToReseal(sealedHeaderHex(storage.currentKey.id)).awaitAsOne() }

    override suspend fun prepare(from: StorageKeyRotationState.Stable, nextKeyId: StorageKeyId) {
        storage.lockedTransaction {
            if (queries.prepareStorageKeyRotation(nextKeyId.value.toLong(), from.currentKeyId.value.toLong()) != 1L) {
                throw IllegalStateException("Storage encryption state changed while rotating")
            }
        }
    }

    override suspend fun activate(from: StorageKeyRotationState.Preparing, key: StorageEncryptionKey) {
        val previous = storage.currentKey
        val next = storage.cipherFactory(key, listOf(previous))
        val keyCheck = next.sealKeyCheck()
        storage.lockedTransaction {
            if (queries.activateStorageKey(keyCheck, previous.id.value.toLong(), key.id.value.toLong()) != 1L) {
                throw IllegalStateException("Storage encryption state changed while rotating")
            }
        }
        storage.useKeys(key, next)
    }

    override suspend fun migrateBatch(from: StorageKeyRotationState.Migrating, maxRecords: Int): Long = storage.lockedTransaction {
        val records = storage.records
        val header = sealedHeaderHex(storage.currentKey.id)
        var budget = maxRecords.toLong()
        if (budget > 0) {
            queries.selectIdentityToReseal(header).awaitAsOneOrNull()?.let { sealed ->
                queries.updateIdentityRecord(records.sealIdentity(records.openIdentity(sealed)))
                budget--
            }
        }
        if (budget > 0) {
            queries.selectDeviceAuthenticationKeyToReseal(header).awaitAsOneOrNull()?.let { sealed ->
                queries.updateDeviceAuthenticationKeyRecord(records.sealDeviceAuthenticationKey(records.openDeviceAuthenticationKey(sealed)))
                budget--
            }
        }
        if (budget > 0) {
            queries.selectDeviceAuthenticationRecoveryKeyToReseal(header).awaitAsOneOrNull()?.let { sealed ->
                queries.updateDeviceAuthenticationRecoveryKeyRecord(
                    records.sealDeviceAuthenticationRecoveryKey(records.openDeviceAuthenticationRecoveryKey(sealed)),
                )
                budget--
            }
        }
        if (budget > 0) {
            queries.selectDeviceAuthenticationRotationKeyToReseal(header).awaitAsOneOrNull()?.let { sealed ->
                queries.updateDeviceAuthenticationRotationKeyRecord(
                    records.sealDeviceAuthenticationRotationKey(records.openDeviceAuthenticationRotationKey(sealed)),
                )
                budget--
            }
        }
        if (budget > 0) {
            queries.selectDeviceAuthenticationLastDeviceRecoveryKeyToReseal(header).awaitAsOneOrNull()?.let { sealed ->
                queries.updateDeviceAuthenticationLastDeviceRecoveryKeyRecord(
                    records.sealDeviceAuthenticationLastDeviceRecoveryKey(records.openDeviceAuthenticationLastDeviceRecoveryKey(sealed)),
                )
                budget--
            }
        }
        if (budget > 0) {
            val rows = queries.selectSignedPreKeysToReseal(header, budget).awaitAsList()
            for (row in rows) {
                val preKey = records.openSignedPreKey(SignedPreKeyId(row.id.toInt()), row.sealed_key_pair)
                queries.updateSignedPreKeyRecord(records.sealSignedPreKey(preKey), row.id)
            }
            budget -= rows.size
        }
        if (budget > 0) {
            val rows = queries.selectOneTimePreKeysToReseal(header, budget).awaitAsList()
            for (row in rows) {
                val preKey = records.openOneTimePreKey(OneTimePreKeyId(row.id.toInt()), row.sealed_key_pair)
                queries.updateOneTimePreKeyRecord(records.sealOneTimePreKey(preKey), row.id)
            }
            budget -= rows.size
        }
        if (budget > 0) {
            val rows = queries.selectSessionsToReseal(header, budget).awaitAsList()
            for (row in rows) {
                val session = records.openSession(DeviceAddress(UserId(row.remote_user_id), DeviceId(row.remote_device_id)), row.sealed_state)
                queries.updateSessionRecord(records.sealSession(session), row.remote_user_id, row.remote_device_id)
            }
            budget -= rows.size
        }
        if (budget > 0) {
            val rows = queries.selectPendingOutboundToReseal(header, budget).awaitAsList()
            for (row in rows) {
                val recipient = DeviceAddress(UserId(row.recipient_user_id), DeviceId(row.recipient_device_id))
                val id = LogicalMessageId.fromByteArray(row.message_id)
                val frame = records.openPendingFrame(recipient, id, row.sealed_frame)
                queries.updatePendingOutboundRecord(records.sealPendingFrame(recipient, id, frame), row.sequence)
            }
            budget -= rows.size
        }
        if (budget > 0) {
            val rows = queries.selectPendingInboundToReseal(header, budget).awaitAsList()
            for (row in rows) {
                val sender = DeviceAddress(UserId(row.sender_user_id), DeviceId(row.sender_device_id))
                val id = LogicalMessageId.fromByteArray(row.message_id)
                val frame = records.openPendingInboundFrame(sender, id, row.sealed_frame)
                queries.updatePendingInboundRecord(records.sealPendingInboundFrame(sender, id, frame), row.sequence)
            }
            budget -= rows.size
        }
        if (budget > 0) {
            val rows = queries.selectProcessedDigestsToReseal(header, budget).awaitAsList()
            for (row in rows) {
                val sender = DeviceAddress(UserId(row.sender_user_id), DeviceId(row.sender_device_id))
                val id = LogicalMessageId.fromByteArray(row.message_id)
                val digest = records.openProcessedDigest(sender, id, row.sealed_digest)
                queries.updateProcessedDigestRecord(records.sealProcessedDigest(sender, id, digest), row.sender_user_id, row.sender_device_id, row.message_id)
            }
        }
        queries.countRecordsToReseal(header).awaitAsOne()
    }

    override suspend fun keyReferences(): Map<StorageKeyId, Long> = storage.lockedTransaction { driver.sealedRecordKeyIds() }

    /**
     * The retiring key check is dropped and every sealed record is scanned in
     * the same transaction; [requireRetirable] throwing rolls it back.
     */
    override suspend fun markRetiring(
        from: StorageKeyRotationState.Migrating,
        requireRetirable: (Map<StorageKeyId, Long>) -> Unit,
    ) {
        storage.lockedTransaction {
            if (queries.markStorageKeyRetiring(from.currentKeyId.value.toLong(), from.retiringKeyId.value.toLong()) != 1L) {
                throw IllegalStateException("Storage encryption state changed while rotating")
            }
            requireRetirable(driver.sealedRecordKeyIds())
        }
        val current = storage.currentKey
        storage.useKeys(current, storage.cipherFactory(current, emptyList()))
    }

    override suspend fun complete(from: StorageKeyRotationState.Retiring) {
        storage.lockedTransaction {
            if (queries.finishStorageKeyRotation(from.currentKeyId.value.toLong(), from.retiringKeyId.value.toLong()) != 1L) {
                throw IllegalStateException("Storage encryption state changed while rotating")
            }
        }
    }

    companion object {
        // Persisted `rotation_phase` values (docs/storage-key-rotation.md); frozen.
        const val PHASE_STABLE = 0L
        const val PHASE_PREPARING = 1L
        const val PHASE_MIGRATING = 2L
        const val PHASE_RETIRING = 3L

        /**
         * The validated rotation state of a `storage_encryption` row with a
         * bound key. Throws [StorageEncryptionException.MalformedRecord] for an
         * inconsistent row and [StorageEncryptionException.UnsupportedFormat] for
         * an unknown phase.
         */
        fun rotationState(row: SelectStorageEncryption): StorageKeyRotationState {
            val phase = when (row.rotation_phase) {
                PHASE_STABLE -> StorageKeyRotationPhase.STABLE
                PHASE_PREPARING -> StorageKeyRotationPhase.PREPARING
                PHASE_MIGRATING -> StorageKeyRotationPhase.MIGRATING
                PHASE_RETIRING -> StorageKeyRotationPhase.RETIRING
                else -> throw StorageEncryptionException.UnsupportedFormat("Unsupported storage key rotation phase ${row.rotation_phase}")
            }
            // The retiring key check exists exactly while the retiring key is needed to open.
            if (phase != StorageKeyRotationPhase.MIGRATING && row.retiring_key_check != null) {
                throw StorageEncryptionException.MalformedRecord("Invalid storage key rotation state")
            }
            return StorageKeyRotationState.of(
                phase = phase,
                currentKeyId = storageKeyId(row.key_id ?: throw StorageEncryptionException.MalformedRecord("Missing storage key ID")),
                highestKeyId = row.highest_key_id?.let(::storageKeyId),
                nextKeyId = row.next_key_id?.let(::storageKeyId),
                retiringKeyId = row.retiring_key_id?.let(::storageKeyId),
            )
        }

        fun storageKeyId(value: Long): StorageKeyId {
            if (value !in 0..Int.MAX_VALUE) throw StorageEncryptionException.MalformedRecord("Invalid storage key ID")
            return StorageKeyId(value.toInt())
        }
    }
}
