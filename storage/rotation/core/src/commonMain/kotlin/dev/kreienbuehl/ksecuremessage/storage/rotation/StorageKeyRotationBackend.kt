package dev.kreienbuehl.ksecuremessage.storage.rotation

import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageEncryptionKey
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyId

/**
 * What a persistent storage adapter provides so [StorageKeyRotationManager]
 * can rotate its storage key (docs/storage-key-rotation.md). The manager owns
 * the order of the steps and the rules between them; the backend owns the
 * persisted rotation state, its transactions, the records and the proof that
 * no record uses a key.
 *
 * Every method except [exclusive] is one atomic storage transaction. A
 * transition method is a compare-and-set: it changes the persisted state only
 * if it still equals `from`, and otherwise throws [IllegalStateException] and
 * changes nothing. A failure rolls back the whole call. Transition methods
 * never call the key provider; the manager does that between them.
 */
interface StorageKeyRotationBackend {
    /**
     * Runs [block] exclusively of every other operation on this storage
     * (other rotation steps and every storage transaction). Throws
     * [IllegalStateException] if called inside a storage transaction. [block]
     * runs outside any transaction, because it calls the key provider.
     */
    suspend fun <T> exclusive(block: suspend () -> T): T

    /** The persisted rotation state. */
    suspend fun state(): StorageKeyRotationState

    /** How many records are not sealed with the current key. */
    suspend fun remainingRecords(): Long

    /**
     * STABLE to PREPARING: records [nextKeyId] as the allocated key and as the
     * new key ID high-water mark, in one commit, so it is never allocated
     * twice.
     */
    suspend fun prepare(from: StorageKeyRotationState.Stable, nextKeyId: StorageKeyId)

    /**
     * PREPARING to MIGRATING: [key] (the allocated key, already persisted by
     * the provider and read back) becomes current and the previous current key
     * becomes the retiring key. From this commit on every new record is sealed
     * with [key]; records of the retiring key stay readable.
     */
    suspend fun activate(from: StorageKeyRotationState.Preparing, key: StorageEncryptionKey)

    /**
     * Re-encrypts up to [maxRecords] records that are not sealed with the
     * current key, in one transaction. A record that fails to open fails the
     * whole batch. Returns how many such records remain.
     */
    suspend fun migrateBatch(from: StorageKeyRotationState.Migrating, maxRecords: Int): Long

    /**
     * The authoritative key reference scan: for every key ID, how many
     * sealed values in the storage name it. Reads every location that holds
     * sealed records, including key checks; a value that is not a well-formed
     * record throws.
     */
    suspend fun keyReferences(): Map<StorageKeyId, Long>

    /**
     * MIGRATING to RETIRING, in one transaction: drops whatever only the
     * retiring key needed for opening, runs [keyReferences] and passes the
     * result to [requireRetirable], and commits only if it returns. From then
     * on the storage no longer needs the retiring key.
     */
    suspend fun markRetiring(
        from: StorageKeyRotationState.Migrating,
        requireRetirable: (Map<StorageKeyId, Long>) -> Unit,
    )

    /** RETIRING to STABLE, after the retiring key was removed from the provider. */
    suspend fun complete(from: StorageKeyRotationState.Retiring)
}
