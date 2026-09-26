package dev.kreienbuehl.ksecuremessage.storage.client.sqldelight

import app.cash.sqldelight.db.QueryResult
import app.cash.sqldelight.db.SqlCursor
import app.cash.sqldelight.db.SqlDriver
import dev.kreienbuehl.ksecuremessage.storage.encryption.SealedRecords
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyId

/**
 * Every column that holds sealed storage records. The key reference scan
 * reads all of them; a table or column that stores sealed records must be
 * listed here, or retiring a key could lose it. `SealedColumnsTest` checks
 * this list against the schema.
 */
internal val SEALED_COLUMNS: List<Pair<String, String>> = listOf(
    "local_identity" to "sealed_identity",
    "device_authentication_key" to "sealed_key_pair",
    "device_authentication_recovery_key" to "sealed_key_pair",
    "device_authentication_rotation_key" to "sealed_key_pair",
    "signed_pre_key" to "sealed_key_pair",
    "one_time_pre_key" to "sealed_key_pair",
    "session" to "sealed_state",
    "pending_outbound_message" to "sealed_frame",
    "storage_encryption" to "key_check",
    "storage_encryption" to "retiring_key_check",
)

/**
 * Counts the sealed records per storage key ID by reading the header of
 * every value in [SEALED_COLUMNS]; nothing is decrypted. A value that is not
 * a well-formed record throws [dev.kreienbuehl.ksecuremessage.storage.encryption.StorageEncryptionException].
 * The authoritative check before a key is retired.
 */
internal suspend fun SqlDriver.sealedRecordKeyIds(): Map<StorageKeyId, Long> {
    val counts = mutableMapOf<StorageKeyId, Long>()
    for ((table, column) in SEALED_COLUMNS) {
        for (record in queryRows("SELECT $column FROM $table WHERE $column IS NOT NULL") { it.getBytes(0)!! }) {
            val id = SealedRecords.keyId(record)
            counts[id] = (counts[id] ?: 0) + 1
        }
    }
    return counts
}

/** The header of records sealed with [keyId], as upper-case hex like SQLite's `hex()`. */
internal fun sealedHeaderHex(keyId: StorageKeyId): String =
    SealedRecords.header(keyId).joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }.uppercase()

// Like SQLDelight's awaitAsList: a synchronous driver's cursor must be
// read before executeQuery returns, an asynchronous one when awaited.
internal suspend fun <T> SqlDriver.queryRows(sql: String, map: (SqlCursor) -> T): List<T> =
    executeQuery(null, sql, { cursor ->
        val rows = mutableListOf<T>()
        when (val first = cursor.next()) {
            is QueryResult.AsyncValue -> QueryResult.AsyncValue {
                if (first.await()) {
                    rows += map(cursor)
                    while (cursor.next().await()) rows += map(cursor)
                }
                rows
            }
            is QueryResult.Value -> {
                if (first.value) {
                    rows += map(cursor)
                    while (cursor.next().value) rows += map(cursor)
                }
                QueryResult.Value(rows)
            }
        }
    }, 0).await()
