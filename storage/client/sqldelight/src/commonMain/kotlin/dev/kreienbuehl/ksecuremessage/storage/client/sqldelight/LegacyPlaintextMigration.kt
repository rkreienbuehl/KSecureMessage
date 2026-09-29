package dev.kreienbuehl.ksecuremessage.storage.client.sqldelight

import app.cash.sqldelight.db.SqlCursor
import app.cash.sqldelight.db.SqlDriver
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.LogicalMessageId
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.LocalIdentity
import dev.kreienbuehl.ksecuremessage.protocol.OneTimePreKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.SecureSession
import dev.kreienbuehl.ksecuremessage.protocol.SignedPreKeyPair
import dev.kreienbuehl.ksecuremessage.storage.encryption.ClientRecordCipher

/**
 * Encrypts a milestone 8 database (storage_encryption.format = 0) in place.
 * The caller runs it inside one SQLite transaction together with setting
 * format 1, so either every sensitive table is rebuilt with encrypted
 * records, or nothing changes.
 *
 * Each sensitive table is rebuilt the way SQLite documents for schema
 * changes: create the new table under a temporary name, copy the rows
 * (sealed), drop the old table, rename the new one. IDs, addresses,
 * timestamps and pending sequence numbers are copied unchanged; the
 * AUTOINCREMENT high-water mark of pending messages is carried over, so
 * sequence numbers are never reused.
 *
 * The DDL below must stay identical to ClientState.sq.
 */
internal class LegacyPlaintextMigration(private val driver: SqlDriver, private val records: ClientRecordCipher) {
    suspend fun run() {
        migrateIdentity()
        migrateSignedPreKeys()
        migrateOneTimePreKeys()
        migrateSessions()
        migratePendingOutbound()
    }

    private suspend fun migrateIdentity() {
        val rows = query("SELECT public_key, private_key FROM local_identity") { LocalIdentity(it.bytes(0), it.bytes(1)) }
        rebuild("local_identity", IDENTITY_DDL) { table ->
            for (identity in rows) {
                execute("INSERT INTO $table (id, sealed_identity) VALUES (0, ?)", records.sealIdentity(identity))
            }
        }
    }

    private suspend fun migrateSignedPreKeys() {
        class Row(val preKey: SignedPreKeyPair, val createdAt: Long?, val replacedAt: Long?)
        val rows = query("SELECT id, public_key, signature, private_key, created_at, replaced_at FROM signed_pre_key") {
            Row(SignedPreKeyPair(SignedPreKeyId(it.long(0).toInt()), it.bytes(1), it.bytes(2), it.bytes(3)), it.getLong(4), it.getLong(5))
        }
        // pre_key_state.current_signed_pre_key_id references signed_pre_key.
        // With foreign keys enforced, dropping the old table while a row
        // references it fails. Detach the reference during the rebuild and
        // restore it once the rebuilt table has the name again.
        val current = query("SELECT current_signed_pre_key_id FROM pre_key_state") { it.getLong(0) }.single()
        execute("UPDATE pre_key_state SET current_signed_pre_key_id = NULL")
        rebuild("signed_pre_key", SIGNED_PRE_KEY_DDL) { table ->
            for (row in rows) {
                val sealed = records.sealSignedPreKey(row.preKey)
                driver.execute(null, "INSERT INTO $table (id, sealed_key_pair, created_at, replaced_at) VALUES (?, ?, ?, ?)", 4) {
                    bindLong(0, row.preKey.id.value.toLong())
                    bindBytes(1, sealed)
                    bindLong(2, row.createdAt)
                    bindLong(3, row.replacedAt)
                }.await()
            }
        }
        driver.execute(null, "UPDATE pre_key_state SET current_signed_pre_key_id = ?", 1) { bindLong(0, current) }.await()
    }

    private suspend fun migrateOneTimePreKeys() {
        val rows = query("SELECT id, public_key, private_key FROM one_time_pre_key") {
            OneTimePreKeyPair(OneTimePreKeyId(it.long(0).toInt()), it.bytes(1), it.bytes(2))
        }
        rebuild("one_time_pre_key", ONE_TIME_PRE_KEY_DDL) { table ->
            for (preKey in rows) {
                val sealed = records.sealOneTimePreKey(preKey)
                driver.execute(null, "INSERT INTO $table (id, sealed_key_pair) VALUES (?, ?)", 2) {
                    bindLong(0, preKey.id.value.toLong())
                    bindBytes(1, sealed)
                }.await()
            }
        }
    }

    private suspend fun migrateSessions() {
        val rows = query("SELECT remote_user_id, remote_device_id, state FROM session") {
            SecureSession(DeviceAddress(UserId(it.string(0)), DeviceId(it.string(1))), it.bytes(2))
        }
        rebuild("session", SESSION_DDL) { table ->
            for (session in rows) {
                val sealed = records.sealSession(session)
                driver.execute(null, "INSERT INTO $table (remote_user_id, remote_device_id, sealed_state) VALUES (?, ?, ?)", 3) {
                    bindString(0, session.remote.userId.value)
                    bindString(1, session.remote.deviceId.value)
                    bindBytes(2, sealed)
                }.await()
            }
        }
    }

    private suspend fun migratePendingOutbound() {
        class Row(val sequence: Long, val recipient: DeviceAddress, val id: LogicalMessageId, val frame: ByteArray)
        val rows = query("SELECT sequence, recipient_user_id, recipient_device_id, message_id, frame FROM pending_outbound_message") {
            Row(it.long(0), DeviceAddress(UserId(it.string(1)), DeviceId(it.string(2))), LogicalMessageId.fromByteArray(it.bytes(3)), it.bytes(4))
        }
        val highWater = query("SELECT seq FROM sqlite_sequence WHERE name = 'pending_outbound_message'") { it.long(0) }.singleOrNull()
        rebuild("pending_outbound_message", PENDING_OUTBOUND_DDL) { table ->
            for (row in rows) {
                val sealed = records.sealPendingFrame(row.recipient, row.id, row.frame)
                driver.execute(
                    null,
                    "INSERT INTO $table (sequence, recipient_user_id, recipient_device_id, message_id, sealed_frame) VALUES (?, ?, ?, ?, ?)",
                    5,
                ) {
                    bindLong(0, row.sequence)
                    bindString(1, row.recipient.userId.value)
                    bindString(2, row.recipient.deviceId.value)
                    bindBytes(3, row.id.toByteArray())
                    bindBytes(4, sealed)
                }.await()
            }
        }
        // Dropping the old table removed its index (schema version 15) and its
        // high-water mark; the copied rows only restored the highest
        // remaining sequence.
        execute(PENDING_OUTBOUND_RECIPIENT_INDEX_DDL)
        execute("DELETE FROM sqlite_sequence WHERE name = 'pending_outbound_message'")
        val restored = listOfNotNull(highWater, rows.maxOfOrNull { it.sequence }).maxOrNull()
        if (restored != null) {
            driver.execute(null, "INSERT INTO sqlite_sequence (name, seq) VALUES ('pending_outbound_message', ?)", 1) {
                bindLong(0, restored)
            }.await()
        }
    }

    private suspend fun rebuild(table: String, ddl: String, copy: suspend (newTable: String) -> Unit) {
        val newTable = "${table}_m9"
        execute(ddl.replace("CREATE TABLE $table ", "CREATE TABLE $newTable "))
        copy(newTable)
        execute("DROP TABLE $table")
        execute("ALTER TABLE $newTable RENAME TO $table")
    }

    private suspend fun execute(sql: String, blob: ByteArray? = null) {
        driver.execute(null, sql, if (blob == null) 0 else 1) { blob?.let { bindBytes(0, it) } }.await()
    }

    private suspend fun <T> query(sql: String, map: (SqlCursor) -> T): List<T> = driver.queryRows(sql, map)

    private fun SqlCursor.bytes(index: Int): ByteArray = checkNotNull(getBytes(index)) { "Unexpected NULL in legacy row" }
    private fun SqlCursor.long(index: Int): Long = checkNotNull(getLong(index)) { "Unexpected NULL in legacy row" }
    private fun SqlCursor.string(index: Int): String = checkNotNull(getString(index)) { "Unexpected NULL in legacy row" }

    companion object {
        /** The milestone 8 plaintext columns of every table this migration rebuilds. */
        private val PLAINTEXT_LAYOUT = mapOf(
            "local_identity" to setOf("public_key", "private_key"),
            "signed_pre_key" to setOf("public_key", "signature", "private_key"),
            "one_time_pre_key" to setOf("public_key", "private_key"),
            "session" to setOf("state"),
            "pending_outbound_message" to setOf("frame"),
        )

        /**
         * Whether every table this migration rebuilds is still in the
         * milestone 8 plaintext layout: its plaintext columns exist and no
         * sealed column does (S1, finding F7). Reads the schema only.
         */
        suspend fun hasPlaintextLayout(driver: SqlDriver): Boolean = PLAINTEXT_LAYOUT.all { (table, plaintext) ->
            val columns = driver.queryRows("SELECT name FROM pragma_table_info('$table')") { checkNotNull(it.getString(0)) }.toSet()
            columns.containsAll(plaintext) && columns.none { it.startsWith("sealed_") }
        }

        // Identical to ClientState.sq. SqlDelightMigrationTest compares the
        // columns of a migrated database with those of a new one.
        const val IDENTITY_DDL = """CREATE TABLE local_identity (
    id INTEGER NOT NULL PRIMARY KEY CHECK (id = 0),
    sealed_identity BLOB NOT NULL
)"""
        const val SIGNED_PRE_KEY_DDL = """CREATE TABLE signed_pre_key (
    id INTEGER NOT NULL PRIMARY KEY CHECK (id BETWEEN 0 AND 2147483647),
    sealed_key_pair BLOB NOT NULL,
    created_at INTEGER,
    replaced_at INTEGER
)"""
        const val ONE_TIME_PRE_KEY_DDL = """CREATE TABLE one_time_pre_key (
    id INTEGER NOT NULL PRIMARY KEY CHECK (id BETWEEN 0 AND 2147483647),
    sealed_key_pair BLOB NOT NULL
)"""
        const val SESSION_DDL = """CREATE TABLE session (
    remote_user_id TEXT NOT NULL,
    remote_device_id TEXT NOT NULL,
    sealed_state BLOB NOT NULL,
    PRIMARY KEY (remote_user_id, remote_device_id)
)"""
        const val PENDING_OUTBOUND_DDL = """CREATE TABLE pending_outbound_message (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient_user_id TEXT NOT NULL,
    recipient_device_id TEXT NOT NULL,
    message_id BLOB NOT NULL CHECK (length(message_id) = 16),
    sealed_frame BLOB NOT NULL,
    UNIQUE (recipient_user_id, recipient_device_id, message_id)
)"""
        const val PENDING_OUTBOUND_RECIPIENT_INDEX_DDL =
            "CREATE INDEX pending_outbound_message_recipient ON pending_outbound_message (recipient_user_id, recipient_device_id, sequence)"
    }
}
