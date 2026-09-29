package dev.kreienbuehl.ksecuremessage.storage.client.sqldelight

import app.cash.sqldelight.db.QueryResult
import app.cash.sqldelight.db.SqlDriver

// Raw access to the test database (synchronous drivers), to inspect and
// tamper with persisted bytes directly instead of going through the storage.

fun SqlDriver.strings(sql: String): List<String?> = executeQuery(null, sql, { cursor ->
    val rows = mutableListOf<String?>()
    while (cursor.next().value) rows += cursor.getString(0)
    QueryResult.Value(rows)
}, 0).value

fun SqlDriver.tables(): List<String> =
    strings("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name").filterNotNull()

/** Column name, type, NOT NULL, default and primary key position of every column of [table]. */
fun SqlDriver.columns(table: String): List<String?> =
    strings("SELECT name || ' ' || type || ' ' || \"notnull\" || ' ' || ifnull(dflt_value, '-') || ' ' || pk FROM pragma_table_info('$table')")

fun SqlDriver.blobs(sql: String): List<ByteArray> = executeQuery(null, sql, { cursor ->
    val rows = mutableListOf<ByteArray>()
    while (cursor.next().value) rows += checkNotNull(cursor.getBytes(0))
    QueryResult.Value(rows)
}, 0).value

fun SqlDriver.blob(sql: String): ByteArray = blobs(sql).single()

fun SqlDriver.longs(sql: String): List<Long?> = executeQuery(null, sql, { cursor ->
    val rows = mutableListOf<Long?>()
    while (cursor.next().value) rows += cursor.getLong(0)
    QueryResult.Value(rows)
}, 0).value

fun SqlDriver.exec(sql: String, vararg blobs: ByteArray) {
    execute(null, sql, blobs.size) { blobs.forEachIndexed { index, blob -> bindBytes(index, blob) } }
}

/** Every row of every table, quoted, for "nothing changed" checks. */
fun SqlDriver.dump(): Map<String, List<String?>> = tables().associateWith { table ->
    val names = strings("SELECT name FROM pragma_table_info('$table')").filterNotNull()
    strings("SELECT ${names.joinToString(" || '|' || ") { "quote(\"$it\")" }} FROM \"$table\" ORDER BY 1")
}

/**
 * A [dump] of a database from before schema version 16 as migration leaves
 * it: the storage_encryption row gained an empty migration_intent (S1).
 */
fun Map<String, List<String?>>.withEmptyMigrationIntent(): Map<String, List<String?>> {
    val row = get("storage_encryption") ?: return this
    return this + ("storage_encryption" to row.map { "$it|NULL" })
}

/**
 * A [dump] of a database from before schema version 10 as migration leaves
 * it: every remote identity pin gained `verification` 0 (unverified).
 */
fun Map<String, List<String?>>.withUnverifiedPins(): Map<String, List<String?>> {
    val pins = get("remote_identity") ?: return this
    return this + ("remote_identity" to pins.map { "$it|0" })
}

/**
 * Removes what schema version 15 (milestone 22, 14.sqm) added, for tests that
 * turn a new database into an older one: the pending outbound recipient index.
 */
fun SqlDriver.dropVersion15Additions() {
    dropVersion16Additions()
    exec("DROP INDEX pending_outbound_message_recipient")
}

/**
 * Removes what schema version 16 (S1, 15.sqm) added, for tests that turn a
 * new database into an older one: the storage encryption migration intent.
 */
fun SqlDriver.dropVersion16Additions() {
    exec("ALTER TABLE storage_encryption DROP COLUMN migration_intent")
}

/**
 * Removes what schema versions 14 (milestone 21, 13.sqm) and 15 added, for
 * tests that turn a new database into an older one: the processed
 * finalization and discard reason and the pending inbound sender index (after
 * [dropVersion15Additions]). `discard_reason` goes first: its CHECK
 * constraint names `finalization`.
 */
fun SqlDriver.dropVersion14Additions() {
    dropVersion15Additions()
    exec("DROP INDEX pending_inbound_message_sender")
    exec("ALTER TABLE processed_inbound_message DROP COLUMN discard_reason")
    exec("ALTER TABLE processed_inbound_message DROP COLUMN finalization")
}

/**
 * Removes what schema versions 13 (milestone 20, 12.sqm) and 14 added, for
 * tests that turn a new database into an older one: the pending inbound
 * table and the processed commit time and digest (after
 * [dropVersion14Additions]).
 */
fun SqlDriver.dropVersion13Additions() {
    dropVersion14Additions()
    exec("DROP TABLE pending_inbound_message")
    exec("DELETE FROM sqlite_sequence WHERE name = 'pending_inbound_message'")
    exec("DROP INDEX processed_inbound_message_committed_at")
    exec("ALTER TABLE processed_inbound_message DROP COLUMN sealed_digest")
    exec("ALTER TABLE processed_inbound_message DROP COLUMN committed_at")
}

/**
 * A [dump] of a database from before schema version 13 as migration leaves
 * it: every processed message ID gained a `NULL` commit time and digest, and
 * (schema version 14) finalization 0 (committed) without a discard reason.
 */
fun Map<String, List<String?>>.withLegacyProcessedMessages(): Map<String, List<String?>> {
    val processed = get("processed_inbound_message") ?: return this
    return this + ("processed_inbound_message" to processed.map { "$it|NULL|NULL|0|NULL" }) + ("pending_inbound_message" to emptyList())
}

/**
 * A [dump] of a schema version 13 database as migration leaves it: every
 * processed message ID gained finalization 0 (committed) without a discard
 * reason.
 */
fun Map<String, List<String?>>.withCommittedFinalization(): Map<String, List<String?>> {
    val processed = get("processed_inbound_message") ?: return this
    return this + ("processed_inbound_message" to processed.map { "$it|0|NULL" })
}

fun ByteArray.toHex(): String = joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }

fun ByteArray.flipped(index: Int): ByteArray = copyOf().also { it[index] = (it[index].toInt() xor 0x01).toByte() }

/** The storage record header magic "KSMR". */
val SEALED_MAGIC: ByteArray = "KSMR".encodeToByteArray()

fun ByteArray.isSealed(): Boolean = size > 4 && copyOfRange(0, 4).contentEquals(SEALED_MAGIC)
