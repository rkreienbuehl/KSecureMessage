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
 * A [dump] of a database from before schema version 10 as migration leaves
 * it: every remote identity pin gained `verification` 0 (unverified).
 */
fun Map<String, List<String?>>.withUnverifiedPins(): Map<String, List<String?>> {
    val pins = get("remote_identity") ?: return this
    return this + ("remote_identity" to pins.map { "$it|0" })
}

fun ByteArray.toHex(): String = joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }

fun ByteArray.flipped(index: Int): ByteArray = copyOf().also { it[index] = (it[index].toInt() xor 0x01).toByte() }

/** The storage record header magic "KSMR". */
val SEALED_MAGIC: ByteArray = "KSMR".encodeToByteArray()

fun ByteArray.isSealed(): Boolean = size > 4 && copyOfRange(0, 4).contentEquals(SEALED_MAGIC)
