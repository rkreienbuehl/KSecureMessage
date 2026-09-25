package dev.kreienbuehl.ksecuremessage.storage.sqldelight

import app.cash.sqldelight.async.coroutines.synchronous
import app.cash.sqldelight.db.QueryResult
import app.cash.sqldelight.db.SqlDriver
import app.cash.sqldelight.db.SqlSchema
import kotlin.random.Random

/**
 * Opens the database file [name], creating it with [schema] if needed, or
 * migrating it to [schema]'s version. [foreignKeys] turns on SQLite's foreign
 * key enforcement for the connection.
 */
expect fun openTestDriver(
    name: String,
    schema: SqlSchema<QueryResult.Value<Unit>> = SqlDelightClientStorage.Schema.synchronous(),
    foreignKeys: Boolean = false,
): SqlDriver

expect fun deleteTestDatabase(name: String)

/** A database file per test, opened and closed as often as needed, deleted by [close]. */
class TestDatabase : AutoCloseable {
    private val name = "ksecuremessage-test-${Random.nextLong().toULong()}.db"
    private val drivers = mutableListOf<SqlDriver>()

    init {
        deleteTestDatabase(name)
    }

    fun open(): SqlDriver = openTestDriver(name).also { drivers += it }

    fun open(schema: SqlSchema<QueryResult.Value<Unit>>): SqlDriver = openTestDriver(name, schema).also { drivers += it }

    fun openWithForeignKeys(): SqlDriver = openTestDriver(name, foreignKeys = true).also { drivers += it }

    fun closeOpenDrivers() {
        drivers.forEach { it.close() }
        drivers.clear()
    }

    override fun close() {
        closeOpenDrivers()
        deleteTestDatabase(name)
    }
}
