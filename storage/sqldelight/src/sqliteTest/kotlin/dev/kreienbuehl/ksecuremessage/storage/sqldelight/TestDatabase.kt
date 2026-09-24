package dev.kreienbuehl.ksecuremessage.storage.sqldelight

import app.cash.sqldelight.db.SqlDriver
import kotlin.random.Random

/** Opens the database file [name], creating it with the schema if needed. */
expect fun openTestDriver(name: String): SqlDriver

expect fun deleteTestDatabase(name: String)

/** A database file per test, opened and closed as often as needed, deleted by [close]. */
class TestDatabase : AutoCloseable {
    private val name = "ksecuremessage-test-${Random.nextLong().toULong()}.db"
    private val drivers = mutableListOf<SqlDriver>()

    init {
        deleteTestDatabase(name)
    }

    fun open(): SqlDriver = openTestDriver(name).also { drivers += it }

    fun closeOpenDrivers() {
        drivers.forEach { it.close() }
        drivers.clear()
    }

    override fun close() {
        closeOpenDrivers()
        deleteTestDatabase(name)
    }
}
