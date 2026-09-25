package dev.kreienbuehl.ksecuremessage.storage.server.sqldelight

import app.cash.sqldelight.db.QueryResult
import app.cash.sqldelight.db.SqlDriver
import app.cash.sqldelight.db.SqlPreparedStatement
import app.cash.sqldelight.driver.jdbc.sqlite.JdbcSqliteDriver
import java.nio.file.Files
import java.nio.file.Path
import java.util.Properties
import kotlin.io.path.deleteIfExists

/** A new in-memory SQLite database with the server schema. One connection, lives until closed. */
internal fun inMemoryDriver(): SqlDriver = JdbcSqliteDriver(JdbcSqliteDriver.IN_MEMORY, Properties(), SqlDelightServerStorage.Schema)

/**
 * A file-backed SQLite database in a fresh temporary file. [driver] opens a
 * new driver (new connections) on the same file each time, so closing one and
 * opening another is a real restart of the database.
 */
internal class TempDatabase : AutoCloseable {
    val path: Path = Files.createTempFile("ksm-server-", ".db")
    private val drivers = mutableListOf<SqlDriver>()

    fun driver(): SqlDriver =
        JdbcSqliteDriver("jdbc:sqlite:${path.toAbsolutePath()}", Properties(), SqlDelightServerStorage.Schema).also { drivers += it }

    override fun close() {
        drivers.forEach { it.close() }
        listOf("", "-journal", "-wal", "-shm").forEach { Path.of("$path$it").deleteIfExists() }
    }
}

/**
 * Delegating driver for failure injection and for proving that the storage
 * uses the driver it was given. A [fault] makes the next statement whose SQL
 * matches fail, either before or after it ran; it fires once.
 */
internal class TestDriver(private val delegate: SqlDriver) : SqlDriver by delegate {
    class Fault(val matches: (String) -> Boolean, val afterExecution: Boolean)

    var fault: Fault? = null
    var statements = 0
        private set

    /** Fails the next statement containing [sql] before it runs. */
    fun failBefore(sql: String) {
        fault = Fault({ sql in it }, afterExecution = false)
    }

    /** Runs the next statement containing [sql], then fails, still inside its transaction. */
    fun failAfter(sql: String) {
        fault = Fault({ sql in it }, afterExecution = true)
    }

    override fun execute(identifier: Int?, sql: String, parameters: Int, binders: (SqlPreparedStatement.() -> Unit)?): QueryResult<Long> {
        statements++
        val fault = fault?.takeIf { it.matches(sql) }
        if (fault != null && !fault.afterExecution) fire()
        val result = delegate.execute(identifier, sql, parameters, binders)
        if (fault != null) fire()
        return result
    }

    override fun <R> executeQuery(
        identifier: Int?,
        sql: String,
        mapper: (app.cash.sqldelight.db.SqlCursor) -> QueryResult<R>,
        parameters: Int,
        binders: (SqlPreparedStatement.() -> Unit)?,
    ): QueryResult<R> {
        statements++
        return delegate.executeQuery(identifier, sql, mapper, parameters, binders)
    }

    private fun fire(): Nothing {
        fault = null
        throw InjectedFailure()
    }
}

internal class InjectedFailure : RuntimeException("injected failure")

/** Runs a single-value `SELECT count(*) ...` directly on [driver]. */
internal fun SqlDriver.count(sql: String): Long =
    executeQuery(null, sql, { cursor -> cursor.next(); QueryResult.Value(cursor.getLong(0)!!) }, 0).value
