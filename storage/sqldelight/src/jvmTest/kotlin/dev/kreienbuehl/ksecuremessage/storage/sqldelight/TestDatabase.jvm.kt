package dev.kreienbuehl.ksecuremessage.storage.sqldelight

import app.cash.sqldelight.async.coroutines.synchronous
import app.cash.sqldelight.db.SqlDriver
import app.cash.sqldelight.driver.jdbc.sqlite.JdbcSqliteDriver
import java.io.File
import java.util.Properties

private fun file(name: String) = File(System.getProperty("java.io.tmpdir"), name)

actual fun openTestDriver(name: String): SqlDriver =
    JdbcSqliteDriver("jdbc:sqlite:${file(name).absolutePath}", Properties(), SqlDelightClientStorage.Schema.synchronous())

actual fun deleteTestDatabase(name: String) {
    file(name).delete()
}
