package dev.kreienbuehl.ksecuremessage.storage.sqldelight

import app.cash.sqldelight.db.QueryResult
import app.cash.sqldelight.db.SqlDriver
import app.cash.sqldelight.db.SqlSchema
import app.cash.sqldelight.driver.jdbc.sqlite.JdbcSqliteDriver
import java.io.File
import java.util.Properties

private fun file(name: String) = File(System.getProperty("java.io.tmpdir"), name)

actual fun openTestDriver(name: String, schema: SqlSchema<QueryResult.Value<Unit>>): SqlDriver =
    JdbcSqliteDriver("jdbc:sqlite:${file(name).absolutePath}", Properties(), schema)

actual fun deleteTestDatabase(name: String) {
    file(name).delete()
}
