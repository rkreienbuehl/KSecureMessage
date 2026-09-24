package dev.kreienbuehl.ksecuremessage.storage.sqldelight

import app.cash.sqldelight.db.QueryResult
import app.cash.sqldelight.db.SqlDriver
import app.cash.sqldelight.db.SqlSchema
import app.cash.sqldelight.driver.native.NativeSqliteDriver
import co.touchlab.sqliter.DatabaseFileContext

actual fun openTestDriver(name: String, schema: SqlSchema<QueryResult.Value<Unit>>): SqlDriver =
    NativeSqliteDriver(schema, name)

actual fun deleteTestDatabase(name: String) {
    DatabaseFileContext.deleteDatabase(name)
}
