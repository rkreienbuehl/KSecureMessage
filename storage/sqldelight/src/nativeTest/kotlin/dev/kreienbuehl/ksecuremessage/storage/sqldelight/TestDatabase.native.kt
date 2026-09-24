package dev.kreienbuehl.ksecuremessage.storage.sqldelight

import app.cash.sqldelight.async.coroutines.synchronous
import app.cash.sqldelight.db.SqlDriver
import app.cash.sqldelight.driver.native.NativeSqliteDriver
import co.touchlab.sqliter.DatabaseFileContext

actual fun openTestDriver(name: String): SqlDriver = NativeSqliteDriver(SqlDelightClientStorage.Schema.synchronous(), name)

actual fun deleteTestDatabase(name: String) {
    DatabaseFileContext.deleteDatabase(name)
}
