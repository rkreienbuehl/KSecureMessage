package dev.kreienbuehl.ksecuremessage.storage.sqldelight

import androidx.sqlite.db.SupportSQLiteDatabase
import androidx.test.platform.app.InstrumentationRegistry
import app.cash.sqldelight.db.QueryResult
import app.cash.sqldelight.db.SqlDriver
import app.cash.sqldelight.db.SqlSchema
import app.cash.sqldelight.driver.android.AndroidSqliteDriver

private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

actual fun openTestDriver(name: String, schema: SqlSchema<QueryResult.Value<Unit>>, foreignKeys: Boolean): SqlDriver =
    AndroidSqliteDriver(
        schema,
        context,
        name,
        callback = object : AndroidSqliteDriver.Callback(schema) {
            override fun onConfigure(db: SupportSQLiteDatabase) {
                db.setForeignKeyConstraintsEnabled(foreignKeys)
            }
        },
    )

actual fun deleteTestDatabase(name: String) {
    context.deleteDatabase(name)
}
