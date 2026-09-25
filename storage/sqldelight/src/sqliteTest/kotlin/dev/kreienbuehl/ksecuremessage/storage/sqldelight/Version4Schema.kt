package dev.kreienbuehl.ksecuremessage.storage.sqldelight

import app.cash.sqldelight.db.AfterVersion
import app.cash.sqldelight.db.QueryResult
import app.cash.sqldelight.db.SqlDriver
import app.cash.sqldelight.db.SqlSchema

/**
 * The database schema as shipped with milestone 7 (schema version 4: version
 * 3 plus the signed prekey lifecycle columns, without the milestone 8
 * reliability tables). Frozen copy for migration tests.
 */
object Version4Schema : SqlSchema<QueryResult.Value<Unit>> {
    override val version: Long = 4

    override fun create(driver: SqlDriver): QueryResult.Value<Unit> {
        Version3Schema.create(driver)
        driver.execute(null, "ALTER TABLE signed_pre_key ADD COLUMN created_at INTEGER", 0)
        driver.execute(null, "ALTER TABLE signed_pre_key ADD COLUMN replaced_at INTEGER", 0)
        driver.execute(null, "ALTER TABLE retired_session_initiation ADD COLUMN signed_pre_key_id INTEGER", 0)
        return QueryResult.Unit
    }

    override fun migrate(
        driver: SqlDriver,
        oldVersion: Long,
        newVersion: Long,
        vararg callbacks: AfterVersion,
    ): QueryResult.Value<Unit> = QueryResult.Unit
}
