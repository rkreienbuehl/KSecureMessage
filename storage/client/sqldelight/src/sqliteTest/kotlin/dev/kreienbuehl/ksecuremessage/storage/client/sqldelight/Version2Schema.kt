package dev.kreienbuehl.ksecuremessage.storage.client.sqldelight

import app.cash.sqldelight.db.AfterVersion
import app.cash.sqldelight.db.QueryResult
import app.cash.sqldelight.db.SqlDriver
import app.cash.sqldelight.db.SqlSchema

/**
 * The database schema as shipped with milestone 5 (schema version 2: version
 * 1 plus `remote_identity`, without `retired_session_initiation`). Frozen
 * copy for migration tests.
 */
object Version2Schema : SqlSchema<QueryResult.Value<Unit>> {
    override val version: Long = 2

    override fun create(driver: SqlDriver): QueryResult.Value<Unit> {
        Version1Schema.create(driver)
        driver.execute(
            null,
            """
            CREATE TABLE remote_identity (
                remote_user_id TEXT NOT NULL,
                remote_device_id TEXT NOT NULL,
                identity_key BLOB NOT NULL,
                PRIMARY KEY (remote_user_id, remote_device_id)
            )
            """.trimIndent(),
            0,
        )
        return QueryResult.Unit
    }

    override fun migrate(
        driver: SqlDriver,
        oldVersion: Long,
        newVersion: Long,
        vararg callbacks: AfterVersion,
    ): QueryResult.Value<Unit> = QueryResult.Unit
}
