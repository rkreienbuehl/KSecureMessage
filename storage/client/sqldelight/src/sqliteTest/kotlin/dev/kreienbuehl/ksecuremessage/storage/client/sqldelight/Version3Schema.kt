package dev.kreienbuehl.ksecuremessage.storage.client.sqldelight

import app.cash.sqldelight.db.AfterVersion
import app.cash.sqldelight.db.QueryResult
import app.cash.sqldelight.db.SqlDriver
import app.cash.sqldelight.db.SqlSchema

/**
 * The database schema as shipped with milestone 6 (schema version 3: version
 * 2 plus `retired_session_initiation`, without the milestone 7 lifecycle
 * columns). Frozen copy for migration tests.
 */
object Version3Schema : SqlSchema<QueryResult.Value<Unit>> {
    override val version: Long = 3

    override fun create(driver: SqlDriver): QueryResult.Value<Unit> {
        Version2Schema.create(driver)
        driver.execute(
            null,
            """
            CREATE TABLE retired_session_initiation (
                remote_user_id TEXT NOT NULL,
                remote_device_id TEXT NOT NULL,
                initiation_id BLOB NOT NULL CHECK (length(initiation_id) = 32),
                PRIMARY KEY (remote_user_id, remote_device_id, initiation_id)
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
