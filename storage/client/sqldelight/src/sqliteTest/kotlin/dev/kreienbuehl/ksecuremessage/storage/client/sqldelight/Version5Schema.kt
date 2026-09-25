package dev.kreienbuehl.ksecuremessage.storage.client.sqldelight

import app.cash.sqldelight.db.AfterVersion
import app.cash.sqldelight.db.QueryResult
import app.cash.sqldelight.db.SqlDriver
import app.cash.sqldelight.db.SqlSchema

/**
 * The database schema as shipped with milestone 8 (schema version 5: version
 * 4 plus the reliability tables, without record encryption). Key pairs,
 * session state and pending frames are plaintext BLOBs. Frozen copy for
 * migration tests.
 */
object Version5Schema : SqlSchema<QueryResult.Value<Unit>> {
    override val version: Long = 5

    override fun create(driver: SqlDriver): QueryResult.Value<Unit> {
        Version4Schema.create(driver)
        driver.execute(
            null,
            """
            CREATE TABLE pending_outbound_message (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                recipient_user_id TEXT NOT NULL,
                recipient_device_id TEXT NOT NULL,
                message_id BLOB NOT NULL CHECK (length(message_id) = 16),
                frame BLOB NOT NULL,
                UNIQUE (recipient_user_id, recipient_device_id, message_id)
            )
            """.trimIndent(),
            0,
        )
        driver.execute(
            null,
            """
            CREATE TABLE processed_inbound_message (
                sender_user_id TEXT NOT NULL,
                sender_device_id TEXT NOT NULL,
                message_id BLOB NOT NULL CHECK (length(message_id) = 16),
                PRIMARY KEY (sender_user_id, sender_device_id, message_id)
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
