package dev.kreienbuehl.ksecuremessage.storage.client.sqldelight

import app.cash.sqldelight.db.AfterVersion
import app.cash.sqldelight.db.QueryResult
import app.cash.sqldelight.db.SqlDriver
import app.cash.sqldelight.db.SqlSchema

/**
 * The database schema as shipped with milestones 9 and 10 (schema version 6:
 * record-level encryption with one bound storage key, no storage key
 * rotation state). Frozen copy for migration tests.
 */
object Version6Schema : SqlSchema<QueryResult.Value<Unit>> {
    override val version: Long = 6

    private val statements = listOf(
        """
        CREATE TABLE storage_encryption (
            id INTEGER NOT NULL PRIMARY KEY CHECK (id = 0),
            format INTEGER NOT NULL,
            key_id INTEGER,
            key_check BLOB
        )
        """,
        "INSERT INTO storage_encryption (id, format) VALUES (0, 1)",
        """
        CREATE TABLE local_identity (
            id INTEGER NOT NULL PRIMARY KEY CHECK (id = 0),
            sealed_identity BLOB NOT NULL
        )
        """,
        """
        CREATE TABLE signed_pre_key (
            id INTEGER NOT NULL PRIMARY KEY CHECK (id BETWEEN 0 AND 2147483647),
            sealed_key_pair BLOB NOT NULL,
            created_at INTEGER,
            replaced_at INTEGER
        )
        """,
        """
        CREATE TABLE one_time_pre_key (
            id INTEGER NOT NULL PRIMARY KEY CHECK (id BETWEEN 0 AND 2147483647),
            sealed_key_pair BLOB NOT NULL
        )
        """,
        """
        CREATE TABLE pre_key_state (
            id INTEGER NOT NULL PRIMARY KEY CHECK (id = 0),
            current_signed_pre_key_id INTEGER REFERENCES signed_pre_key(id),
            highest_signed_pre_key_id INTEGER,
            highest_one_time_pre_key_id INTEGER
        )
        """,
        "INSERT INTO pre_key_state (id) VALUES (0)",
        """
        CREATE TABLE session (
            remote_user_id TEXT NOT NULL,
            remote_device_id TEXT NOT NULL,
            sealed_state BLOB NOT NULL,
            PRIMARY KEY (remote_user_id, remote_device_id)
        )
        """,
        """
        CREATE TABLE remote_identity (
            remote_user_id TEXT NOT NULL,
            remote_device_id TEXT NOT NULL,
            identity_key BLOB NOT NULL,
            PRIMARY KEY (remote_user_id, remote_device_id)
        )
        """,
        """
        CREATE TABLE retired_session_initiation (
            remote_user_id TEXT NOT NULL,
            remote_device_id TEXT NOT NULL,
            initiation_id BLOB NOT NULL CHECK (length(initiation_id) = 32),
            signed_pre_key_id INTEGER,
            PRIMARY KEY (remote_user_id, remote_device_id, initiation_id)
        )
        """,
        """
        CREATE TABLE pending_outbound_message (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient_user_id TEXT NOT NULL,
            recipient_device_id TEXT NOT NULL,
            message_id BLOB NOT NULL CHECK (length(message_id) = 16),
            sealed_frame BLOB NOT NULL,
            UNIQUE (recipient_user_id, recipient_device_id, message_id)
        )
        """,
        """
        CREATE TABLE processed_inbound_message (
            sender_user_id TEXT NOT NULL,
            sender_device_id TEXT NOT NULL,
            message_id BLOB NOT NULL CHECK (length(message_id) = 16),
            PRIMARY KEY (sender_user_id, sender_device_id, message_id)
        )
        """,
    )

    override fun create(driver: SqlDriver): QueryResult.Value<Unit> {
        statements.forEach { driver.execute(null, it.trimIndent(), 0) }
        return QueryResult.Unit
    }

    override fun migrate(
        driver: SqlDriver,
        oldVersion: Long,
        newVersion: Long,
        vararg callbacks: AfterVersion,
    ): QueryResult.Value<Unit> = QueryResult.Unit
}
