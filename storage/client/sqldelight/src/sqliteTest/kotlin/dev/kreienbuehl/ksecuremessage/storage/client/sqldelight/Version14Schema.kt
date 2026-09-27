package dev.kreienbuehl.ksecuremessage.storage.client.sqldelight

import app.cash.sqldelight.db.AfterVersion
import app.cash.sqldelight.db.QueryResult
import app.cash.sqldelight.db.SqlDriver
import app.cash.sqldelight.db.SqlSchema

/**
 * The database schema as shipped with milestone 21 (schema version 14:
 * version 13 plus the processed finalization and discard reason and the
 * pending inbound sender pagination index; no pending outbound recipient
 * pagination index). Frozen copy for migration tests.
 */
object Version14Schema : SqlSchema<QueryResult.Value<Unit>> {
    override val version: Long = 14

    private val statements = listOf(
        """
        CREATE TABLE storage_encryption (
            id INTEGER NOT NULL PRIMARY KEY CHECK (id = 0),
            format INTEGER NOT NULL,
            key_id INTEGER,
            key_check BLOB,
            highest_key_id INTEGER,
            rotation_phase INTEGER NOT NULL DEFAULT 0,
            next_key_id INTEGER,
            retiring_key_id INTEGER,
            retiring_key_check BLOB
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
            verification INTEGER NOT NULL DEFAULT 0 CHECK (verification IN (0, 1)),
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
            committed_at INTEGER,
            sealed_digest BLOB,
            finalization INTEGER NOT NULL DEFAULT 0 CHECK (finalization IN (0, 1)),
            discard_reason INTEGER
                CHECK ((finalization = 0 AND discard_reason IS NULL) OR (finalization = 1 AND discard_reason IS NOT NULL AND discard_reason BETWEEN 1 AND 5)),
            PRIMARY KEY (sender_user_id, sender_device_id, message_id)
        )
        """,
        """
        CREATE INDEX processed_inbound_message_committed_at ON processed_inbound_message (committed_at)
        """,
        """
        CREATE TABLE pending_inbound_message (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_user_id TEXT NOT NULL,
            sender_device_id TEXT NOT NULL,
            message_id BLOB NOT NULL CHECK (length(message_id) = 16),
            received_at INTEGER NOT NULL,
            sealed_frame BLOB NOT NULL,
            UNIQUE (sender_user_id, sender_device_id, message_id)
        )
        """,
        """
        CREATE INDEX pending_inbound_message_sender ON pending_inbound_message (sender_user_id, sender_device_id, sequence)
        """,
        """
        CREATE TABLE device_authentication_key (
            id INTEGER NOT NULL PRIMARY KEY CHECK (id = 0),
            sealed_key_pair BLOB NOT NULL
        )
        """,
        """
        CREATE TABLE device_authentication_state (
            id INTEGER NOT NULL PRIMARY KEY CHECK (id = 0),
            awaits_upgrade_key INTEGER NOT NULL
        )
        """,
        "INSERT INTO device_authentication_state (id, awaits_upgrade_key) VALUES (0, 0)",
        """
        CREATE TABLE device_authentication_recovery_key (
            id INTEGER NOT NULL PRIMARY KEY CHECK (id = 0),
            sealed_key_pair BLOB NOT NULL
        )
        """,
        """
        CREATE TABLE device_authentication_rotation_key (
            id INTEGER NOT NULL PRIMARY KEY CHECK (id = 0),
            sealed_key_pair BLOB NOT NULL
        )
        """,
        """
        CREATE TABLE device_authentication_last_device_recovery_key (
            id INTEGER NOT NULL PRIMARY KEY CHECK (id = 0),
            sealed_key_pair BLOB NOT NULL
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
