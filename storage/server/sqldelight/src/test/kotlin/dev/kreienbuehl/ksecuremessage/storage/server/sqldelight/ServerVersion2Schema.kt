package dev.kreienbuehl.ksecuremessage.storage.server.sqldelight

import app.cash.sqldelight.db.AfterVersion
import app.cash.sqldelight.db.QueryResult
import app.cash.sqldelight.db.SqlDriver
import app.cash.sqldelight.db.SqlSchema

/**
 * The server database schema as shipped with milestones 14 and 15 (server
 * schema version 2: registrations with epoch and recovery ID, no rotation
 * ID). Frozen copy for migration tests.
 */
object ServerVersion2Schema : SqlSchema<QueryResult.Value<Unit>> {
    override val version: Long = 2

    private val statements = listOf(
        """
        CREATE TABLE server_storage (
            id INTEGER NOT NULL PRIMARY KEY CHECK (id = 0),
            format INTEGER NOT NULL
        )
        """,
        "INSERT INTO server_storage (id, format) VALUES (0, 2)",
        """
        CREATE TABLE device_registration (
            user_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            auth_public_key BLOB NOT NULL,
            auth_epoch INTEGER NOT NULL DEFAULT 1,
            recovery_id BLOB,
            PRIMARY KEY (user_id, device_id)
        )
        """,
        """
        CREATE TABLE authentication_nonce (
            user_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            nonce BLOB NOT NULL,
            request_timestamp INTEGER NOT NULL,
            PRIMARY KEY (user_id, device_id, nonce)
        )
        """,
        "CREATE INDEX authentication_nonce_timestamp ON authentication_nonce (request_timestamp)",
        """
        CREATE TABLE device_prekey_state (
            user_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            identity_key BLOB NOT NULL,
            signed_pre_key_id INTEGER NOT NULL,
            signed_pre_key BLOB NOT NULL,
            signed_pre_key_signature BLOB NOT NULL,
            PRIMARY KEY (user_id, device_id)
        )
        """,
        """
        CREATE TABLE available_one_time_prekey (
            user_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            pre_key_id INTEGER NOT NULL,
            public_key BLOB NOT NULL,
            PRIMARY KEY (user_id, device_id, pre_key_id)
        )
        """,
        """
        CREATE TABLE consumed_one_time_prekey (
            user_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            pre_key_id INTEGER NOT NULL,
            PRIMARY KEY (user_id, device_id, pre_key_id)
        )
        """,
        """
        CREATE TABLE mailbox_message (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_user_id TEXT NOT NULL,
            sender_device_id TEXT NOT NULL,
            recipient_user_id TEXT NOT NULL,
            recipient_device_id TEXT NOT NULL,
            envelope_id TEXT NOT NULL,
            protocol_version INTEGER NOT NULL,
            payload BLOB NOT NULL
        )
        """,
        "CREATE INDEX mailbox_message_recipient ON mailbox_message (recipient_user_id, recipient_device_id, sequence)",
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
