package dev.kreienbuehl.ksecuremessage.storage.server.sqldelight

import app.cash.sqldelight.db.AfterVersion
import app.cash.sqldelight.db.QueryResult
import app.cash.sqldelight.db.SqlDriver
import app.cash.sqldelight.db.SqlSchema

/**
 * The server database schema as shipped with milestones 19 to 22 (server
 * schema version 6: registrations with epoch, recovery, rotation and
 * last-device recovery IDs and key installation time; the per-user recovery
 * key state with epoch, ACTIVE/REVOKED and rotation/revocation IDs; per-device
 * challenges bound to a recovery key epoch; no pending recovery key reset).
 * Frozen copy for migration tests.
 */
object ServerVersion6Schema : SqlSchema<QueryResult.Value<Unit>> {
    override val version: Long = 6

    private val statements = listOf(
        """
        CREATE TABLE server_storage (
            id INTEGER NOT NULL PRIMARY KEY CHECK (id = 0),
            format INTEGER NOT NULL
        )
        """,
        "INSERT INTO server_storage (id, format) VALUES (0, 6)",
        """
        CREATE TABLE device_registration (
            user_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            auth_public_key BLOB NOT NULL,
            auth_epoch INTEGER NOT NULL DEFAULT 1,
            recovery_id BLOB,
            rotation_id BLOB,
            auth_key_installed_at INTEGER,
            last_device_recovery_id BLOB,
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
        CREATE TABLE last_device_recovery_key_state (
            user_id TEXT NOT NULL PRIMARY KEY,
            state INTEGER NOT NULL CHECK (state IN (1, 2)),
            epoch INTEGER NOT NULL CHECK (epoch >= 1),
            public_key BLOB,
            installed_at INTEGER,
            transitioned_at INTEGER NOT NULL,
            rotation_id BLOB,
            revocation_id BLOB,
            CHECK ((state = 1 AND public_key IS NOT NULL AND installed_at IS NOT NULL AND revocation_id IS NULL) OR
                   (state = 2 AND public_key IS NULL AND installed_at IS NULL AND rotation_id IS NULL))
        )
        """,
        """
        CREATE TABLE last_device_recovery_challenge (
            user_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            challenge_id BLOB NOT NULL UNIQUE,
            challenge_nonce BLOB NOT NULL,
            auth_epoch INTEGER NOT NULL,
            auth_public_key BLOB NOT NULL,
            issued_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            recovery_key_epoch INTEGER NOT NULL DEFAULT 1,
            PRIMARY KEY (user_id, device_id)
        )
        """,
        "CREATE INDEX last_device_recovery_challenge_expiry ON last_device_recovery_challenge (expires_at)",
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
