package dev.kreienbuehl.ksecuremessage.storage.sqldelight

import app.cash.sqldelight.db.AfterVersion
import app.cash.sqldelight.db.QueryResult
import app.cash.sqldelight.db.SqlDriver
import app.cash.sqldelight.db.SqlSchema

/**
 * The database schema as shipped before milestone 5 (schema version 1,
 * without `remote_identity`). Frozen copy for migration tests.
 */
object Version1Schema : SqlSchema<QueryResult.Value<Unit>> {
    override val version: Long = 1

    private val statements = listOf(
        """
        CREATE TABLE local_identity (
            id INTEGER NOT NULL PRIMARY KEY CHECK (id = 0),
            public_key BLOB NOT NULL,
            private_key BLOB NOT NULL
        )
        """,
        """
        CREATE TABLE signed_pre_key (
            id INTEGER NOT NULL PRIMARY KEY CHECK (id BETWEEN 0 AND 2147483647),
            public_key BLOB NOT NULL,
            signature BLOB NOT NULL,
            private_key BLOB NOT NULL
        )
        """,
        """
        CREATE TABLE one_time_pre_key (
            id INTEGER NOT NULL PRIMARY KEY CHECK (id BETWEEN 0 AND 2147483647),
            public_key BLOB NOT NULL,
            private_key BLOB NOT NULL
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
            state BLOB NOT NULL,
            PRIMARY KEY (remote_user_id, remote_device_id)
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
