package dev.kreienbuehl.ksecuremessage.storage.server.sqldelight

import app.cash.sqldelight.db.QueryResult
import app.cash.sqldelight.db.SqlDriver
import app.cash.sqldelight.driver.jdbc.sqlite.JdbcSqliteDriver
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.DeviceRegistration
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.MessageId
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication
import dev.kreienbuehl.ksecuremessage.model.PublicOneTimePreKey
import dev.kreienbuehl.ksecuremessage.model.PublicSignedPreKey
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecoveryId
import dev.kreienbuehl.ksecuremessage.protocol.RequestNonce
import dev.kreienbuehl.ksecuremessage.storage.RecoveryReplacement
import dev.kreienbuehl.ksecuremessage.storage.RecoveryReplacementResult
import kotlinx.coroutines.test.runTest
import java.util.Properties
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/**
 * Server schema version 1 (milestone 13) to 2 (milestone 14, 1.sqm): every
 * row is kept, registrations get epoch 1 and no recovery ID, and the
 * migrated schema equals a new one.
 */
class SqlDelightServerMigrationTest {
    private val database = TempDatabase()
    private val drivers = mutableListOf<SqlDriver>()

    private val alice = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val laptop = DeviceAddress(UserId("alice"), DeviceId("laptop"))
    private val bob = DeviceAddress(UserId("bob"), DeviceId("laptop"))
    private val t0 = Instant.fromEpochMilliseconds(1_767_225_600_000)

    private fun key(seed: Int) = ByteArray(32) { (seed * 7 + it).toByte() }

    private fun open(schema: app.cash.sqldelight.db.SqlSchema<QueryResult.Value<Unit>>): SqlDriver =
        JdbcSqliteDriver("jdbc:sqlite:${database.path.toAbsolutePath()}", Properties(), schema).also { drivers += it }

    @AfterTest
    fun cleanUp() {
        drivers.forEach { it.close() }
        database.close()
    }

    /** A milestone 13 database with a row in every table, written through the version 1 schema. */
    private fun version1Database(): Map<String, List<String>> {
        val old = open(ServerVersion1Schema)
        old.exec("INSERT INTO device_registration VALUES ('alice', 'phone', ?)", key(1))
        old.exec("INSERT INTO device_registration VALUES ('alice', 'laptop', ?)", key(2))
        old.exec("INSERT INTO authentication_nonce VALUES ('alice', 'phone', ?, ${t0.toEpochMilliseconds()})", ByteArray(16) { 9 })
        old.exec("INSERT INTO device_prekey_state VALUES ('bob', 'laptop', ?, 1, ?, ?)", key(3), key(4), ByteArray(64) { 5 })
        old.exec("INSERT INTO available_one_time_prekey VALUES ('bob', 'laptop', 2, ?)", key(6))
        old.exec("INSERT INTO consumed_one_time_prekey VALUES ('bob', 'laptop', 1)")
        for (sequence in 1..3) {
            old.exec("INSERT INTO mailbox_message (sender_user_id, sender_device_id, recipient_user_id, recipient_device_id, envelope_id, protocol_version, payload) VALUES ('alice', 'phone', 'bob', 'laptop', 'm$sequence', 1, ?)", byteArrayOf(sequence.toByte()))
        }
        old.exec("DELETE FROM mailbox_message WHERE sequence = 3") // drained: its sequence is never reused
        val before = old.dump()
        old.close()
        drivers -= old
        return before
    }

    @Test
    fun driverWithTheSchemaMigratesAndKeepsEveryRow() = runTest {
        val before = version1Database()
        val driver = open(SqlDelightServerStorage.Schema)
        assertEquals(listOf(2L), driver.longs("PRAGMA user_version"))
        val after = driver.dump()

        assertEquals(before - "device_registration" - "server_storage", after - "device_registration" - "server_storage")
        assertEquals(listOf("0|2"), after.getValue("server_storage"))
        assertEquals(before.getValue("device_registration").map { "$it|1|NULL" }, after.getValue("device_registration"))

        val storage = SqlDelightServerStorage.open(driver)
        val state = assertNotNull(storage.devices.registrationState(alice))
        assertEquals(1, state.authEpoch)
        assertNull(state.recoveryId)
        assertContentEquals(key(1), state.registration.publicKey)
        assertFalse(storage.authenticationNonces.claim(alice, ByteArray(16) { 9 }, t0, t0 - 5.minutes), "nonce kept")
        assertEquals(1, storage.preKeys.oneTimePreKeyCount(bob))
        storage.preKeys.publish(
            PreKeyPublication(bob, key(3), PublicSignedPreKey(SignedPreKeyId(1), key(4), ByteArray(64) { 5 }), listOf(PublicOneTimePreKey(OneTimePreKeyId(1), key(7)))),
        )
        assertEquals(1, storage.preKeys.oneTimePreKeyCount(bob), "tombstone kept")

        storage.mailboxes.enqueue(EncryptedEnvelope(MessageId("m4"), alice, bob, payload = byteArrayOf(4)))
        assertEquals(listOf("m1", "m2", "m4"), storage.mailboxes.drain(bob).map { it.id.value })
        assertEquals(listOf(4L), driver.longs("SELECT seq FROM sqlite_sequence WHERE name = 'mailbox_message'"), "sequence continues")
    }

    @Test
    fun migratedRegistrationsCanBeRecovered() = runTest {
        version1Database()
        val storage = SqlDelightServerStorage.open(open(SqlDelightServerStorage.Schema))
        val replacement = RecoveryReplacement(
            assertNotNull(storage.devices.registrationState(laptop)),
            assertNotNull(storage.devices.registrationState(alice)),
            key(8),
            DeviceRecoveryId(ByteArray(32) { 1 }),
            RequestNonce(ByteArray(16) { 2 }),
            t0,
            t0 - 5.minutes,
        )
        assertEquals(RecoveryReplacementResult.REPLACED, storage.devices.replaceForRecovery(replacement))
        assertEquals(2, storage.devices.registrationState(laptop)?.authEpoch)
    }

    @Test
    fun explicitMigrationByTheHost() = runTest {
        version1Database()
        val driver = open(ServerVersion1Schema)
        assertFailsWith<IllegalStateException> { SqlDelightServerStorage.open(driver) }
        SqlDelightServerStorage.Schema.migrate(driver, 1, SqlDelightServerStorage.Schema.version)
        assertEquals(1, SqlDelightServerStorage.open(driver).devices.registrationState(alice)?.authEpoch)
    }

    @Test
    fun migratedSchemaEqualsNewSchema() {
        version1Database()
        val migrated = open(SqlDelightServerStorage.Schema)
        val fresh = inMemoryDriver().also { drivers += it }
        assertEquals(fresh.schemaShape(), migrated.schemaShape())
        assertEquals(fresh.longs("PRAGMA user_version"), migrated.longs("PRAGMA user_version"))
        assertEquals(fresh.dump().getValue("server_storage"), migrated.dump().getValue("server_storage"))
    }

    @Test
    fun newRegistrationsAfterMigrationStartAtEpochOne() = runTest {
        version1Database()
        val storage = SqlDelightServerStorage.open(open(SqlDelightServerStorage.Schema))
        storage.devices.register(DeviceRegistration(DeviceAddress(UserId("carol"), DeviceId("tablet")), key(9)))
        assertEquals(1, storage.devices.registrationState(DeviceAddress(UserId("carol"), DeviceId("tablet")))?.authEpoch)
    }
}
