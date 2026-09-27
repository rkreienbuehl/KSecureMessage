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
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationRotationId
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecoveryId
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryChallengeId
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryId
import dev.kreienbuehl.ksecuremessage.protocol.RequestNonce
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryChallengeIssue
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryChallengeRequest
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryReplacement
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryReplacementResult
import dev.kreienbuehl.ksecuremessage.storage.RecoveryReplacement
import dev.kreienbuehl.ksecuremessage.storage.RecoveryReplacementResult
import dev.kreienbuehl.ksecuremessage.storage.RotationReplacement
import dev.kreienbuehl.ksecuremessage.storage.RotationReplacementResult
import kotlinx.coroutines.test.runTest
import java.util.Properties
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/**
 * Server schema version 1 (milestone 13), 2 (milestones 14/15, 1.sqm), 3
 * (milestone 16, 2.sqm), 4 (milestone 17, 3.sqm) and 5 (milestone 18, 4.sqm)
 * to 6 (milestone 19, 5.sqm): every row is kept, version 1 registrations get
 * epoch 1 and no recovery ID, older registrations get no rotation ID, every
 * migrated registration gets its key installation time once, from the clock
 * of the first open, no registration gets a last-device recovery ID, the
 * last-device recovery tables start empty before version 5, version 5
 * recovery keys become ACTIVE at recovery key epoch 1 with their
 * registration time as installation time, their challenges are bound to
 * epoch 1, and the migrated schema equals a new one. Version 6 (milestones
 * 19–22) to 7 (milestone 23, 6.sqm): the recovery key state table is rebuilt
 * with every row (no reset completion ID) and the pending reset table starts
 * empty.
 */
class SqlDelightServerMigrationTest {
    private val database = TempDatabase()
    private val drivers = mutableListOf<SqlDriver>()

    private val alice = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val laptop = DeviceAddress(UserId("alice"), DeviceId("laptop"))
    private val bob = DeviceAddress(UserId("bob"), DeviceId("laptop"))
    private val t0 = Instant.fromEpochMilliseconds(1_767_225_600_000)

    /** The server time of the first open after the migration. */
    private val tMigration = t0 + 40.days

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
        assertEquals(listOf(7L), driver.longs("PRAGMA user_version"))
        val after = driver.dump()

        assertEquals(before - "device_registration" - "server_storage" - NEW_TABLES, after - "device_registration" - "server_storage" - NEW_TABLES)
        assertEquals(listOf("0|7"), after.getValue("server_storage"))
        NEW_TABLES.forEach { assertEquals(emptyList(), after.getValue(it), it) }
        assertEquals(before.getValue("device_registration").map { "$it|1|NULL|NULL|NULL|NULL" }, after.getValue("device_registration"))

        val storage = SqlDelightServerStorage.open(driver, clock = fixedClock(tMigration))
        val state = assertNotNull(storage.devices.registrationState(alice))
        assertEquals(1, state.authEpoch)
        assertEquals(tMigration, state.authKeyInstalledAt)
        assertNull(state.recoveryId)
        assertNull(state.rotationId)
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

    /**
     * A milestone 14/15 database: a row in every table, one registration
     * installed by a recovery (epoch 3, recovery ID), written through the
     * version 2 schema.
     */
    private fun version2Database(): Map<String, List<String>> {
        val old = open(ServerVersion2Schema)
        old.exec("INSERT INTO device_registration (user_id, device_id, auth_public_key) VALUES ('alice', 'phone', ?)", key(1))
        old.exec("INSERT INTO device_registration VALUES ('alice', 'laptop', ?, 3, ?)", key(2), ByteArray(32) { 4 })
        old.exec("INSERT INTO authentication_nonce VALUES ('alice', 'laptop', ?, ${t0.toEpochMilliseconds()})", ByteArray(16) { 9 })
        old.exec("INSERT INTO device_prekey_state VALUES ('bob', 'laptop', ?, 1, ?, ?)", key(3), key(4), ByteArray(64) { 5 })
        old.exec("INSERT INTO available_one_time_prekey VALUES ('bob', 'laptop', 2, ?)", key(6))
        old.exec("INSERT INTO consumed_one_time_prekey VALUES ('bob', 'laptop', 1)")
        for (sequence in 1..3) {
            old.exec("INSERT INTO mailbox_message (sender_user_id, sender_device_id, recipient_user_id, recipient_device_id, envelope_id, protocol_version, payload) VALUES ('alice', 'phone', 'bob', 'laptop', 'm$sequence', 1, ?)", byteArrayOf(sequence.toByte()))
        }
        old.exec("DELETE FROM mailbox_message WHERE sequence = 3")
        val before = old.dump()
        old.close()
        drivers -= old
        return before
    }

    @Test
    fun version2DatabaseMigratesAndKeepsEveryRow() = runTest {
        val before = version2Database()
        val driver = open(SqlDelightServerStorage.Schema)
        assertEquals(listOf(7L), driver.longs("PRAGMA user_version"))
        val after = driver.dump()

        assertEquals(before - "device_registration" - "server_storage" - NEW_TABLES, after - "device_registration" - "server_storage" - NEW_TABLES)
        assertEquals(listOf("0|7"), after.getValue("server_storage"))
        NEW_TABLES.forEach { assertEquals(emptyList(), after.getValue(it), it) }
        assertEquals(before.getValue("device_registration").map { "$it|NULL|NULL|NULL" }, after.getValue("device_registration"))

        val storage = SqlDelightServerStorage.open(driver, clock = fixedClock(tMigration))
        val recovered = assertNotNull(storage.devices.registrationState(laptop))
        assertEquals(3, recovered.authEpoch)
        assertEquals(tMigration, recovered.authKeyInstalledAt)
        assertEquals(DeviceRecoveryId(ByteArray(32) { 4 }), recovered.recoveryId)
        assertNull(recovered.rotationId)
        assertFalse(storage.authenticationNonces.claim(laptop, ByteArray(16) { 9 }, t0, t0 - 5.minutes), "nonce kept")
        assertEquals(1, storage.preKeys.oneTimePreKeyCount(bob))
        storage.preKeys.publish(
            PreKeyPublication(bob, key(3), PublicSignedPreKey(SignedPreKeyId(1), key(4), ByteArray(64) { 5 }), listOf(PublicOneTimePreKey(OneTimePreKeyId(1), key(7)))),
        )
        assertEquals(1, storage.preKeys.oneTimePreKeyCount(bob), "tombstone kept")
        storage.mailboxes.enqueue(EncryptedEnvelope(MessageId("m4"), alice, bob, payload = byteArrayOf(4)))
        assertEquals(listOf("m1", "m2", "m4"), storage.mailboxes.drain(bob).map { it.id.value })

        // A migrated registration rotates: epoch 3 -> 4, the recovery ID is replaced by the rotation ID.
        val rotationId = DeviceAuthenticationRotationId(ByteArray(32) { 6 })
        assertEquals(
            RotationReplacementResult.REPLACED,
            storage.devices.replaceForRotation(RotationReplacement(recovered, key(8), rotationId, RequestNonce(ByteArray(16) { 3 }), t0, t0 - 5.minutes, tMigration + 1.days)),
        )
        val rotated = assertNotNull(storage.devices.registrationState(laptop))
        assertEquals(4, rotated.authEpoch)
        assertNull(rotated.recoveryId)
        assertEquals(rotationId, rotated.rotationId)
        assertEquals(tMigration + 1.days, rotated.authKeyInstalledAt)
    }

    @Test
    fun explicitMigrationOfAVersion2DatabaseByTheHost() = runTest {
        version2Database()
        val driver = open(ServerVersion2Schema)
        assertFailsWith<IllegalStateException> { SqlDelightServerStorage.open(driver) }
        SqlDelightServerStorage.Schema.migrate(driver, 2, SqlDelightServerStorage.Schema.version)
        assertEquals(3, SqlDelightServerStorage.open(driver).devices.registrationState(laptop)?.authEpoch)
    }

    /**
     * A milestone 16 database: a row in every table, one registration from
     * first registration, one installed by a recovery, one by a rotation,
     * written through the version 3 schema.
     */
    private fun version3Database(): Map<String, List<String>> {
        val old = open(ServerVersion3Schema)
        old.exec("INSERT INTO device_registration (user_id, device_id, auth_public_key) VALUES ('alice', 'phone', ?)", key(1))
        old.exec("INSERT INTO device_registration VALUES ('alice', 'laptop', ?, 3, ?, NULL)", key(2), ByteArray(32) { 4 })
        old.exec("INSERT INTO device_registration VALUES ('bob', 'laptop', ?, 5, NULL, ?)", key(5), ByteArray(32) { 6 })
        old.exec("INSERT INTO authentication_nonce VALUES ('alice', 'laptop', ?, ${t0.toEpochMilliseconds()})", ByteArray(16) { 9 })
        old.exec("INSERT INTO device_prekey_state VALUES ('bob', 'laptop', ?, 1, ?, ?)", key(3), key(4), ByteArray(64) { 5 })
        old.exec("INSERT INTO available_one_time_prekey VALUES ('bob', 'laptop', 2, ?)", key(6))
        old.exec("INSERT INTO consumed_one_time_prekey VALUES ('bob', 'laptop', 1)")
        for (sequence in 1..3) {
            old.exec("INSERT INTO mailbox_message (sender_user_id, sender_device_id, recipient_user_id, recipient_device_id, envelope_id, protocol_version, payload) VALUES ('alice', 'phone', 'bob', 'laptop', 'm$sequence', 1, ?)", byteArrayOf(sequence.toByte()))
        }
        old.exec("DELETE FROM mailbox_message WHERE sequence = 3")
        val before = old.dump()
        old.close()
        drivers -= old
        return before
    }

    @Test
    fun version3DatabaseMigratesAndStampsLegacyRegistrationsOnce() = runTest {
        val before = version3Database()
        val driver = open(SqlDelightServerStorage.Schema)
        assertEquals(listOf(7L), driver.longs("PRAGMA user_version"))
        val migrated = driver.dump()
        assertEquals(before - "device_registration" - "server_storage" - NEW_TABLES, migrated - "device_registration" - "server_storage" - NEW_TABLES)
        assertEquals(listOf("0|7"), migrated.getValue("server_storage"))
        NEW_TABLES.forEach { assertEquals(emptyList(), migrated.getValue(it), it) }
        assertEquals(before.getValue("device_registration").map { "$it|NULL|NULL" }, migrated.getValue("device_registration"), "SQL invents no time")

        // The first open stamps every legacy registration with its clock's time, in one step.
        val storage = SqlDelightServerStorage.open(driver, clock = fixedClock(tMigration))
        val stamped = driver.dump()
        assertEquals(migrated - "device_registration", stamped - "device_registration", "stamping changes nothing else")
        assertEquals(
            before.getValue("device_registration").map { "$it|${tMigration.toEpochMilliseconds()}|NULL" },
            stamped.getValue("device_registration"),
            "keys, epochs, recovery and rotation IDs unchanged",
        )
        val recovered = assertNotNull(storage.devices.registrationState(laptop))
        assertEquals(3, recovered.authEpoch)
        assertEquals(DeviceRecoveryId(ByteArray(32) { 4 }), recovered.recoveryId)
        assertEquals(tMigration, recovered.authKeyInstalledAt)
        val rotated = assertNotNull(storage.devices.registrationState(bob))
        assertEquals(5, rotated.authEpoch)
        assertEquals(DeviceAuthenticationRotationId(ByteArray(32) { 6 }), rotated.rotationId)
        assertEquals(tMigration, rotated.authKeyInstalledAt)

        // A restart with another clock never rewrites a stamped time.
        driver.close()
        drivers -= driver
        val restarted = open(SqlDelightServerStorage.Schema)
        val reopened = SqlDelightServerStorage.open(restarted, clock = fixedClock(tMigration + 30.days))
        assertEquals(stamped, restarted.dump())
        assertEquals(tMigration, reopened.devices.registrationState(alice)?.authKeyInstalledAt)
        assertEquals(tMigration, reopened.devices.registrationState(laptop)?.authKeyInstalledAt)
        assertFalse(reopened.authenticationNonces.claim(laptop, ByteArray(16) { 9 }, t0, t0 - 5.minutes), "nonce kept")
        assertEquals(1, reopened.preKeys.oneTimePreKeyCount(bob))
        reopened.preKeys.publish(
            PreKeyPublication(bob, key(3), PublicSignedPreKey(SignedPreKeyId(1), key(4), ByteArray(64) { 5 }), listOf(PublicOneTimePreKey(OneTimePreKeyId(1), key(7)))),
        )
        assertEquals(1, reopened.preKeys.oneTimePreKeyCount(bob), "tombstone kept")
        reopened.mailboxes.enqueue(EncryptedEnvelope(MessageId("m4"), alice, bob, payload = byteArrayOf(4)))
        assertEquals(listOf("m1", "m2", "m4"), reopened.mailboxes.drain(bob).map { it.id.value })
        assertEquals(listOf(4L), restarted.longs("SELECT seq FROM sqlite_sequence WHERE name = 'mailbox_message'"), "sequence continues")

        // New registrations and transitions after the migration record their own server time.
        val carol = DeviceAddress(UserId("carol"), DeviceId("tablet"))
        assertTrue(reopened.devices.register(DeviceRegistration(carol, key(9)), tMigration + 31.days))
        assertEquals(tMigration + 31.days, reopened.devices.registrationState(carol)?.authKeyInstalledAt)
    }

    @Test
    fun explicitMigrationOfAVersion3DatabaseByTheHost() = runTest {
        version3Database()
        val driver = open(ServerVersion3Schema)
        assertFailsWith<IllegalStateException> { SqlDelightServerStorage.open(driver) }
        SqlDelightServerStorage.Schema.migrate(driver, 3, SqlDelightServerStorage.Schema.version)
        assertEquals(tMigration, SqlDelightServerStorage.open(driver, clock = fixedClock(tMigration)).devices.registrationState(bob)?.authKeyInstalledAt)
    }

    /**
     * A milestone 17 database: a row in every table, registrations from first
     * registration, recovery and rotation, each with a key installation time,
     * written through the version 4 schema.
     */
    private fun version4Database(): Map<String, List<String>> {
        val old = open(ServerVersion4Schema)
        old.exec("INSERT INTO device_registration VALUES ('alice', 'phone', ?, 1, NULL, NULL, ${t0.toEpochMilliseconds()})", key(1))
        old.exec("INSERT INTO device_registration VALUES ('alice', 'laptop', ?, 3, ?, NULL, ${(t0 + 1.days).toEpochMilliseconds()})", key(2), ByteArray(32) { 4 })
        old.exec("INSERT INTO device_registration VALUES ('bob', 'laptop', ?, 5, NULL, ?, ${(t0 + 2.days).toEpochMilliseconds()})", key(5), ByteArray(32) { 6 })
        old.exec("INSERT INTO authentication_nonce VALUES ('alice', 'laptop', ?, ${t0.toEpochMilliseconds()})", ByteArray(16) { 9 })
        old.exec("INSERT INTO device_prekey_state VALUES ('bob', 'laptop', ?, 1, ?, ?)", key(3), key(4), ByteArray(64) { 5 })
        old.exec("INSERT INTO available_one_time_prekey VALUES ('bob', 'laptop', 2, ?)", key(6))
        old.exec("INSERT INTO consumed_one_time_prekey VALUES ('bob', 'laptop', 1)")
        for (sequence in 1..3) {
            old.exec("INSERT INTO mailbox_message (sender_user_id, sender_device_id, recipient_user_id, recipient_device_id, envelope_id, protocol_version, payload) VALUES ('alice', 'phone', 'bob', 'laptop', 'm$sequence', 1, ?)", byteArrayOf(sequence.toByte()))
        }
        old.exec("DELETE FROM mailbox_message WHERE sequence = 3")
        val before = old.dump()
        old.close()
        drivers -= old
        return before
    }

    @Test
    fun version4DatabaseMigratesAndKeepsEveryRow() = runTest {
        val before = version4Database()
        val driver = open(SqlDelightServerStorage.Schema)
        assertEquals(listOf(7L), driver.longs("PRAGMA user_version"))
        val migrated = driver.dump()
        assertEquals(before - "device_registration" - "server_storage", migrated - "device_registration" - "server_storage" - NEW_TABLES)
        assertEquals(listOf("0|7"), migrated.getValue("server_storage"))
        NEW_TABLES.forEach { assertEquals(emptyList(), migrated.getValue(it), it) }
        assertEquals(
            before.getValue("device_registration").map { "$it|NULL" },
            migrated.getValue("device_registration"),
            "keys, epochs, installation times, recovery and rotation IDs unchanged",
        )

        // Opening changes nothing: every registration already has its installation time.
        val storage = SqlDelightServerStorage.open(driver, clock = fixedClock(tMigration))
        assertEquals(migrated, driver.dump())
        val recovered = assertNotNull(storage.devices.registrationState(laptop))
        assertEquals(3, recovered.authEpoch)
        assertEquals(DeviceRecoveryId(ByteArray(32) { 4 }), recovered.recoveryId)
        assertEquals(t0 + 1.days, recovered.authKeyInstalledAt)
        assertNull(recovered.lastDeviceRecoveryId)
        val rotated = assertNotNull(storage.devices.registrationState(bob))
        assertEquals(DeviceAuthenticationRotationId(ByteArray(32) { 6 }), rotated.rotationId)
        assertEquals(t0 + 2.days, rotated.authKeyInstalledAt)
        assertFalse(storage.authenticationNonces.claim(laptop, ByteArray(16) { 9 }, t0, t0 - 5.minutes), "nonce kept")
        assertEquals(1, storage.preKeys.oneTimePreKeyCount(bob))
        storage.preKeys.publish(
            PreKeyPublication(bob, key(3), PublicSignedPreKey(SignedPreKeyId(1), key(4), ByteArray(64) { 5 }), listOf(PublicOneTimePreKey(OneTimePreKeyId(1), key(7)))),
        )
        assertEquals(1, storage.preKeys.oneTimePreKeyCount(bob), "tombstone kept")
        storage.mailboxes.enqueue(EncryptedEnvelope(MessageId("m4"), alice, bob, payload = byteArrayOf(4)))
        assertEquals(listOf("m1", "m2", "m4"), storage.mailboxes.drain(bob).map { it.id.value })
        assertEquals(listOf(4L), driver.longs("SELECT seq FROM sqlite_sequence WHERE name = 'mailbox_message'"), "sequence continues")

        // A migrated registration can be recovered with a last-device recovery key.
        assertTrue(storage.lastDeviceRecovery.registerRecoveryKey(alice.userId, key(20), tMigration))
        val challenge = assertIs<LastDeviceRecoveryChallengeIssue.Issued>(
            storage.lastDeviceRecovery.issueChallenge(
                LastDeviceRecoveryChallengeRequest(laptop, LastDeviceRecoveryChallengeId(ByteArray(16) { 1 }), ByteArray(32) { 2 }, tMigration, tMigration + 5.minutes),
            ),
        ).challenge
        assertEquals(3, challenge.challenge.authEpoch)
        val id = LastDeviceRecoveryId(ByteArray(32) { 3 })
        assertEquals(
            LastDeviceRecoveryReplacementResult.REPLACED,
            storage.devices.replaceForLastDeviceRecovery(
                LastDeviceRecoveryReplacement(recovered, key(20), challenge.challenge.id, challenge.challenge.nonce, key(8), id, tMigration + 1.minutes),
            ),
        )
        val replaced = assertNotNull(storage.devices.registrationState(laptop))
        assertEquals(4, replaced.authEpoch)
        assertEquals(id, replaced.lastDeviceRecoveryId)
        assertNull(replaced.recoveryId)
        assertEquals(tMigration + 1.minutes, replaced.authKeyInstalledAt)
    }

    @Test
    fun explicitMigrationOfAVersion4DatabaseByTheHost() = runTest {
        version4Database()
        val driver = open(ServerVersion4Schema)
        val e = assertFailsWith<IllegalStateException> { SqlDelightServerStorage.open(driver) }
        assertTrue(e.message.orEmpty().contains("migrate"))
        SqlDelightServerStorage.Schema.migrate(driver, 4, SqlDelightServerStorage.Schema.version)
        assertEquals(5, SqlDelightServerStorage.open(driver).devices.registrationState(bob)?.authEpoch)
    }

    /**
     * A milestone 18 database: registrations (one installed by a last-device
     * recovery), a recovery key for alice, an outstanding challenge for
     * alice's laptop and an orphan challenge of a user without a key, and a
     * row in every other table, written through the version 5 schema.
     */
    private fun version5Database(): Map<String, List<String>> {
        val old = open(ServerVersion5Schema)
        old.exec("INSERT INTO device_registration VALUES ('alice', 'phone', ?, 1, NULL, NULL, ${t0.toEpochMilliseconds()}, NULL)", key(1))
        old.exec("INSERT INTO device_registration VALUES ('alice', 'laptop', ?, 4, NULL, NULL, ${(t0 + 1.days).toEpochMilliseconds()}, ?)", key(2), ByteArray(32) { 4 })
        old.exec("INSERT INTO device_registration VALUES ('bob', 'laptop', ?, 5, NULL, ?, ${(t0 + 2.days).toEpochMilliseconds()}, NULL)", key(5), ByteArray(32) { 6 })
        old.exec("INSERT INTO authentication_nonce VALUES ('alice', 'laptop', ?, ${t0.toEpochMilliseconds()})", ByteArray(16) { 9 })
        old.exec("INSERT INTO last_device_recovery_key VALUES ('alice', ?, ${(t0 + 3.days).toEpochMilliseconds()})", key(20))
        old.exec(
            "INSERT INTO last_device_recovery_challenge VALUES ('alice', 'laptop', ?, ?, 4, ?, ${tMigration.toEpochMilliseconds()}, ${(tMigration + 5.minutes).toEpochMilliseconds()})",
            ByteArray(16) { 1 }, ByteArray(32) { 2 }, key(2),
        )
        old.exec(
            "INSERT INTO last_device_recovery_challenge VALUES ('bob', 'laptop', ?, ?, 5, ?, ${tMigration.toEpochMilliseconds()}, ${(tMigration + 5.minutes).toEpochMilliseconds()})",
            ByteArray(16) { 3 }, ByteArray(32) { 4 }, key(5),
        )
        old.exec("INSERT INTO device_prekey_state VALUES ('bob', 'laptop', ?, 1, ?, ?)", key(3), key(4), ByteArray(64) { 5 })
        old.exec("INSERT INTO available_one_time_prekey VALUES ('bob', 'laptop', 2, ?)", key(6))
        old.exec("INSERT INTO consumed_one_time_prekey VALUES ('bob', 'laptop', 1)")
        for (sequence in 1..3) {
            old.exec("INSERT INTO mailbox_message (sender_user_id, sender_device_id, recipient_user_id, recipient_device_id, envelope_id, protocol_version, payload) VALUES ('alice', 'phone', 'bob', 'laptop', 'm$sequence', 1, ?)", byteArrayOf(sequence.toByte()))
        }
        old.exec("DELETE FROM mailbox_message WHERE sequence = 3")
        val before = old.dump()
        old.close()
        drivers -= old
        return before
    }

    @Test
    fun version5DatabaseMigratesRecoveryKeysToActiveAtEpochOne() = runTest {
        val before = version5Database()
        val driver = open(SqlDelightServerStorage.Schema)
        assertEquals(listOf(7L), driver.longs("PRAGMA user_version"))
        val migrated = driver.dump()
        val untouched = listOf("server_storage", "last_device_recovery_key", "last_device_recovery_challenge")
        assertEquals(emptyList(), migrated.getValue("last_device_recovery_key_reset"))
        assertEquals(before - untouched, migrated - untouched - NEW_TABLES, "registrations, IDs, nonces, prekeys, tombstones and mailbox unchanged")
        assertEquals(listOf("0|7"), migrated.getValue("server_storage"))
        assertFalse("last_device_recovery_key" in migrated, "old table dropped")
        val registered = (t0 + 3.days).toEpochMilliseconds()
        assertEquals(
            listOf("'alice'|1|1|X'${key(20).toHex()}'|$registered|$registered|NULL|NULL|NULL"),
            migrated.getValue("last_device_recovery_key_state"),
            "ACTIVE, epoch 1, installation time = registration time",
        )
        val aliceChallenge = before.getValue("last_device_recovery_challenge").single { it.startsWith("'alice'") }
        assertEquals(listOf("$aliceChallenge|1"), migrated.getValue("last_device_recovery_challenge"), "bound to epoch 1; orphan dropped")

        val storage = SqlDelightServerStorage.open(driver, clock = fixedClock(tMigration))
        assertEquals(migrated, driver.dump(), "opening changes nothing")
        val state = assertNotNull(storage.lastDeviceRecovery.recoveryKeyState(alice.userId))
        assertEquals(1, state.epoch)
        assertEquals(dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyStatus.ACTIVE, state.status)
        assertContentEquals(key(20), state.publicKey)
        assertEquals(t0 + 3.days, state.installedAt)
        assertNull(state.rotationId)
        assertNull(storage.lastDeviceRecovery.recoveryKeyState(bob.userId))
        assertEquals(1, storage.lastDeviceRecovery.challenge(laptop)?.recoveryKeyEpoch)
        assertNull(storage.lastDeviceRecovery.challenge(bob))
        val lastDevice = assertNotNull(storage.devices.registrationState(laptop))
        assertEquals(LastDeviceRecoveryId(ByteArray(32) { 4 }), lastDevice.lastDeviceRecoveryId)
        assertEquals(4, lastDevice.authEpoch)
        assertFalse(storage.authenticationNonces.claim(laptop, ByteArray(16) { 9 }, t0, t0 - 5.minutes), "nonce kept")
        assertEquals(1, storage.preKeys.oneTimePreKeyCount(bob))
        storage.mailboxes.enqueue(EncryptedEnvelope(MessageId("m4"), alice, bob, payload = byteArrayOf(4)))
        assertEquals(listOf("m1", "m2", "m4"), storage.mailboxes.drain(bob).map { it.id.value })
        assertEquals(listOf(4L), driver.longs("SELECT seq FROM sqlite_sequence WHERE name = 'mailbox_message'"), "sequence continues")

        // The migrated challenge is still usable: it was issued under the migrated key.
        val stored = assertNotNull(storage.lastDeviceRecovery.challenge(laptop))
        val id = LastDeviceRecoveryId(ByteArray(32) { 7 })
        assertEquals(
            LastDeviceRecoveryReplacementResult.REPLACED,
            storage.devices.replaceForLastDeviceRecovery(
                LastDeviceRecoveryReplacement(lastDevice, key(20), stored.challenge.id, stored.challenge.nonce, key(8), id, tMigration + 1.minutes),
            ),
        )
        assertEquals(5, storage.devices.registrationState(laptop)?.authEpoch)
    }

    @Test
    fun explicitMigrationOfAVersion5DatabaseByTheHost() = runTest {
        version5Database()
        val driver = open(ServerVersion5Schema)
        val e = assertFailsWith<IllegalStateException> { SqlDelightServerStorage.open(driver) }
        assertTrue(e.message.orEmpty().contains("version 5"))
        SqlDelightServerStorage.Schema.migrate(driver, 5, SqlDelightServerStorage.Schema.version)
        assertEquals(1, SqlDelightServerStorage.open(driver).lastDeviceRecovery.recoveryKeyState(alice.userId)?.epoch)
    }

    @Test
    fun migratedVersion5SchemaEqualsNewSchema() {
        version5Database()
        val migrated = open(SqlDelightServerStorage.Schema)
        val fresh = inMemoryDriver().also { drivers += it }
        assertEquals(fresh.schemaShape(), migrated.schemaShape())
        assertEquals(fresh.longs("PRAGMA user_version"), migrated.longs("PRAGMA user_version"))
        assertEquals(fresh.dump().getValue("server_storage"), migrated.dump().getValue("server_storage"))
    }

    @Test
    fun freshVersion5FixtureMatchesTheVersion5Schema() {
        // The frozen fixture is what 4.sqm produced: a version 4 database migrated to 5 has its shape.
        version4Database()
        val migrated = open(ServerVersion4Schema)
        SqlDelightServerStorage.Schema.migrate(migrated, 4, 5)
        val fixtureDatabase = TempDatabase()
        val fixture = JdbcSqliteDriver("jdbc:sqlite:${fixtureDatabase.path.toAbsolutePath()}", Properties(), ServerVersion5Schema)
        try {
            assertEquals(fixture.schemaShape(), migrated.schemaShape())
        } finally {
            fixture.close()
            fixtureDatabase.close()
        }
    }

    @Test
    fun recoveryKeyStateConstraintsHoldInFreshAndMigratedSchemas() {
        version5Database()
        val migrated = open(SqlDelightServerStorage.Schema)
        val fresh = inMemoryDriver().also { drivers += it }
        for (driver in listOf(fresh, migrated)) {
            val invalid = listOf(
                "INSERT INTO last_device_recovery_key_state VALUES ('x', 1, 1, NULL, 1, 1, NULL, NULL, NULL)", // active without key
                "INSERT INTO last_device_recovery_key_state VALUES ('x', 2, 1, X'00', NULL, 1, NULL, NULL, NULL)", // revoked with key
                "INSERT INTO last_device_recovery_key_state VALUES ('x', 1, 0, X'00', 1, 1, NULL, NULL, NULL)", // epoch 0
                "INSERT INTO last_device_recovery_key_state VALUES ('x', 3, 1, NULL, NULL, 1, NULL, NULL, NULL)", // unknown state
                "INSERT INTO last_device_recovery_key_state VALUES ('x', 2, 1, NULL, NULL, 1, X'00', NULL, NULL)", // revoked by a rotation
                "INSERT INTO last_device_recovery_key_state VALUES ('x', 1, 1, X'00', 1, 1, NULL, X'00', NULL)", // active with a revocation ID
                "INSERT INTO last_device_recovery_key_state VALUES ('x', 2, 1, NULL, NULL, 1, NULL, X'00', X'00')", // revoked by a reset
                "INSERT INTO last_device_recovery_key_state VALUES ('x', 1, 1, X'00', 1, 1, X'00', NULL, X'00')", // two transition IDs
            )
            for (sql in invalid) assertFailsWith<Exception>(sql) { driver.exec(sql) }
        }
    }

    /**
     * A milestone 19–22 database: registrations, alice's recovery key rotated
     * (epoch 2, rotation ID) with a challenge bound to epoch 2, bob's key
     * revoked (epoch 3, revocation ID), carol's key registered, and a row in
     * every other table, written through the version 6 schema.
     */
    private fun version6Database(): Map<String, List<String>> {
        val old = open(ServerVersion6Schema)
        old.exec("INSERT INTO device_registration VALUES ('alice', 'phone', ?, 1, NULL, NULL, ${t0.toEpochMilliseconds()}, NULL)", key(1))
        old.exec("INSERT INTO device_registration VALUES ('alice', 'laptop', ?, 4, NULL, NULL, ${(t0 + 1.days).toEpochMilliseconds()}, ?)", key(2), ByteArray(32) { 4 })
        old.exec("INSERT INTO device_registration VALUES ('bob', 'laptop', ?, 5, NULL, ?, ${(t0 + 2.days).toEpochMilliseconds()}, NULL)", key(5), ByteArray(32) { 6 })
        old.exec("INSERT INTO authentication_nonce VALUES ('alice', 'laptop', ?, ${t0.toEpochMilliseconds()})", ByteArray(16) { 9 })
        val rotatedAt = (t0 + 3.days).toEpochMilliseconds()
        old.exec("INSERT INTO last_device_recovery_key_state VALUES ('alice', 1, 2, ?, $rotatedAt, $rotatedAt, ?, NULL)", key(20), ByteArray(32) { 7 })
        old.exec("INSERT INTO last_device_recovery_key_state VALUES ('bob', 2, 3, NULL, NULL, $rotatedAt, NULL, ?)", ByteArray(32) { 8 })
        old.exec("INSERT INTO last_device_recovery_key_state VALUES ('carol', 1, 1, ?, $rotatedAt, $rotatedAt, NULL, NULL)", key(21))
        old.exec(
            "INSERT INTO last_device_recovery_challenge VALUES ('alice', 'laptop', ?, ?, 4, ?, ${tMigration.toEpochMilliseconds()}, ${(tMigration + 5.minutes).toEpochMilliseconds()}, 2)",
            ByteArray(16) { 1 }, ByteArray(32) { 2 }, key(2),
        )
        old.exec("INSERT INTO device_prekey_state VALUES ('bob', 'laptop', ?, 1, ?, ?)", key(3), key(4), ByteArray(64) { 5 })
        old.exec("INSERT INTO available_one_time_prekey VALUES ('bob', 'laptop', 2, ?)", key(6))
        old.exec("INSERT INTO consumed_one_time_prekey VALUES ('bob', 'laptop', 1)")
        for (sequence in 1..3) {
            old.exec("INSERT INTO mailbox_message (sender_user_id, sender_device_id, recipient_user_id, recipient_device_id, envelope_id, protocol_version, payload) VALUES ('alice', 'phone', 'bob', 'laptop', 'm$sequence', 1, ?)", byteArrayOf(sequence.toByte()))
        }
        old.exec("DELETE FROM mailbox_message WHERE sequence = 3")
        val before = old.dump()
        old.close()
        drivers -= old
        return before
    }

    @Test
    fun version6DatabaseKeepsEveryRecoveryKeyStateAndStartsWithoutResets() = runTest {
        val before = version6Database()
        val driver = open(SqlDelightServerStorage.Schema)
        assertEquals(listOf(7L), driver.longs("PRAGMA user_version"))
        val migrated = driver.dump()
        val changed = listOf("server_storage", "last_device_recovery_key_state", "last_device_recovery_key_reset")
        assertEquals(before - changed, migrated - changed, "registrations, IDs, challenges, nonces, prekeys, tombstones and mailbox unchanged")
        assertEquals(listOf("0|7"), migrated.getValue("server_storage"))
        assertEquals(before.getValue("last_device_recovery_key_state").map { "$it|NULL" }, migrated.getValue("last_device_recovery_key_state"), "no time invented")
        assertEquals(emptyList(), migrated.getValue("last_device_recovery_key_reset"))
        assertFalse("last_device_recovery_key_state_v6" in migrated, "temporary table dropped")

        val storage = SqlDelightServerStorage.open(driver, clock = fixedClock(tMigration))
        assertEquals(migrated, driver.dump(), "opening changes nothing")
        val alice = assertNotNull(storage.lastDeviceRecovery.recoveryKeyState(this@SqlDelightServerMigrationTest.alice.userId))
        assertEquals(2, alice.epoch)
        assertEquals(dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRotationId(ByteArray(32) { 7 }), alice.rotationId)
        assertNull(alice.resetCompletionId)
        assertEquals(t0 + 3.days, alice.installedAt)
        val bob = assertNotNull(storage.lastDeviceRecovery.recoveryKeyState(bob.userId))
        assertEquals(dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyStatus.REVOKED, bob.status)
        assertEquals(3, bob.epoch)
        assertEquals(2, storage.lastDeviceRecovery.challenge(laptop)?.recoveryKeyEpoch)
        assertNull(storage.lastDeviceRecovery.pendingRecoveryKeyReset(this@SqlDelightServerMigrationTest.alice.userId))
        assertEquals(1, storage.preKeys.oneTimePreKeyCount(this@SqlDelightServerMigrationTest.bob))
        assertEquals(listOf(3L), driver.longs("SELECT seq FROM sqlite_sequence WHERE name = 'mailbox_message'"), "sequence kept")

        // A migrated active key can be reset.
        val requester = assertNotNull(storage.devices.registrationState(laptop))
        val reset = assertIs<dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyResetRequestResult.Created>(
            storage.lastDeviceRecovery.requestRecoveryKeyReset(
                dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyResetRequest(
                    requester, dev.kreienbuehl.ksecuremessage.model.RecoveryKeyResetId(ByteArray(16) { 3 }), tMigration, tMigration + 1.days,
                ),
            ),
        ).reset
        assertEquals(2, reset.recoveryKeyEpoch)
        assertContentEquals(key(20), reset.recoveryPublicKey)
    }

    @Test
    fun explicitMigrationOfAVersion6DatabaseByTheHost() = runTest {
        version6Database()
        val driver = open(ServerVersion6Schema)
        val e = assertFailsWith<IllegalStateException> { SqlDelightServerStorage.open(driver) }
        assertTrue(e.message.orEmpty().contains("version 6"))
        SqlDelightServerStorage.Schema.migrate(driver, 6, SqlDelightServerStorage.Schema.version)
        assertEquals(2, SqlDelightServerStorage.open(driver).lastDeviceRecovery.recoveryKeyState(alice.userId)?.epoch)
    }

    @Test
    fun migratedVersion6SchemaEqualsNewSchema() {
        version6Database()
        val migrated = open(SqlDelightServerStorage.Schema)
        val fresh = inMemoryDriver().also { drivers += it }
        assertEquals(fresh.schemaShape(), migrated.schemaShape())
        assertEquals(fresh.longs("PRAGMA user_version"), migrated.longs("PRAGMA user_version"))
        assertEquals(fresh.dump().getValue("server_storage"), migrated.dump().getValue("server_storage"))
        // The rebuilt table has exactly the DDL of a new one, CHECK constraints included.
        val ddl = "SELECT sql FROM sqlite_master WHERE name IN ('last_device_recovery_key_state', 'last_device_recovery_key_reset') ORDER BY name"
        assertEquals(fresh.strings(ddl), migrated.strings(ddl))
    }

    @Test
    fun freshVersion6FixtureMatchesTheVersion6Schema() {
        // The frozen fixture is what 5.sqm produced: a version 5 database migrated to 6 has its shape.
        version5Database()
        val migrated = open(ServerVersion5Schema)
        SqlDelightServerStorage.Schema.migrate(migrated, 5, 6)
        val fixtureDatabase = TempDatabase()
        val fixture = JdbcSqliteDriver("jdbc:sqlite:${fixtureDatabase.path.toAbsolutePath()}", Properties(), ServerVersion6Schema)
        try {
            assertEquals(fixture.schemaShape(), migrated.schemaShape())
        } finally {
            fixture.close()
            fixtureDatabase.close()
        }
    }

    @Test
    fun recoveryKeyResetConstraintsHoldInFreshAndMigratedSchemas() {
        version6Database()
        val migrated = open(SqlDelightServerStorage.Schema)
        val fresh = inMemoryDriver().also { drivers += it }
        val key = "X'${"00".repeat(32)}'"
        val id = "X'${"00".repeat(16)}'"
        for (driver in listOf(fresh, migrated)) {
            driver.exec("INSERT INTO last_device_recovery_key_reset VALUES ('x', $id, 'phone', 1, $key, 1, 2)")
            val invalid = listOf(
                "INSERT INTO last_device_recovery_key_reset VALUES ('x', X'${"01".repeat(16)}', 'phone', 1, $key, 1, 2)", // second reset of a user
                "INSERT INTO last_device_recovery_key_reset VALUES ('y', $id, 'phone', 1, $key, 1, 2)", // reset ID reused
                "INSERT INTO last_device_recovery_key_reset VALUES ('y', X'${"02".repeat(15)}', 'phone', 1, $key, 1, 2)", // short ID
                "INSERT INTO last_device_recovery_key_reset VALUES ('y', X'${"02".repeat(16)}', 'phone', 1, X'00', 1, 2)", // short key
                "INSERT INTO last_device_recovery_key_reset VALUES ('y', X'${"02".repeat(16)}', 'phone', 0, $key, 1, 2)", // epoch 0
                "INSERT INTO last_device_recovery_key_reset VALUES ('y', X'${"02".repeat(16)}', 'phone', 1, $key, 2, 2)", // eligible at the request
                "INSERT INTO last_device_recovery_key_reset VALUES ('y', X'${"02".repeat(16)}', NULL, 1, $key, 1, 2)", // no requester
            )
            for (sql in invalid) assertFailsWith<Exception>(sql) { driver.exec(sql) }
        }
    }

    @Test
    fun migratedVersion4SchemaEqualsNewSchema() {
        version4Database()
        val migrated = open(SqlDelightServerStorage.Schema)
        val fresh = inMemoryDriver().also { drivers += it }
        assertEquals(fresh.schemaShape(), migrated.schemaShape())
        assertEquals(fresh.longs("PRAGMA user_version"), migrated.longs("PRAGMA user_version"))
        assertEquals(fresh.dump().getValue("server_storage"), migrated.dump().getValue("server_storage"))
    }

    @Test
    fun freshVersion4FixtureMatchesTheVersion4Schema() {
        // The frozen fixture is what 3.sqm produced: a version 3 database migrated to 4 has its shape.
        version3Database()
        val migrated = open(ServerVersion3Schema)
        SqlDelightServerStorage.Schema.migrate(migrated, 3, 4)
        val fixtureDatabase = TempDatabase()
        val fixture = JdbcSqliteDriver("jdbc:sqlite:${fixtureDatabase.path.toAbsolutePath()}", Properties(), ServerVersion4Schema)
        try {
            assertEquals(fixture.schemaShape(), migrated.schemaShape())
        } finally {
            fixture.close()
            fixtureDatabase.close()
        }
    }

    @Test
    fun migratedVersion3SchemaEqualsNewSchema() {
        version3Database()
        val migrated = open(SqlDelightServerStorage.Schema)
        val fresh = inMemoryDriver().also { drivers += it }
        assertEquals(fresh.schemaShape(), migrated.schemaShape())
        assertEquals(fresh.longs("PRAGMA user_version"), migrated.longs("PRAGMA user_version"))
        assertEquals(fresh.dump().getValue("server_storage"), migrated.dump().getValue("server_storage"))
    }

    @Test
    fun freshVersion3FixtureMatchesTheVersion3Schema() {
        // The frozen fixture is what 2.sqm produced: a version 2 database migrated to 3 has its shape.
        version2Database()
        val migrated = open(ServerVersion2Schema)
        SqlDelightServerStorage.Schema.migrate(migrated, 2, 3)
        val fixtureDatabase = TempDatabase()
        val fixture = JdbcSqliteDriver("jdbc:sqlite:${fixtureDatabase.path.toAbsolutePath()}", Properties(), ServerVersion3Schema)
        try {
            assertEquals(fixture.schemaShape(), migrated.schemaShape())
        } finally {
            fixture.close()
            fixtureDatabase.close()
        }
    }

    @Test
    fun migratedVersion2SchemaEqualsNewSchema() {
        version2Database()
        val migrated = open(SqlDelightServerStorage.Schema)
        val fresh = inMemoryDriver().also { drivers += it }
        assertEquals(fresh.schemaShape(), migrated.schemaShape())
        assertEquals(fresh.longs("PRAGMA user_version"), migrated.longs("PRAGMA user_version"))
        assertEquals(fresh.dump().getValue("server_storage"), migrated.dump().getValue("server_storage"))
    }

    @Test
    fun freshVersion2FixtureMatchesTheVersion2Schema() {
        // The frozen fixture is what 1.sqm produced: a version 1 database migrated to 2 has its shape.
        version1Database()
        val migrated = open(ServerVersion1Schema)
        SqlDelightServerStorage.Schema.migrate(migrated, 1, 2)
        val fixtureDatabase = TempDatabase()
        val fixture = JdbcSqliteDriver("jdbc:sqlite:${fixtureDatabase.path.toAbsolutePath()}", Properties(), ServerVersion2Schema)
        try {
            assertEquals(fixture.schemaShape(), migrated.schemaShape())
        } finally {
            fixture.close()
            fixtureDatabase.close()
        }
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
            t0 + 100.days,
        )
        assertEquals(RecoveryReplacementResult.REPLACED, storage.devices.replaceForRecovery(replacement))
        assertEquals(2, storage.devices.registrationState(laptop)?.authEpoch)
        assertEquals(t0 + 100.days, storage.devices.registrationState(laptop)?.authKeyInstalledAt)
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

    private fun ByteArray.toHex(): String = joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0').uppercase() }

    private companion object {
        /** Last-device recovery tables (4.sqm, 5.sqm, 6.sqm); empty after every migration from before version 5. */
        val NEW_TABLES = listOf("last_device_recovery_key_state", "last_device_recovery_challenge", "last_device_recovery_key_reset")
    }

    @Test
    fun newRegistrationsAfterMigrationStartAtEpochOne() = runTest {
        version1Database()
        val storage = SqlDelightServerStorage.open(open(SqlDelightServerStorage.Schema))
        storage.devices.register(DeviceRegistration(DeviceAddress(UserId("carol"), DeviceId("tablet")), key(9)), t0)
        assertEquals(1, storage.devices.registrationState(DeviceAddress(UserId("carol"), DeviceId("tablet")))?.authEpoch)
    }
}
