package dev.kreienbuehl.ksecuremessage.storage.client.sqldelight

import app.cash.sqldelight.db.SqlDriver
import dev.kreienbuehl.ksecuremessage.client.PreKeyConfiguration
import dev.kreienbuehl.ksecuremessage.client.ReceiveResult
import dev.kreienbuehl.ksecuremessage.client.SecureMessageClient
import dev.kreienbuehl.ksecuremessage.client.SecureMessageClientException
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.LocalIdentity
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage
import dev.kreienbuehl.ksecuremessage.storage.encryption.ClientRecordCipher
import dev.kreienbuehl.ksecuremessage.storage.encryption.SealedRecords
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageEncryptionException
import kotlinx.coroutines.test.runTest
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
import kotlin.time.Instant

private val ALICE = DeviceAddress(UserId("alice"), DeviceId("phone"))
private val BOB = DeviceAddress(UserId("bob"), DeviceId("laptop"))

private val AUTH_TABLES = setOf(
    "device_authentication_key",
    "device_authentication_state",
    "device_authentication_recovery_key",
    "device_authentication_rotation_key",
    "device_authentication_last_device_recovery_key",
)

/**
 * The device authentication key in SQLDelight storage (milestone 12,
 * docs/server-authentication.md): sealed at rest, created once, migrated
 * into milestone 11 databases exactly once, and never recreated after a loss.
 */
class DeviceAuthenticationStorageTest {
    private val database = TestDatabase()
    private val engine = KodiumProtocolEngine()
    private val network = TestRelay()
    private val clock = TestClock(Instant.fromEpochMilliseconds(1_000_000_000_000))
    private val config = PreKeyConfiguration(oneTimePreKeyTarget = 3)
    private lateinit var driver: SqlDriver

    @AfterTest
    fun close() = database.close()

    private suspend fun reopen(records: MutableList<FailingRecords>? = null): SqlDelightClientStorage {
        database.closeOpenDrivers()
        driver = database.open()
        return if (records == null) {
            SqlDelightClientStorage.open(driver, TestKeys.providerA)
        } else {
            SqlDelightClientStorage.open(driver, TestKeys.providerA, FailingRecords.factory(records))
        }
    }

    private fun client(address: DeviceAddress, storage: ClientStorage) = SecureMessageClient(address, storage, engine, network, config, clock)

    private fun sealedKey(): ByteArray = driver.blob("SELECT sealed_key_pair FROM device_authentication_key")

    private fun awaitsUpgradeKeyColumn(): Long? = driver.longs("SELECT awaits_upgrade_key FROM device_authentication_state").single()

    /** Turns the open database back into a milestone 11 one (schema version 7), keeping every other row. */
    private fun downgradeToVersion7() {
        driver.exec("DROP TABLE device_authentication_key")
        driver.exec("DROP TABLE device_authentication_state")
        driver.exec("DROP TABLE device_authentication_recovery_key")
        driver.exec("DROP TABLE device_authentication_rotation_key")
        driver.exec("DROP TABLE device_authentication_last_device_recovery_key")
        driver.exec("ALTER TABLE remote_identity DROP COLUMN verification")
        driver.exec("PRAGMA user_version = 7")
    }

    @Test
    fun initializeCreatesOneSealedKeyThatSurvivesRestarts() = runTest {
        val storage = reopen()
        client(BOB, storage).initialize()
        val keyPair = assertNotNull(storage.deviceAuthentication.keyPair())
        assertEquals(32, keyPair.publicKey.size)
        assertEquals(32, keyPair.privateKey.size)

        val sealed = sealedKey()
        assertTrue(sealed.isSealed())
        for (row in driver.dump().values.flatten()) {
            assertFalse(row.orEmpty().contains(keyPair.privateKey.toHex(), ignoreCase = true), "private key in plaintext")
        }
        assertEquals(0L, awaitsUpgradeKeyColumn())

        val restarted = reopen()
        client(BOB, restarted).initialize()
        assertContentEquals(keyPair.privateKey, restarted.deviceAuthentication.keyPair()?.privateKey)
        assertContentEquals(keyPair.publicKey, restarted.deviceAuthentication.keyPair()?.publicKey)
        assertContentEquals(sealed, sealedKey(), "not rewritten")
        assertEquals(listOf(1L), driver.longs("SELECT count(*) FROM device_authentication_key"))
    }

    @Test
    fun keySurvivesStorageKeyRotation() = runTest {
        val storage = reopen()
        client(BOB, storage).initialize()
        val keyPair = assertNotNull(storage.deviceAuthentication.keyPair())
        assertEquals(1, SealedRecords.keyId(sealedKey()).value)

        val provider = MemoryKeyStore().apply { put("auth", TestKeys.A) }.provider("auth")
        database.closeOpenDrivers()
        driver = database.open()
        val rotating = SqlDelightClientStorage.open(driver, provider)
        rotating.rotateStorageKey()
        completeStorageKeyRotation { rotating.resumeStorageKeyRotation(1) }

        assertEquals(2, SealedRecords.keyId(sealedKey()).value, "re-encrypted with the new storage key")
        assertContentEquals(keyPair.privateKey, rotating.deviceAuthentication.keyPair()?.privateKey)
        client(BOB, rotating).initialize()
        assertContentEquals(keyPair.privateKey, rotating.deviceAuthentication.keyPair()?.privateKey)
    }

    @Test
    fun version7FixtureMigratesWithTheIdentityMarkedAsAwaitingItsKey() = runTest {
        val records = ClientRecordCipher(TestKeys.A)
        val old = database.open(Version7Schema)
        old.exec("INSERT INTO local_identity (id, sealed_identity) VALUES (0, ?)", records.sealIdentity(LocalIdentity(ByteArray(64) { 1 }, ByteArray(32) { 2 })))
        old.exec("UPDATE storage_encryption SET key_id = 1, key_check = ?, highest_key_id = 1", records.sealKeyCheck())
        val before = old.dump()
        database.closeOpenDrivers()

        val storage = reopen()
        assertEquals(listOf(12L), driver.longs("PRAGMA user_version"))
        val after = driver.dump()
        assertEquals(before.withUnverifiedPins(), after - AUTH_TABLES, "no existing row changes")
        assertEquals(emptyList(), after.getValue("device_authentication_key"), "SQL creates no key material")
        assertEquals(1L, awaitsUpgradeKeyColumn())
        assertTrue(storage.deviceAuthentication.awaitsUpgradeKey())
        assertNull(storage.deviceAuthentication.keyPair())
    }

    @Test
    fun version7FixtureWithoutIdentityIsAFreshInstallation() = runTest {
        database.open(Version7Schema)
        database.closeOpenDrivers()

        val storage = reopen()
        assertEquals(0L, awaitsUpgradeKeyColumn())
        assertFalse(storage.deviceAuthentication.awaitsUpgradeKey())
        client(BOB, storage).initialize()
        assertNotNull(storage.identity.identity())
        assertNotNull(storage.deviceAuthentication.keyPair())
    }

    @Test
    fun downgradedDatabaseMatchesTheVersion7Fixture() = runTest {
        client(BOB, reopen()).initialize()
        downgradeToVersion7()
        val downgraded = driver.tables().associateWith { driver.columns(it) }

        val fixture = TestDatabase()
        try {
            val fixtureDriver = fixture.open(Version7Schema)
            assertEquals(fixtureDriver.tables().associateWith { fixtureDriver.columns(it) }, downgraded)
        } finally {
            fixture.close()
        }
    }

    @Test
    fun milestone11InstallationGetsExactlyOneKeyAndKeepsEverythingElse() = runTest {
        // A real conversation on schema version 8, then turned into the milestone 11 database it would have been.
        val alice = client(ALICE, reopenAlice())
        alice.initialize()
        val bobStorage = reopen()
        val bob = client(BOB, bobStorage)
        bob.initialize()
        network.publish(bob)
        alice.send(BOB, "before the upgrade".encodeToByteArray())
        assertEquals("before the upgrade", assertIs<ReceiveResult.Message>(bob.decrypt(network.receive(BOB).single())).plaintext.decodeToString())
        alice.decrypt(network.receive(ALICE).single())
        bob.send(ALICE, "pending at the upgrade".encodeToByteArray())
        network.receive(ALICE) // lost: stays pending at Bob
        val identity = assertNotNull(bobStorage.identity.identity())
        downgradeToVersion7()
        val before = driver.dump()

        // Opening migrates the schema; nothing but the new tables changes, and no key is created yet.
        val migrated = reopen()
        assertEquals(before.withUnverifiedPins(), driver.dump() - AUTH_TABLES)
        assertTrue(migrated.deviceAuthentication.awaitsUpgradeKey())
        assertNull(migrated.deviceAuthentication.keyPair())

        client(BOB, migrated).initialize()
        val keyPair = assertNotNull(migrated.deviceAuthentication.keyPair())
        assertFalse(migrated.deviceAuthentication.awaitsUpgradeKey())
        assertEquals(0L, awaitsUpgradeKeyColumn())
        assertContentEquals(identity.privateKey, migrated.identity.identity()?.privateKey, "the identity is kept")
        assertEquals(before.withUnverifiedPins() - "one_time_pre_key" - "pre_key_state", driver.dump() - AUTH_TABLES - "one_time_pre_key" - "pre_key_state")

        // Exactly once: later starts keep that key.
        repeat(2) {
            val restarted = reopen()
            client(BOB, restarted).initialize()
            assertContentEquals(keyPair.privateKey, restarted.deviceAuthentication.keyPair()?.privateKey)
        }
        assertEquals(listOf(1L), driver.longs("SELECT count(*) FROM device_authentication_key"))

        // Messaging continues on the kept session, and the pending message is still pending.
        val upgraded = client(BOB, reopen())
        assertEquals(1, upgraded.pendingMessages(ALICE).size)
        upgraded.send(ALICE, "after the upgrade".encodeToByteArray())
        val received = network.receive(ALICE).map { alice.decrypt(it) }
        assertEquals(listOf("after the upgrade"), received.filterIsInstance<ReceiveResult.Message>().map { it.plaintext.decodeToString() })
    }

    private val aliceDatabase = TestDatabase()

    private suspend fun reopenAlice(): SqlDelightClientStorage {
        aliceDatabase.closeOpenDrivers()
        return SqlDelightClientStorage.open(aliceDatabase.open(), TestKeys.providerA)
    }

    @AfterTest
    fun closeAlice() = aliceDatabase.close()

    @Test
    fun lostKeyAfterInitializationFailsClosed() = runTest {
        val storage = reopen()
        client(BOB, storage).initialize()
        val keyPair = assertNotNull(storage.deviceAuthentication.keyPair())
        driver.exec("DELETE FROM device_authentication_key")

        val restarted = reopen()
        val failure = assertFailsWith<SecureMessageClientException.InconsistentStorage> { client(BOB, restarted).initialize() }
        assertFalse(failure.message.orEmpty().contains(keyPair.privateKey.toHex(), ignoreCase = true))
        assertEquals(listOf(0L), driver.longs("SELECT count(*) FROM device_authentication_key"), "no replacement key")
        assertEquals(0L, awaitsUpgradeKeyColumn())
        assertFailsWith<SecureMessageClientException.NotInitialized> { client(BOB, restarted).registerDevice() }
        assertFailsWith<SecureMessageClientException.NotInitialized> { client(BOB, restarted).receive() }
    }

    @Test
    fun corruptedKeyRecordFailsClosed() = runTest {
        val storage = reopen()
        client(BOB, storage).initialize()
        val damaged = sealedKey().flipped(30)
        driver.exec("UPDATE device_authentication_key SET sealed_key_pair = ?", damaged)

        val restarted = reopen()
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { client(BOB, restarted).initialize() }
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { client(BOB, restarted).registerDevice() }
        assertContentEquals(damaged, sealedKey(), "never replaced")
    }

    @Test
    fun failedKeyCreationRollsBackTheWholeInitialization() = runTest {
        val created = mutableListOf<FailingRecords>()
        val storage = reopen(created)
        created.last().failing = setOf("deviceAuthenticationKey")
        assertFailsWith<IllegalStateException> { client(BOB, storage).initialize() }
        assertNull(storage.identity.identity())
        assertNull(storage.deviceAuthentication.keyPair())
        assertNull(storage.preKeys.currentSignedPreKey())
        assertEquals(0, storage.preKeys.oneTimePreKeyCount())

        created.last().failing = emptySet()
        client(BOB, storage).initialize()
        assertNotNull(storage.deviceAuthentication.keyPair())
    }

    @Test
    fun failedUpgradeKeyCreationKeepsTheInstallationUpgradable() = runTest {
        client(BOB, reopen()).initialize()
        downgradeToVersion7()
        val created = mutableListOf<FailingRecords>()
        val migrated = reopen(created)
        created.last().failing = setOf("deviceAuthenticationKey")
        assertFailsWith<IllegalStateException> { client(BOB, migrated).initialize() }
        assertTrue(migrated.deviceAuthentication.awaitsUpgradeKey())
        assertNull(migrated.deviceAuthentication.keyPair())

        created.last().failing = emptySet()
        client(BOB, migrated).initialize()
        assertNotNull(migrated.deviceAuthentication.keyPair())
        assertFalse(migrated.deviceAuthentication.awaitsUpgradeKey())
    }
}
