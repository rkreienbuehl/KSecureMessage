package dev.kreienbuehl.ksecuremessage.storage.client.sqldelight

import app.cash.sqldelight.db.SqlDriver
import dev.kreienbuehl.ksecuremessage.client.PreKeyConfiguration
import dev.kreienbuehl.ksecuremessage.client.ReceiveResult
import dev.kreienbuehl.ksecuremessage.client.RemoteIdentityTrust
import dev.kreienbuehl.ksecuremessage.client.SecureMessageClient
import dev.kreienbuehl.ksecuremessage.client.SecureMessageClientException
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.PublicIdentityKey
import dev.kreienbuehl.ksecuremessage.protocol.VerificationState
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage
import dev.kreienbuehl.ksecuremessage.storage.encryption.ClientRecordCipher
import kotlinx.coroutines.test.runTest
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Instant

private val ALICE = DeviceAddress(UserId("alice"), DeviceId("phone"))
private val ALICE_LAPTOP = DeviceAddress(UserId("alice"), DeviceId("laptop"))
private val BOB = DeviceAddress(UserId("bob"), DeviceId("laptop"))

/**
 * Remote identity verification state in SQLDelight storage (milestone 15,
 * docs/identity-verification.md): persisted per pin, reset by an accepted
 * identity change, and added by schema version 10 without guessing any
 * verification for existing pins.
 */
class IdentityVerificationStorageTest {
    private val aliceDatabase = TestDatabase()
    private val bobDatabase = TestDatabase()
    private val newBobDatabase = TestDatabase()
    private val engine = KodiumProtocolEngine()
    private val network = TestRelay()
    private val clock = TestClock(Instant.fromEpochMilliseconds(1_000_000_000_000))
    private val config = PreKeyConfiguration(oneTimePreKeyTarget = 3)
    private lateinit var driver: SqlDriver

    @AfterTest
    fun close() {
        aliceDatabase.close()
        bobDatabase.close()
        newBobDatabase.close()
    }

    /** Alice's storage, reopened like after an application restart; [driver] is its connection. */
    private suspend fun reopenAlice(): SqlDelightClientStorage {
        aliceDatabase.closeOpenDrivers()
        driver = aliceDatabase.open()
        return SqlDelightClientStorage.open(driver, TestKeys.providerA)
    }

    private suspend fun open(database: TestDatabase): SqlDelightClientStorage {
        database.closeOpenDrivers()
        return SqlDelightClientStorage.open(database.open(), TestKeys.providerA)
    }

    private fun client(address: DeviceAddress, storage: ClientStorage) = SecureMessageClient(address, storage, engine, network, config, clock)

    private suspend fun started(address: DeviceAddress, storage: ClientStorage) = client(address, storage).also {
        it.initialize()
        network.publish(it)
    }

    private suspend fun SecureMessageClient.receiveOne(): ReceiveResult = decrypt(network.receive(localAddress).single())

    private suspend fun ClientStorage.publicIdentity() = PublicIdentityKey(assertNotNull(identity.identity()).publicKey)

    @Test
    fun verificationAndAcceptedChangeSurviveRestarts() = runTest {
        val alice = started(ALICE, reopenAlice())
        val bobStorage = open(bobDatabase)
        val bob = started(BOB, bobStorage)
        alice.send(BOB, "hi".encodeToByteArray())
        bob.accept(network.receive(BOB).single())
        alice.receiveOne()
        alice.markRemoteIdentityVerified(alice.safetyNumber(BOB))

        var aliceAgain = client(ALICE, reopenAlice())
        assertEquals(RemoteIdentityTrust(BOB, bobStorage.publicIdentity(), VerificationState.VERIFIED), aliceAgain.remoteIdentityTrust(BOB))
        assertEquals(listOf(1L), driver.longs("SELECT verification FROM remote_identity"))

        // Bob reinstalls and writes; Alice accepts the change and restarts.
        val newBobStorage = open(newBobDatabase)
        val newBob = started(BOB, newBobStorage)
        network.publish(aliceAgain)
        newBob.send(ALICE, "new phone".encodeToByteArray())
        val envelope = network.receive(ALICE).single()
        val changed = assertFailsWith<SecureMessageClientException.IdentityChanged> { aliceAgain.decrypt(envelope) }
        aliceAgain.acceptRemoteIdentityChange(changed.change)

        aliceAgain = client(ALICE, reopenAlice())
        assertEquals(RemoteIdentityTrust(BOB, newBobStorage.publicIdentity(), VerificationState.UNVERIFIED), aliceAgain.remoteIdentityTrust(BOB))
        assertEquals(emptyList(), driver.strings("SELECT remote_user_id FROM session"))
        assertEquals(1L, driver.longs("SELECT count(*) FROM retired_session_initiation").single())
        assertEquals("new phone", aliceAgain.accept(envelope).plaintext.decodeToString())
    }

    @Test
    fun version9DatabaseKeepsEveryRowAndPinsBecomeUnverified() = runTest {
        // A real milestone 14 state: conversation, pending message, pending recovery key, a pin.
        val aliceStorage = reopenAlice()
        val alice = started(ALICE, aliceStorage)
        val bob = started(BOB, open(bobDatabase))
        alice.send(BOB, "hi".encodeToByteArray())
        bob.accept(network.receive(BOB).single())
        alice.receiveOne()
        bob.send(ALICE, "pending at the upgrade".encodeToByteArray())
        network.receive(ALICE) // lost: pending at Bob
        alice.send(BOB, "pending too".encodeToByteArray())
        network.receive(BOB) // lost: pending at Alice
        alice.prepareDeviceAuthenticationRecovery(ALICE_LAPTOP)
        // Even a verification made on the new schema is not carried through a downgrade and upgrade.
        alice.markRemoteIdentityVerified(alice.safetyNumber(BOB))
        val identity = assertNotNull(aliceStorage.identity.identity())
        val deviceKey = assertNotNull(aliceStorage.deviceAuthentication.keyPair())
        val recoveryKey = assertNotNull(aliceStorage.deviceAuthentication.pendingRecoveryKeyPair())
        val session = assertNotNull(aliceStorage.sessions.load(BOB)).state
        val rotation = aliceStorage.storageKeyRotationStatus()

        driver.exec("DROP TABLE device_authentication_rotation_key")
        driver.exec("DROP TABLE device_authentication_last_device_recovery_key")
        driver.exec("ALTER TABLE remote_identity DROP COLUMN verification")
        driver.dropVersion13Additions()
        driver.exec("PRAGMA user_version = 9")
        val fixture = TestDatabase()
        try {
            val fixtureDriver = fixture.open(Version9Schema)
            assertEquals(fixtureDriver.tables().associateWith { fixtureDriver.columns(it) }, driver.tables().associateWith { driver.columns(it) })
        } finally {
            fixture.close()
        }
        val before = driver.dump()

        val migrated = reopenAlice()
        assertEquals(listOf(16L), driver.longs("PRAGMA user_version"))
        assertEquals(
            before.withUnverifiedPins().withLegacyProcessedMessages().withEmptyMigrationIntent(),
            driver.dump() - "device_authentication_rotation_key" - "device_authentication_last_device_recovery_key",
            "only the verification column and the empty rotation and last-device recovery key tables are new",
        )
        assertEquals(emptyList(), driver.dump().getValue("device_authentication_rotation_key"))
        assertEquals(emptyList(), driver.dump().getValue("device_authentication_last_device_recovery_key"))
        assertEquals(VerificationState.UNVERIFIED, migrated.remoteIdentities.record(BOB)?.verification)
        assertContentEquals(identity.privateKey, migrated.identity.identity()?.privateKey)
        assertContentEquals(deviceKey.privateKey, migrated.deviceAuthentication.keyPair()?.privateKey)
        assertContentEquals(recoveryKey.privateKey, migrated.deviceAuthentication.pendingRecoveryKeyPair()?.privateKey)
        assertContentEquals(session, migrated.sessions.load(BOB)?.state)
        assertEquals(rotation, migrated.storageKeyRotationStatus())

        val aliceAgain = client(ALICE, migrated)
        aliceAgain.initialize()
        assertEquals("pending too", aliceAgain.pendingMessages(limit = 100, recipient = BOB).messages.single().plaintext.decodeToString())
        assertEquals("pending at the upgrade", aliceAgain.accept(bob.retryAndTake()).plaintext.decodeToString())
        aliceAgain.markRemoteIdentityVerified(aliceAgain.safetyNumber(BOB))
        assertEquals(VerificationState.VERIFIED, aliceAgain.remoteIdentityTrust(BOB)?.verification)
    }

    private suspend fun SecureMessageClient.retryAndTake() =
        retryPendingMessages(ALICE).let { network.receive(ALICE).last() }

    @Test
    fun version9FixtureMigratesAPinAsUnverified() = runTest {
        aliceDatabase.closeOpenDrivers()
        val old = aliceDatabase.open(Version9Schema)
        old.exec("UPDATE storage_encryption SET key_id = 1, key_check = ?, highest_key_id = 1", ClientRecordCipher(TestKeys.A).sealKeyCheck())
        old.exec("INSERT INTO remote_identity (remote_user_id, remote_device_id, identity_key) VALUES ('bob', 'laptop', ?)", ByteArray(64) { 5 })
        aliceDatabase.closeOpenDrivers()

        val storage = reopenAlice()
        assertEquals(listOf(16L), driver.longs("PRAGMA user_version"))
        val record = assertNotNull(storage.remoteIdentities.record(BOB))
        assertContentEquals(ByteArray(64) { 5 }, record.identityKey)
        assertEquals(VerificationState.UNVERIFIED, record.verification)
    }

    @Test
    fun unknownVerificationCodeFailsClosed() = runTest {
        val storage = reopenAlice()
        storage.remoteIdentities.store(BOB, ByteArray(64) { 5 })
        assertFailsWith<Exception> { driver.exec("UPDATE remote_identity SET verification = 2") }
        // A damaged or foreign database without the CHECK constraint.
        driver.exec("ALTER TABLE remote_identity RENAME TO remote_identity_checked")
        driver.exec(
            "CREATE TABLE remote_identity (remote_user_id TEXT NOT NULL, remote_device_id TEXT NOT NULL, " +
                "identity_key BLOB NOT NULL, verification INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (remote_user_id, remote_device_id))",
        )
        driver.exec("INSERT INTO remote_identity SELECT remote_user_id, remote_device_id, identity_key, 2 FROM remote_identity_checked")
        driver.exec("DROP TABLE remote_identity_checked")
        assertFailsWith<IllegalStateException> { storage.remoteIdentities.record(BOB) }
        assertContentEquals(ByteArray(64) { 5 }, storage.remoteIdentities.identityKey(BOB), "the pin itself stays readable")
        assertTrue(driver.longs("SELECT verification FROM remote_identity").single() == 2L)
        assertNull(storage.remoteIdentities.record(ALICE))
    }
}
