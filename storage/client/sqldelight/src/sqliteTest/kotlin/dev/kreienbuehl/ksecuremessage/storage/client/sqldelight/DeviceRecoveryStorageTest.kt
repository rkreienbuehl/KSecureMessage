package dev.kreienbuehl.ksecuremessage.storage.client.sqldelight

import app.cash.sqldelight.db.SqlDriver
import dev.kreienbuehl.ksecuremessage.client.PreKeyConfiguration
import dev.kreienbuehl.ksecuremessage.client.SecureMessageClient
import dev.kreienbuehl.ksecuremessage.client.SecureMessageClientException
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransport
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException
import dev.kreienbuehl.ksecuremessage.client.ServerRequestSigner
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.DeviceRegistration
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecovery
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecoveryAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.ServerApiPaths
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequest
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequestAuthentication
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage
import dev.kreienbuehl.ksecuremessage.storage.client.inmemory.InMemoryClientStorage
import dev.kreienbuehl.ksecuremessage.storage.encryption.SealedRecords
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageEncryptionException
import kotlinx.coroutines.test.runTest
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Instant

private val PHONE = DeviceAddress(UserId("alice"), DeviceId("phone"))
private val LAPTOP = DeviceAddress(UserId("alice"), DeviceId("laptop"))

/**
 * The pending device recovery key in SQLDelight storage (milestone 14,
 * docs/device-recovery.md): sealed as its own record type, kept across
 * restarts and storage key rotation, promoted atomically, and migrated into
 * schema version 8 databases as an empty table.
 */
class DeviceRecoveryStorageTest {
    private val database = TestDatabase()
    private val engine = KodiumProtocolEngine()
    private val server = RecoveryServer()
    private val clock = TestClock(Instant.fromEpochMilliseconds(1_767_225_600_000))
    private val config = PreKeyConfiguration(oneTimePreKeyTarget = 3)
    private lateinit var driver: SqlDriver
    private val phone = SecureMessageClient(PHONE, InMemoryClientStorage(), engine, server, config, clock)

    @AfterTest
    fun close() = database.close()

    private suspend fun reopen(
        records: MutableList<FailingRecords>? = null,
        provider: dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyProvider = TestKeys.providerA,
    ): SqlDelightClientStorage {
        database.closeOpenDrivers()
        driver = database.open()
        return if (records == null) {
            SqlDelightClientStorage.open(driver, provider)
        } else {
            SqlDelightClientStorage.open(driver, provider, FailingRecords.factory(records))
        }
    }

    private fun laptop(storage: ClientStorage) = SecureMessageClient(LAPTOP, storage, engine, server, config, clock)

    private fun pendingRecord(): ByteArray = driver.blob("SELECT sealed_key_pair FROM device_authentication_recovery_key")

    private fun pendingRows(): Long = driver.longs("SELECT count(*) FROM device_authentication_recovery_key").single()!!

    /** Phone and laptop registered; the laptop's active key row is then deleted, as if lost. */
    private suspend fun lostLaptop(): ByteArray {
        phone.initialize()
        phone.registerDevice()
        val storage = reopen()
        laptop(storage).initialize()
        laptop(storage).registerDevice()
        val lost = assertNotNull(storage.deviceAuthentication.keyPair()).publicKey
        driver.exec("DELETE FROM device_authentication_key")
        return lost
    }

    @Test
    fun pendingKeyIsSealedAndSurvivesRestarts() = runTest {
        lostLaptop()
        val storage = reopen()
        assertFailsWith<SecureMessageClientException.InconsistentStorage> { laptop(storage).initialize() }
        val first = laptop(storage).prepareDeviceAuthenticationRecovery(PHONE)
        val pending = assertNotNull(storage.deviceAuthentication.pendingRecoveryKeyPair())

        val sealed = pendingRecord()
        assertTrue(sealed.isSealed())
        for (row in driver.dump().values.flatten()) {
            assertFalse(row.orEmpty().contains(pending.privateKey.toHex(), ignoreCase = true), "pending private key in plaintext")
        }
        assertEquals(listOf(0L), driver.longs("SELECT count(*) FROM device_authentication_key"), "no active key created")

        val restarted = reopen()
        val second = laptop(restarted).prepareDeviceAuthenticationRecovery(PHONE)
        assertContentEquals(first.replacementPublicKey, second.replacementPublicKey, "same pending key after a restart")
        assertContentEquals(sealed, pendingRecord(), "not rewritten")
        assertFailsWith<SecureMessageClientException.InconsistentStorage> { laptop(restarted).initialize() }
    }

    @Test
    fun completedRecoveryIsPromotedAndSurvivesRestarts() = runTest {
        lostLaptop()
        val request = laptop(reopen()).prepareDeviceAuthenticationRecovery(PHONE)
        val authorization = phone.authorizeDeviceRecovery(request)
        laptop(reopen()).completeDeviceAuthenticationRecovery(authorization)
        assertEquals(0L, pendingRows())

        val restarted = reopen()
        assertContentEquals(request.replacementPublicKey, restarted.deviceAuthentication.keyPair()?.publicKey)
        assertNull(restarted.deviceAuthentication.pendingRecoveryKeyPair())
        assertTrue(driver.blob("SELECT sealed_key_pair FROM device_authentication_key").isSealed())
        laptop(restarted).initialize()
        laptop(restarted).receive() // signed with the recovered key
        assertEquals(0L, driver.longs("SELECT awaits_upgrade_key FROM device_authentication_state").single())
    }

    @Test
    fun storageKeyRotationReEncryptsThePendingKey() = runTest {
        lostLaptop()
        val request = laptop(reopen()).prepareDeviceAuthenticationRecovery(PHONE)
        assertEquals(1, SealedRecords.keyId(pendingRecord()).value)

        val provider = MemoryKeyStore().apply { put("recovery", TestKeys.A) }.provider("recovery")
        val rotating = reopen(provider = provider)
        rotating.rotateStorageKey()
        completeStorageKeyRotation { rotating.resumeStorageKeyRotation(1) }
        assertEquals(2, SealedRecords.keyId(pendingRecord()).value, "re-encrypted with the new storage key")

        val reopened = reopen(provider = provider)
        val again = laptop(reopened).prepareDeviceAuthenticationRecovery(PHONE)
        assertContentEquals(request.replacementPublicKey, again.replacementPublicKey, "the candidate key survived rotation")
        laptop(reopened).completeDeviceAuthenticationRecovery(phone.authorizeDeviceRecovery(again))
        assertContentEquals(request.replacementPublicKey, reopened.deviceAuthentication.keyPair()?.publicKey)
    }

    @Test
    fun corruptedPendingRecordFailsClosed() = runTest {
        lostLaptop()
        val request = laptop(reopen()).prepareDeviceAuthenticationRecovery(PHONE)
        val authorization = phone.authorizeDeviceRecovery(request)
        val damaged = pendingRecord().flipped(30)
        driver.exec("UPDATE device_authentication_recovery_key SET sealed_key_pair = ?", damaged)

        val storage = reopen()
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { laptop(storage).prepareDeviceAuthenticationRecovery(PHONE) }
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { laptop(storage).completeDeviceAuthenticationRecovery(authorization) }
        assertContentEquals(damaged, pendingRecord(), "never replaced by a new key")
        assertEquals(0, server.recoveries, "nothing submitted")
    }

    @Test
    fun activeRecordDoesNotOpenAsPendingAndBack() = runTest {
        lostLaptop()
        laptop(reopen()).prepareDeviceAuthenticationRecovery(PHONE)
        val pending = pendingRecord()
        driver.exec("INSERT INTO device_authentication_key (id, sealed_key_pair) VALUES (0, ?)", pending)
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { reopen().deviceAuthentication.keyPair() }
    }

    @Test
    fun failedPromotionKeepsThePendingKey() = runTest {
        lostLaptop()
        val created = mutableListOf<FailingRecords>()
        val storage = reopen(created)
        val request = laptop(storage).prepareDeviceAuthenticationRecovery(PHONE)
        created.last().failing = setOf("deviceAuthenticationKey")
        assertFailsWith<IllegalStateException> { laptop(storage).completeDeviceAuthenticationRecovery(phone.authorizeDeviceRecovery(request)) }
        assertEquals(1L, pendingRows())
        assertEquals(listOf(0L), driver.longs("SELECT count(*) FROM device_authentication_key"))

        created.last().failing = emptySet()
        assertTrue(laptop(reopen()).resolveDeviceAuthenticationRecovery(), "the server has the pending key")
        assertEquals(0L, pendingRows())
        assertContentEquals(request.replacementPublicKey, reopen().deviceAuthentication.keyPair()?.publicKey)
    }

    @Test
    fun failedPendingKeyCreationStoresNothing() = runTest {
        lostLaptop()
        val created = mutableListOf<FailingRecords>()
        val storage = reopen(created)
        created.last().failing = setOf("deviceAuthenticationRecoveryKey")
        assertFailsWith<IllegalStateException> { laptop(storage).prepareDeviceAuthenticationRecovery(PHONE) }
        assertEquals(0L, pendingRows())
    }

    @Test
    fun version8FixtureMigratesWithAnEmptyRecoveryTable() = runTest {
        val old = database.open(Version8Schema)
        old.exec("UPDATE storage_encryption SET key_id = 1, key_check = ?, highest_key_id = 1", dev.kreienbuehl.ksecuremessage.storage.encryption.ClientRecordCipher(TestKeys.A).sealKeyCheck())
        val before = old.dump()
        database.closeOpenDrivers()

        val storage = reopen()
        assertEquals(listOf(9L), driver.longs("PRAGMA user_version"))
        val after = driver.dump()
        assertEquals(before, after - "device_authentication_recovery_key", "no existing row changes")
        assertEquals(emptyList(), after.getValue("device_authentication_recovery_key"))
        assertNull(storage.deviceAuthentication.pendingRecoveryKeyPair())
    }

    @Test
    fun downgradedDatabaseMatchesTheVersion8Fixture() = runTest {
        laptop(reopen()).initialize()
        driver.exec("DROP TABLE device_authentication_recovery_key")
        driver.exec("PRAGMA user_version = 8")
        val downgraded = driver.tables().associateWith { driver.columns(it) }
        val fixture = TestDatabase()
        try {
            val fixtureDriver = fixture.open(Version8Schema)
            assertEquals(fixtureDriver.tables().associateWith { fixtureDriver.columns(it) }, downgraded)
        } finally {
            fixture.close()
        }
    }

    /**
     * The server side of registration and recovery as far as these tests
     * need it: TOFU registration with proof of possession, recovery with
     * both proofs against the registered authorizer key. No time window.
     */
    private class RecoveryServer : SecureMessageTransport {
        private val keys = mutableMapOf<DeviceAddress, ByteArray>()
        var recoveries = 0
            private set

        private suspend fun verify(address: DeviceAddress, endpoint: String, method: String, body: ByteArray, key: ByteArray, signer: ServerRequestSigner) {
            val request = ServerRequest(address, method, ServerApiPaths.device(address, endpoint), body)
            check(ServerRequestAuthentication.verify(key, request, signer.sign(request))) { "bad signature" }
        }

        override suspend fun registerDevice(registration: DeviceRegistration, signer: ServerRequestSigner) {
            verify(registration.address, ServerApiPaths.REGISTRATION, "PUT", ByteArray(0), registration.publicKey, signer)
            val existing = keys.getOrPut(registration.address) { registration.publicKey }
            if (!existing.contentEquals(registration.publicKey)) throw SecureMessageTransportException.DeviceRegistrationConflict()
        }

        override suspend fun recoverDevice(authorization: DeviceRecoveryAuthorization) {
            recoveries++
            val request = authorization.request
            val authorizerKey = keys.getValue(request.authorizer)
            check(DeviceRecovery.verifyAuthorization(authorizerKey, authorization) && DeviceRecovery.verifyProofOfPossession(request))
            keys[request.target] = request.replacementPublicKey
        }

        override suspend fun receive(address: DeviceAddress, signer: ServerRequestSigner): List<EncryptedEnvelope> {
            verify(address, ServerApiPaths.MESSAGES, "GET", ByteArray(0), keys.getValue(address), signer)
            return emptyList()
        }

        override suspend fun publishPreKeys(publication: PreKeyPublication, signer: ServerRequestSigner) = error("not used")

        override suspend fun fetchPreKeyBundle(address: DeviceAddress): PreKeyBundle = error("not used")

        override suspend fun send(envelope: EncryptedEnvelope) = error("not used")
    }
}
