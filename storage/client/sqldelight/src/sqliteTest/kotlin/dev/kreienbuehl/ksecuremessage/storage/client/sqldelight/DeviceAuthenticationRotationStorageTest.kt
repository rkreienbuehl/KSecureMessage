package dev.kreienbuehl.ksecuremessage.storage.client.sqldelight

import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryChallenge
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryKeyRegistration
import app.cash.sqldelight.db.SqlDriver
import dev.kreienbuehl.ksecuremessage.client.PreKeyConfiguration
import dev.kreienbuehl.ksecuremessage.client.ReceiveResult
import dev.kreienbuehl.ksecuremessage.client.SecureMessageClient
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransport
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException
import dev.kreienbuehl.ksecuremessage.client.ServerRequestSigner
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceAuthenticationRegistrationStatus
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.DeviceRegistration
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationRotation
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationRotationAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationRotationId
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecoveryAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.ServerApiPaths
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequest
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequestAuthentication
import dev.kreienbuehl.ksecuremessage.protocol.VerificationState
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
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Instant

private val ALICE = DeviceAddress(UserId("alice"), DeviceId("phone"))
private val BOB = DeviceAddress(UserId("bob"), DeviceId("laptop"))

/**
 * The pending routine rotation key in SQLDelight storage (milestone 16,
 * docs/device-authentication-rotation.md): sealed as its own record type 9,
 * kept across restarts and storage key rotation, promoted atomically,
 * resolvable after a crash between the server's commit and the local
 * promotion, and migrated into schema version 10 databases as an empty table.
 */
class DeviceAuthenticationRotationStorageTest {
    private val database = TestDatabase()
    private val engine = KodiumProtocolEngine()
    private val server = RotationServer()
    private val clock = TestClock(Instant.fromEpochMilliseconds(1_767_225_600_000))
    private val config = PreKeyConfiguration(oneTimePreKeyTarget = 3)
    private lateinit var driver: SqlDriver
    private val bob = SecureMessageClient(BOB, InMemoryClientStorage(), engine, server, config, clock)

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

    private fun alice(storage: ClientStorage) = SecureMessageClient(ALICE, storage, engine, server, config, clock)

    private fun pendingRecord(): ByteArray = driver.blob("SELECT sealed_key_pair FROM device_authentication_rotation_key")

    private fun pendingRows(): Long = driver.longs("SELECT count(*) FROM device_authentication_rotation_key").single()!!

    private fun activeRecord(): ByteArray = driver.blob("SELECT sealed_key_pair FROM device_authentication_key")

    /** Alice (SQLDelight) and Bob registered with prekeys; Bob sent Alice one message she read. Returns Alice's storage. */
    private suspend fun registered(): SqlDelightClientStorage {
        val storage = reopen()
        val alice = alice(storage)
        for (client in listOf(alice, bob)) {
            client.initialize()
            client.registerDevice()
            client.publishPreKeys()
        }
        bob.send(ALICE, "before".encodeToByteArray())
        assertIs<ReceiveResult.Message>(alice.decrypt(alice.receive().single()))
        bob.receive().forEach { bob.decrypt(it) } // the ACK
        return storage
    }

    @Test
    fun pendingKeyIsSealedAndSurvivesRestarts() = runTest {
        val storage = registered()
        val k1 = assertNotNull(storage.deviceAuthentication.keyPair())
        alice(storage).prepareDeviceAuthenticationRotation()
        val pending = assertNotNull(storage.deviceAuthentication.pendingRotationKeyPair())

        val sealed = pendingRecord()
        assertTrue(sealed.isSealed())
        for (row in driver.dump().values.flatten()) {
            assertFalse(row.orEmpty().contains(pending.privateKey.toHex(), ignoreCase = true), "pending private key in plaintext")
        }
        assertEquals(0L, driver.longs("SELECT count(*) FROM device_authentication_recovery_key").single(), "not a recovery key")

        val restarted = reopen()
        alice(restarted).prepareDeviceAuthenticationRotation()
        assertContentEquals(pending.privateKey, restarted.deviceAuthentication.pendingRotationKeyPair()?.privateKey, "same K2 after a restart")
        assertContentEquals(sealed, pendingRecord(), "not rewritten")
        assertContentEquals(k1.privateKey, restarted.deviceAuthentication.keyPair()?.privateKey, "K1 still active")
        assertEquals(0, server.rotationAttempts.size)
        alice(restarted).receive() // signed with K1
    }

    @Test
    fun completedRotationIsPromotedAndSurvivesRestarts() = runTest {
        val storage = registered()
        alice(storage).prepareDeviceAuthenticationRotation()
        val k2 = assertNotNull(storage.deviceAuthentication.pendingRotationKeyPair())
        alice(reopen()).completeDeviceAuthenticationRotation()
        assertEquals(0L, pendingRows())

        val restarted = reopen()
        assertContentEquals(k2.privateKey, restarted.deviceAuthentication.keyPair()?.privateKey)
        assertNull(restarted.deviceAuthentication.pendingRotationKeyPair())
        assertTrue(activeRecord().isSealed())
        assertEquals(1, SealedRecords.keyId(activeRecord()).value)
        alice(restarted).initialize()
        alice(restarted).receive() // signed with K2
        assertEquals(2L, server.epochs[ALICE])
    }

    @Test
    fun crashBetweenServerCommitAndPromotionIsResolvedAfterRestart() = runTest {
        registered()
        val created = mutableListOf<FailingRecords>()
        val failing = reopen(created)
        alice(failing).prepareDeviceAuthenticationRotation()
        val k2 = assertNotNull(failing.deviceAuthentication.pendingRotationKeyPair())
        // Promotion reseals the pending key as the active key: that seal fails, like a crash before the commit.
        created.last().failing = setOf("deviceAuthenticationKey")
        assertFailsWith<IllegalStateException> { alice(failing).completeDeviceAuthenticationRotation() }
        assertEquals(2L, server.epochs[ALICE], "the server committed K2")
        assertEquals(1L, pendingRows(), "K2 survived")

        val restarted = reopen()
        assertTrue(alice(restarted).resolveDeviceAuthenticationRotation())
        assertEquals(0L, pendingRows())
        assertContentEquals(k2.privateKey, reopen().deviceAuthentication.keyPair()?.privateKey)
        assertEquals(2L, server.epochs[ALICE], "no second transition")
        assertEquals(1, server.rotationAttempts.size)
    }

    @Test
    fun lostResponseIsResolvedByTheNextCompletionAfterRestart() = runTest {
        registered()
        alice(reopen()).prepareDeviceAuthenticationRotation()
        server.afterRotation = {
            server.afterRotation = {}
            throw SecureMessageTransportException.UnexpectedResponse(504)
        }
        assertFailsWith<SecureMessageTransportException.UnexpectedResponse> { alice(reopen()).completeDeviceAuthenticationRotation() }
        val restarted = reopen()
        alice(restarted).completeDeviceAuthenticationRotation()
        assertEquals(0L, pendingRows())
        assertContentEquals(server.keys[ALICE], restarted.deviceAuthentication.keyPair()?.publicKey)
        assertEquals(2L, server.epochs[ALICE])
    }

    @Test
    fun failedPendingKeyCreationStoresNothing() = runTest {
        registered()
        val created = mutableListOf<FailingRecords>()
        val storage = reopen(created)
        val k1 = activeRecord()
        created.last().failing = setOf("deviceAuthenticationRotationKey")
        assertFailsWith<IllegalStateException> { alice(storage).prepareDeviceAuthenticationRotation() }
        assertEquals(0L, pendingRows())
        assertContentEquals(k1, activeRecord())
    }

    @Test
    fun storageKeyRotationReEncryptsThePendingKey() = runTest {
        registered()
        alice(reopen()).prepareDeviceAuthenticationRotation()
        val k2 = assertNotNull(reopen().deviceAuthentication.pendingRotationKeyPair())
        assertEquals(1, SealedRecords.keyId(pendingRecord()).value)

        val provider = MemoryKeyStore().apply { put("rotation", TestKeys.A) }.provider("rotation")
        val rotating = reopen(provider = provider)
        rotating.rotateStorageKey()
        // One record per batch: the pending key is migrated like every other sealed record, then key 1 is retired.
        completeStorageKeyRotation { rotating.resumeStorageKeyRotation(1) }
        assertEquals(2, SealedRecords.keyId(pendingRecord()).value, "re-encrypted with the new storage key")
        assertEquals(0L, rotating.storageKeyRotationStatus().remainingRecords)

        val reopened = reopen(provider = provider)
        assertContentEquals(k2.privateKey, reopened.deviceAuthentication.pendingRotationKeyPair()?.privateKey, "K2 survived storage key rotation")
        alice(reopened).completeDeviceAuthenticationRotation()
        assertContentEquals(k2.privateKey, reopened.deviceAuthentication.keyPair()?.privateKey)
        assertEquals(2, SealedRecords.keyId(activeRecord()).value)
    }

    @Test
    fun pendingKeyWrittenDuringAStorageKeyRotationUsesTheNewKey() = runTest {
        registered()
        val provider = MemoryKeyStore().apply { put("rotation", TestKeys.A) }.provider("rotation")
        val rotating = reopen(provider = provider)
        rotating.rotateStorageKey() // MIGRATING: new records already use key 2
        alice(rotating).prepareDeviceAuthenticationRotation()
        assertEquals(2, SealedRecords.keyId(pendingRecord()).value)
        completeStorageKeyRotation { rotating.resumeStorageKeyRotation(1) }
        alice(reopen(provider = provider)).completeDeviceAuthenticationRotation()
        assertEquals(0L, pendingRows())
    }

    @Test
    fun corruptedPendingRecordFailsClosed() = runTest {
        registered()
        alice(reopen()).prepareDeviceAuthenticationRotation()
        val damaged = pendingRecord().flipped(30)
        driver.exec("UPDATE device_authentication_rotation_key SET sealed_key_pair = ?", damaged)

        val storage = reopen()
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { alice(storage).prepareDeviceAuthenticationRotation() }
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { alice(storage).completeDeviceAuthenticationRotation() }
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { alice(storage).prepareDeviceAuthenticationRecovery(DeviceAddress(UserId("alice"), DeviceId("laptop"))) }
        assertContentEquals(damaged, pendingRecord(), "never replaced by a new key")
        assertEquals(0, server.rotationAttempts.size, "nothing submitted")
        assertEquals(1L, server.epochs[ALICE])
    }

    @Test
    fun recordsDoNotOpenAsAnotherDeviceAuthenticationRecordType() = runTest {
        registered()
        alice(reopen()).prepareDeviceAuthenticationRotation()
        val rotationRecord = pendingRecord()
        val active = activeRecord()

        // The rotation record in the active slot and in the recovery slot.
        driver.exec("UPDATE device_authentication_key SET sealed_key_pair = ?", rotationRecord)
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { reopen().deviceAuthentication.keyPair() }
        driver.exec("UPDATE device_authentication_key SET sealed_key_pair = ?", active)
        driver.exec("INSERT INTO device_authentication_recovery_key (id, sealed_key_pair) VALUES (0, ?)", rotationRecord)
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { reopen().deviceAuthentication.pendingRecoveryKeyPair() }
        driver.exec("DELETE FROM device_authentication_recovery_key")
        // The active record in the rotation slot.
        driver.exec("UPDATE device_authentication_rotation_key SET sealed_key_pair = ?", active)
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { reopen().deviceAuthentication.pendingRotationKeyPair() }
    }

    @Test
    fun rotationKeepsMessagingStateAndVerification() = runTest {
        val storage = registered()
        val alice = alice(storage)
        alice.markRemoteIdentityVerified(alice.safetyNumber(BOB))
        alice.send(BOB, "pending".encodeToByteArray())
        server.mailboxes.remove(BOB) // lost: stays pending
        val before = driver.dump()

        alice.rotateDeviceAuthenticationKey()

        val after = driver.dump()
        val authTables = setOf("device_authentication_key", "device_authentication_rotation_key", "authentication_nonce")
        assertEquals(before - authTables, after - authTables, "no messaging row changed")
        assertEquals(VerificationState.VERIFIED, alice(reopen()).remoteIdentityTrust(BOB)?.verification)
        assertEquals("pending", alice(reopen()).pendingMessages(BOB).single().plaintext.decodeToString())
    }

    @Test
    fun version10FixtureMigratesWithAnEmptyRotationTable() = runTest {
        // A full database, turned back into schema version 10.
        val storage = registered()
        val alice = alice(storage)
        alice.markRemoteIdentityVerified(alice.safetyNumber(BOB))
        alice.send(BOB, "pending at the upgrade".encodeToByteArray())
        server.mailboxes.remove(BOB)
        alice.prepareDeviceAuthenticationRecovery(DeviceAddress(UserId("alice"), DeviceId("laptop")))
        val identity = assertNotNull(storage.identity.identity())
        val deviceKey = assertNotNull(storage.deviceAuthentication.keyPair())
        val recoveryKey = assertNotNull(storage.deviceAuthentication.pendingRecoveryKeyPair())
        val rotation = storage.storageKeyRotationStatus()

        driver.exec("DROP TABLE device_authentication_rotation_key")
        driver.exec("DROP TABLE device_authentication_last_device_recovery_key")
        driver.exec("PRAGMA user_version = 10")
        val fixture = TestDatabase()
        try {
            val fixtureDriver = fixture.open(Version10Schema)
            assertEquals(fixtureDriver.tables().associateWith { fixtureDriver.columns(it) }, driver.tables().associateWith { driver.columns(it) })
        } finally {
            fixture.close()
        }
        val before = driver.dump()

        val migrated = reopen()
        assertEquals(listOf(12L), driver.longs("PRAGMA user_version"))
        val after = driver.dump()
        assertEquals(before, after - "device_authentication_rotation_key" - "device_authentication_last_device_recovery_key", "no existing row changes")
        assertEquals(emptyList(), after.getValue("device_authentication_rotation_key"))
        assertEquals(emptyList(), after.getValue("device_authentication_last_device_recovery_key"))
        assertContentEquals(identity.privateKey, migrated.identity.identity()?.privateKey)
        assertContentEquals(deviceKey.privateKey, migrated.deviceAuthentication.keyPair()?.privateKey)
        assertContentEquals(recoveryKey.privateKey, migrated.deviceAuthentication.pendingRecoveryKeyPair()?.privateKey)
        assertNull(migrated.deviceAuthentication.pendingRotationKeyPair())
        assertEquals(rotation, migrated.storageKeyRotationStatus())
        assertEquals(VerificationState.VERIFIED, alice(migrated).remoteIdentityTrust(BOB)?.verification, "verification kept")
        assertEquals("pending at the upgrade", alice(migrated).pendingMessages(BOB).single().plaintext.decodeToString())

        // After the upgrade, a rotation works (once the recovery is cancelled).
        alice(migrated).cancelDeviceAuthenticationRecovery()
        alice(migrated).rotateDeviceAuthenticationKey()
        assertEquals(2L, server.epochs[ALICE])
    }

    @Test
    fun downgradedDatabaseMatchesTheVersion10Fixture() = runTest {
        alice(reopen()).initialize()
        driver.exec("DROP TABLE device_authentication_rotation_key")
        driver.exec("DROP TABLE device_authentication_last_device_recovery_key")
        driver.exec("PRAGMA user_version = 10")
        val downgraded = driver.tables().associateWith { driver.columns(it) }
        val fixture = TestDatabase()
        try {
            val fixtureDriver = fixture.open(Version10Schema)
            assertEquals(fixtureDriver.tables().associateWith { fixtureDriver.columns(it) }, downgraded)
        } finally {
            fixture.close()
        }
    }

    /**
     * The server side as far as these tests need it: TOFU registration with
     * proof of possession, the signed epoch read, routine rotation with both
     * proofs, CAS on key and epoch and exact-retry recognition, prekey
     * bundles and mailboxes. No time window.
     */
    private class RotationServer : SecureMessageTransport {
        val keys = mutableMapOf<DeviceAddress, ByteArray>()
        val epochs = mutableMapOf<DeviceAddress, Long>()
        private val rotationIds = mutableMapOf<DeviceAddress, DeviceAuthenticationRotationId>()
        private val bundles = mutableMapOf<DeviceAddress, PreKeyBundle>()
        val mailboxes = mutableMapOf<DeviceAddress, MutableList<EncryptedEnvelope>>()
        val rotationAttempts = mutableListOf<DeviceAuthenticationRotationAuthorization>()
        var afterRotation: () -> Unit = {}

        private suspend fun verify(address: DeviceAddress, endpoint: String, method: String, key: ByteArray?, signer: ServerRequestSigner) {
            val request = ServerRequest(address, method, ServerApiPaths.device(address, endpoint), ByteArray(0))
            if (key == null || !ServerRequestAuthentication.verify(key, request, signer.sign(request))) {
                throw SecureMessageTransportException.AuthenticationFailed(SecureMessageTransportException.AuthenticationFailure.INVALID)
            }
        }

        override suspend fun registerDevice(registration: DeviceRegistration, signer: ServerRequestSigner) {
            verify(registration.address, ServerApiPaths.REGISTRATION, "PUT", registration.publicKey, signer)
            val existing = keys.getOrPut(registration.address) { registration.publicKey.also { epochs[registration.address] = 1 } }
            if (!existing.contentEquals(registration.publicKey)) throw SecureMessageTransportException.DeviceRegistrationConflict()
        }

        override suspend fun registrationStatus(address: DeviceAddress, signer: ServerRequestSigner): DeviceAuthenticationRegistrationStatus {
            verify(address, ServerApiPaths.REGISTRATION, "GET", keys[address], signer)
            return DeviceAuthenticationRegistrationStatus(epochs.getValue(address), Instant.fromEpochMilliseconds(0))
        }

        override suspend fun registerLastDeviceRecoveryKey(address: DeviceAddress, registration: LastDeviceRecoveryKeyRegistration, signer: ServerRequestSigner) =
            error("not used")

        override suspend fun lastDeviceRecoveryChallenge(target: DeviceAddress): LastDeviceRecoveryChallenge = error("not used")

        override suspend fun lastDeviceRecoveryKeyStatus(
            address: dev.kreienbuehl.ksecuremessage.model.DeviceAddress,
            signer: dev.kreienbuehl.ksecuremessage.client.ServerRequestSigner,
        ): dev.kreienbuehl.ksecuremessage.model.LastDeviceRecoveryKeyStatus = error("not used")

        override suspend fun rotateLastDeviceRecoveryKey(
            authorization: dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRotationAuthorization,
            signer: dev.kreienbuehl.ksecuremessage.client.ServerRequestSigner,
        ) = error("not used")

        override suspend fun revokeLastDeviceRecoveryKey(
            authorization: dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRevocationAuthorization,
            signer: dev.kreienbuehl.ksecuremessage.client.ServerRequestSigner,
        ) = error("not used")

        override suspend fun recoverLastDevice(authorization: LastDeviceRecoveryAuthorization) = error("not used")

        override suspend fun rotateDeviceAuthenticationKey(authorization: DeviceAuthenticationRotationAuthorization) {
            rotationAttempts += authorization
            val statement = authorization.statement
            val address = statement.address
            val id = DeviceAuthenticationRotation.rotationId(statement)
            fun reject(failure: SecureMessageTransportException.RotationFailure): Nothing =
                throw SecureMessageTransportException.DeviceAuthenticationRotationRejected(failure)
            val registered = keys[address] ?: reject(SecureMessageTransportException.RotationFailure.NOT_REGISTERED)
            if (rotationIds[address] != id) {
                if (!registered.contentEquals(statement.currentPublicKey) || epochs[address] != statement.expectedAuthEpoch) {
                    reject(SecureMessageTransportException.RotationFailure.CONFLICT)
                }
                if (!DeviceAuthenticationRotation.verifyAuthorization(registered, authorization) ||
                    !DeviceAuthenticationRotation.verifyProofOfPossession(authorization)
                ) {
                    reject(SecureMessageTransportException.RotationFailure.INVALID_PROOF)
                }
                keys[address] = statement.replacementPublicKey
                epochs[address] = statement.expectedAuthEpoch + 1
                rotationIds[address] = id
            }
            afterRotation()
        }

        override suspend fun recoverDevice(authorization: DeviceRecoveryAuthorization) = error("not used")

        override suspend fun publishPreKeys(publication: PreKeyPublication, signer: ServerRequestSigner) {
            verify(publication.address, ServerApiPaths.PRE_KEYS, "PUT", keys[publication.address], signer)
            bundles[publication.address] = PreKeyBundle(publication.address, publication.identityKey, publication.signedPreKey, publication.oneTimePreKeys.firstOrNull())
        }

        override suspend fun fetchPreKeyBundle(address: DeviceAddress): PreKeyBundle = bundles.getValue(address)

        override suspend fun send(envelope: EncryptedEnvelope) {
            mailboxes.getOrPut(envelope.recipient) { mutableListOf() }.add(envelope)
        }

        override suspend fun receive(address: DeviceAddress, signer: ServerRequestSigner): List<EncryptedEnvelope> {
            verify(address, ServerApiPaths.MESSAGES, "GET", keys[address], signer)
            return mailboxes.remove(address)?.toList().orEmpty()
        }
    }
}
