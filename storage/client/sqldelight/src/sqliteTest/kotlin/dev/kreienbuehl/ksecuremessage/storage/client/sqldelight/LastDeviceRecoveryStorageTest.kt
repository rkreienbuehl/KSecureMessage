package dev.kreienbuehl.ksecuremessage.storage.client.sqldelight

import app.cash.sqldelight.db.SqlDriver
import dev.kreienbuehl.ksecuremessage.client.PreKeyConfiguration
import dev.kreienbuehl.ksecuremessage.client.SecureMessageClient
import dev.kreienbuehl.ksecuremessage.client.SecureMessageClientException
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransport
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException
import dev.kreienbuehl.ksecuremessage.client.ServerRequestSigner
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceAuthenticationRegistrationStatus
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.DeviceRegistration
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.LastDeviceRecoveryKeyStatus
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationRotationAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecoveryAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecovery
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryChallenge
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryChallengeId
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryId
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryKey
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryKeyRegistration
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRevocationAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRotationAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.ServerApiPaths
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequest
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequestAuthentication
import dev.kreienbuehl.ksecuremessage.protocol.VerificationState
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage
import dev.kreienbuehl.ksecuremessage.storage.client.inmemory.InMemoryClientStorage
import dev.kreienbuehl.ksecuremessage.storage.encryption.SealedRecords
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageEncryptionException
import kotlinx.coroutines.test.runTest
import kotlin.random.Random
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

private val ALICE = DeviceAddress(UserId("alice"), DeviceId("phone"))
private val BOB = DeviceAddress(UserId("bob"), DeviceId("laptop"))
private const val TABLE = "device_authentication_last_device_recovery_key"

/**
 * The pending last-device recovery key in SQLDelight storage (milestone 18,
 * docs/last-device-recovery.md): sealed as its own record type 10, kept
 * across restarts and storage key rotation, promoted atomically, resolvable
 * after a crash between the server's commit and the local promotion, and
 * migrated into schema version 11 databases as an empty table. The offline
 * recovery key itself is never stored.
 */
class LastDeviceRecoveryStorageTest {
    private val database = TestDatabase()
    private val engine = KodiumProtocolEngine()
    private val server = RecoveryServer()
    private val clock = TestClock(Instant.fromEpochMilliseconds(1_767_225_600_000))
    private val config = PreKeyConfiguration(oneTimePreKeyTarget = 3)
    private lateinit var driver: SqlDriver
    private val bob = SecureMessageClient(BOB, InMemoryClientStorage(), engine, server, config, clock)
    private lateinit var recoveryKey: LastDeviceRecoveryKey

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

    private fun pendingRecord(): ByteArray = driver.blob("SELECT sealed_key_pair FROM $TABLE")

    private fun pendingRows(): Long = driver.longs("SELECT count(*) FROM $TABLE").single()!!

    private fun activeRecord(): ByteArray = driver.blob("SELECT sealed_key_pair FROM device_authentication_key")

    /**
     * Alice (SQLDelight, her only device) and Bob registered with prekeys;
     * Alice registered her offline recovery key; Bob sent Alice one message
     * she read; then Alice lost her device authentication key (the row is
     * deleted, as after a damaged backup restore).
     */
    private suspend fun lost(): SqlDelightClientStorage {
        val storage = reopen()
        val alice = alice(storage)
        for (client in listOf(alice, bob)) {
            client.initialize()
            client.registerDevice()
            client.publishPreKeys()
        }
        recoveryKey = alice.createLastDeviceRecoveryKey()
        alice.registerLastDeviceRecoveryKey(recoveryKey)
        bob.send(ALICE, "before".encodeToByteArray())
        alice.accept(alice.receive().single())
        bob.receive().forEach { bob.decrypt(it) } // the ACK
        driver.exec("DELETE FROM device_authentication_key")
        return reopen()
    }

    @Test
    fun pendingKeyIsSealedAndSurvivesRestarts() = runTest {
        val storage = lost()
        assertFailsWith<SecureMessageClientException.InconsistentStorage> { alice(storage).initialize() }
        alice(storage).prepareLastDeviceRecovery()
        val pending = assertNotNull(storage.deviceAuthentication.pendingLastDeviceRecoveryKeyPair())

        val sealed = pendingRecord()
        assertTrue(sealed.isSealed())
        for (row in driver.dump().values.flatten()) {
            assertFalse(row.orEmpty().contains(pending.privateKey.toHex(), ignoreCase = true), "pending private key in plaintext")
            assertFalse(row.orEmpty().contains(recoveryKey.encode()), "the recovery key is never stored")
        }
        assertEquals(0L, driver.longs("SELECT count(*) FROM device_authentication_recovery_key").single(), "not a device recovery key")
        assertEquals(0L, driver.longs("SELECT count(*) FROM device_authentication_rotation_key").single(), "not a rotation key")

        val restarted = reopen()
        alice(restarted).prepareLastDeviceRecovery()
        assertContentEquals(pending.privateKey, restarted.deviceAuthentication.pendingLastDeviceRecoveryKeyPair()?.privateKey, "same key after a restart")
        assertContentEquals(sealed, pendingRecord(), "not rewritten")
        assertEquals(0, server.attempts, "nothing sent")
    }

    @Test
    fun completedRecoveryIsPromotedAndSurvivesRestarts() = runTest {
        val storage = lost()
        alice(storage).prepareLastDeviceRecovery()
        val k2 = assertNotNull(storage.deviceAuthentication.pendingLastDeviceRecoveryKeyPair())
        alice(reopen()).completeLastDeviceRecovery(recoveryKey)
        assertEquals(0L, pendingRows())

        val restarted = reopen()
        assertContentEquals(k2.privateKey, restarted.deviceAuthentication.keyPair()?.privateKey)
        assertNull(restarted.deviceAuthentication.pendingLastDeviceRecoveryKeyPair())
        assertTrue(activeRecord().isSealed())
        alice(restarted).initialize()
        alice(restarted).receive() // signed with K2
        assertEquals(2L, server.epochs[ALICE])
    }

    @Test
    fun crashBetweenServerCommitAndPromotionIsResolvedAfterRestart() = runTest {
        lost()
        val created = mutableListOf<FailingRecords>()
        val failing = reopen(created)
        alice(failing).prepareLastDeviceRecovery()
        val k2 = assertNotNull(failing.deviceAuthentication.pendingLastDeviceRecoveryKeyPair())
        // Promotion reseals the pending key as the active key: that seal fails, like a crash before the commit.
        created.last().failing = setOf("deviceAuthenticationKey")
        assertFailsWith<IllegalStateException> { alice(failing).completeLastDeviceRecovery(recoveryKey) }
        assertEquals(2L, server.epochs[ALICE], "the server committed K2")
        assertEquals(1L, pendingRows(), "K2 survived")

        val restarted = reopen()
        assertTrue(alice(restarted).resolveLastDeviceRecovery())
        assertEquals(0L, pendingRows())
        assertContentEquals(k2.privateKey, reopen().deviceAuthentication.keyPair()?.privateKey)
        assertEquals(2L, server.epochs[ALICE], "no second transition")
        assertEquals(1, server.attempts)
    }

    @Test
    fun lostResponseIsResolvedByTheNextCompletionAfterRestart() = runTest {
        lost()
        alice(reopen()).prepareLastDeviceRecovery()
        server.afterRecovery = {
            server.afterRecovery = {}
            throw SecureMessageTransportException.UnexpectedResponse(504)
        }
        assertFailsWith<SecureMessageTransportException.UnexpectedResponse> { alice(reopen()).completeLastDeviceRecovery(recoveryKey) }
        val restarted = reopen()
        alice(restarted).completeLastDeviceRecovery(recoveryKey)
        assertEquals(0L, pendingRows())
        assertContentEquals(server.keys[ALICE], restarted.deviceAuthentication.keyPair()?.publicKey)
        assertEquals(2L, server.epochs[ALICE])
    }

    @Test
    fun failedPendingKeyCreationStoresNothing() = runTest {
        lost()
        val created = mutableListOf<FailingRecords>()
        val storage = reopen(created)
        created.last().failing = setOf("deviceAuthenticationLastDeviceRecoveryKey")
        assertFailsWith<IllegalStateException> { alice(storage).prepareLastDeviceRecovery() }
        assertEquals(0L, pendingRows())
    }

    @Test
    fun storageKeyRotationReEncryptsThePendingKey() = runTest {
        lost()
        alice(reopen()).prepareLastDeviceRecovery()
        val k2 = assertNotNull(reopen().deviceAuthentication.pendingLastDeviceRecoveryKeyPair())
        assertEquals(1, SealedRecords.keyId(pendingRecord()).value)

        val provider = MemoryKeyStore().apply { put("rotation", TestKeys.A) }.provider("rotation")
        val rotating = reopen(provider = provider)
        rotating.rotateStorageKey()
        // One record per batch: the pending key is migrated like every other sealed record, then key 1 is retired.
        completeStorageKeyRotation { rotating.resumeStorageKeyRotation(1) }
        assertEquals(2, SealedRecords.keyId(pendingRecord()).value, "re-encrypted with the new storage key")
        assertEquals(0L, rotating.storageKeyRotationStatus().remainingRecords)

        val reopened = reopen(provider = provider)
        assertContentEquals(k2.privateKey, reopened.deviceAuthentication.pendingLastDeviceRecoveryKeyPair()?.privateKey, "survived storage key rotation")
        alice(reopened).completeLastDeviceRecovery(recoveryKey)
        assertContentEquals(k2.privateKey, reopened.deviceAuthentication.keyPair()?.privateKey)
        assertEquals(2, SealedRecords.keyId(activeRecord()).value)
    }

    @Test
    fun pendingKeyWrittenDuringAStorageKeyRotationUsesTheNewKey() = runTest {
        lost()
        val provider = MemoryKeyStore().apply { put("rotation", TestKeys.A) }.provider("rotation")
        val rotating = reopen(provider = provider)
        rotating.rotateStorageKey() // MIGRATING: new records already use key 2
        alice(rotating).prepareLastDeviceRecovery()
        assertEquals(2, SealedRecords.keyId(pendingRecord()).value)
        completeStorageKeyRotation { rotating.resumeStorageKeyRotation(1) }
        alice(reopen(provider = provider)).completeLastDeviceRecovery(recoveryKey)
        assertEquals(0L, pendingRows())
    }

    @Test
    fun corruptedPendingRecordFailsClosed() = runTest {
        lost()
        alice(reopen()).prepareLastDeviceRecovery()
        val damaged = pendingRecord().flipped(30)
        driver.exec("UPDATE $TABLE SET sealed_key_pair = ?", damaged)

        val storage = reopen()
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { alice(storage).prepareLastDeviceRecovery() }
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { alice(storage).completeLastDeviceRecovery(recoveryKey) }
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> {
            alice(storage).prepareDeviceAuthenticationRecovery(DeviceAddress(UserId("alice"), DeviceId("laptop")))
        }
        assertContentEquals(damaged, pendingRecord(), "never replaced by a new key")
        assertEquals(0, server.attempts, "nothing submitted")
        assertEquals(1L, server.epochs[ALICE])
    }

    @Test
    fun recordsDoNotOpenAsAnotherDeviceAuthenticationRecordType() = runTest {
        lost()
        alice(reopen()).prepareLastDeviceRecovery()
        val lastDeviceRecord = pendingRecord()
        driver.exec("DELETE FROM $TABLE")

        driver.exec("INSERT INTO device_authentication_key (id, sealed_key_pair) VALUES (0, ?)", lastDeviceRecord)
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { reopen().deviceAuthentication.keyPair() }
        driver.exec("DELETE FROM device_authentication_key")
        driver.exec("INSERT INTO device_authentication_recovery_key (id, sealed_key_pair) VALUES (0, ?)", lastDeviceRecord)
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { reopen().deviceAuthentication.pendingRecoveryKeyPair() }
        driver.exec("DELETE FROM device_authentication_recovery_key")
        driver.exec("INSERT INTO device_authentication_rotation_key (id, sealed_key_pair) VALUES (0, ?)", lastDeviceRecord)
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { reopen().deviceAuthentication.pendingRotationKeyPair() }
        driver.exec("DELETE FROM device_authentication_rotation_key")
        // Another type's record in the last-device slot.
        alice(reopen()).prepareDeviceAuthenticationRecovery(DeviceAddress(UserId("alice"), DeviceId("laptop")))
        val recoveryRecord = driver.blob("SELECT sealed_key_pair FROM device_authentication_recovery_key")
        driver.exec("DELETE FROM device_authentication_recovery_key")
        driver.exec("INSERT INTO $TABLE (id, sealed_key_pair) VALUES (0, ?)", recoveryRecord)
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { reopen().deviceAuthentication.pendingLastDeviceRecoveryKeyPair() }
    }

    @Test
    fun recoveryKeepsMessagingStateAndVerification() = runTest {
        val storage = lost()
        val alice = alice(storage)
        alice.markRemoteIdentityVerified(alice.safetyNumber(BOB))
        // Without its device key the device cannot sign the submission (S1): the message stays pending.
        assertFailsWith<SecureMessageClientException.MessageNotSent> { alice.send(BOB, "pending".encodeToByteArray()) }
        val before = driver.dump()

        alice.recoverLastDevice(recoveryKey)

        val after = driver.dump()
        val authTables = setOf("device_authentication_key", TABLE)
        assertEquals(before - authTables, after - authTables, "no messaging row changed")
        assertEquals(VerificationState.VERIFIED, alice(reopen()).remoteIdentityTrust(BOB)?.verification)
        assertEquals("pending", alice(reopen()).pendingMessages(limit = 100, recipient = BOB).messages.single().plaintext.decodeToString())
    }

    @Test
    fun version11FixtureMigratesWithAnEmptyLastDeviceRecoveryTable() = runTest {
        // A full database, turned back into schema version 11.
        val storage = reopen()
        val alice = alice(storage)
        for (client in listOf(alice, bob)) {
            client.initialize()
            client.registerDevice()
            client.publishPreKeys()
        }
        bob.send(ALICE, "before".encodeToByteArray())
        alice.accept(alice.receive().single())
        bob.receive().forEach { bob.decrypt(it) } // the ACK
        alice.markRemoteIdentityVerified(alice.safetyNumber(BOB))
        alice.send(BOB, "pending at the upgrade".encodeToByteArray())
        server.mailboxes.remove(BOB)
        alice.prepareDeviceAuthenticationRotation()
        val identity = assertNotNull(storage.identity.identity())
        val deviceKey = assertNotNull(storage.deviceAuthentication.keyPair())
        val rotationKey = assertNotNull(storage.deviceAuthentication.pendingRotationKeyPair())
        val rotation = storage.storageKeyRotationStatus()

        driver.exec("DROP TABLE $TABLE")
        driver.dropVersion13Additions()
        driver.exec("PRAGMA user_version = 11")
        val fixture = TestDatabase()
        try {
            val fixtureDriver = fixture.open(Version11Schema)
            assertEquals(fixtureDriver.tables().associateWith { fixtureDriver.columns(it) }, driver.tables().associateWith { driver.columns(it) })
        } finally {
            fixture.close()
        }
        val before = driver.dump()

        val migrated = reopen()
        assertEquals(listOf(16L), driver.longs("PRAGMA user_version"))
        val after = driver.dump()
        assertEquals(before.withLegacyProcessedMessages().withEmptyMigrationIntent(), after - TABLE, "no existing row changes")
        assertEquals(emptyList(), after.getValue(TABLE))
        assertContentEquals(identity.privateKey, migrated.identity.identity()?.privateKey)
        assertContentEquals(deviceKey.privateKey, migrated.deviceAuthentication.keyPair()?.privateKey)
        assertContentEquals(rotationKey.privateKey, migrated.deviceAuthentication.pendingRotationKeyPair()?.privateKey)
        assertNull(migrated.deviceAuthentication.pendingLastDeviceRecoveryKeyPair())
        assertEquals(rotation, migrated.storageKeyRotationStatus())
        assertEquals(VerificationState.VERIFIED, alice(migrated).remoteIdentityTrust(BOB)?.verification, "verification kept")
        assertEquals("pending at the upgrade", alice(migrated).pendingMessages(limit = 100, recipient = BOB).messages.single().plaintext.decodeToString())

        // After the upgrade the last-device recovery slot works (once the rotation is cancelled).
        alice(migrated).cancelDeviceAuthenticationRotation()
        alice(migrated).prepareLastDeviceRecovery()
        assertEquals(1L, pendingRows())
    }

    @Test
    fun downgradedDatabaseMatchesTheVersion11Fixture() = runTest {
        alice(reopen()).initialize()
        driver.exec("DROP TABLE $TABLE")
        driver.dropVersion13Additions()
        driver.exec("PRAGMA user_version = 11")
        val downgraded = driver.tables().associateWith { driver.columns(it) }
        val fixture = TestDatabase()
        try {
            val fixtureDriver = fixture.open(Version11Schema)
            assertEquals(fixtureDriver.tables().associateWith { fixtureDriver.columns(it) }, downgraded)
        } finally {
            fixture.close()
        }
    }

    /**
     * The server side as far as these tests need it: TOFU registration with
     * proof of possession, recovery key registration, one challenge per
     * device, last-device recovery with both proofs, CAS on key and epoch,
     * challenge consumption and exact-retry recognition, prekey bundles and
     * mailboxes. No expiry.
     */
    private class RecoveryServer : SecureMessageTransport {
        val keys = mutableMapOf<DeviceAddress, ByteArray>()
        val epochs = mutableMapOf<DeviceAddress, Long>()
        private val recoveryKeys = mutableMapOf<UserId, ByteArray>()
        private val challenges = mutableMapOf<DeviceAddress, Pair<LastDeviceRecoveryChallenge, ByteArray>>()
        private val recoveryIds = mutableMapOf<DeviceAddress, LastDeviceRecoveryId>()
        private val bundles = mutableMapOf<DeviceAddress, PreKeyBundle>()
        val mailboxes = mutableMapOf<DeviceAddress, MutableList<EncryptedEnvelope>>()
        var attempts = 0
        var afterRecovery: () -> Unit = {}

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

        override suspend fun registrationStatus(address: DeviceAddress, signer: ServerRequestSigner): DeviceAuthenticationRegistrationStatus =
            error("not used")

        override suspend fun registerLastDeviceRecoveryKey(address: DeviceAddress, registration: LastDeviceRecoveryKeyRegistration, signer: ServerRequestSigner) {
            verify(address, ServerApiPaths.LAST_DEVICE_RECOVERY_KEY, "PUT", keys[address], signer)
            check(LastDeviceRecovery.verifyKeyRegistration(registration) && registration.userId == address.userId)
            val existing = recoveryKeys.getOrPut(registration.userId) { registration.publicKey }
            if (!existing.contentEquals(registration.publicKey)) {
                throw SecureMessageTransportException.LastDeviceRecoveryKeyRejected(SecureMessageTransportException.RecoveryKeyFailure.CONFLICT)
            }
        }

        override suspend fun lastDeviceRecoveryChallenge(target: DeviceAddress): LastDeviceRecoveryChallenge {
            val key = keys.getValue(target)
            val epoch = epochs.getValue(target)
            challenges[target]?.let { (challenge, issuedFor) ->
                if (challenge.authEpoch == epoch && issuedFor.contentEquals(key)) return challenge
            }
            val challenge = LastDeviceRecoveryChallenge(
                target, LastDeviceRecoveryChallengeId(Random.nextBytes(16)), Random.nextBytes(32), epoch, Instant.fromEpochMilliseconds(Long.MAX_VALUE / 2),
            )
            challenges[target] = challenge to key
            return challenge
        }

        override suspend fun lastDeviceRecoveryKeyStatus(
            address: DeviceAddress,
            signer: ServerRequestSigner,
        ): LastDeviceRecoveryKeyStatus = error("not used")

        override suspend fun rotateLastDeviceRecoveryKey(
            authorization: RecoveryKeyRotationAuthorization,
            signer: ServerRequestSigner,
        ) = error("not used")

        override suspend fun revokeLastDeviceRecoveryKey(
            authorization: RecoveryKeyRevocationAuthorization,
            signer: ServerRequestSigner,
        ) = error("not used")

        override suspend fun requestLastDeviceRecoveryKeyReset(
            address: DeviceAddress,
            signer: ServerRequestSigner,
        ): dev.kreienbuehl.ksecuremessage.model.RecoveryKeyResetStatus.Pending = error("not used")

        override suspend fun lastDeviceRecoveryKeyResetStatus(
            address: DeviceAddress,
            signer: ServerRequestSigner,
        ): dev.kreienbuehl.ksecuremessage.model.RecoveryKeyResetStatus = error("not used")

        override suspend fun completeLastDeviceRecoveryKeyReset(
            authorization: dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyResetCompletionAuthorization,
            signer: ServerRequestSigner,
        ) = error("not used")

        override suspend fun cancelLastDeviceRecoveryKeyReset(
            address: DeviceAddress,
            resetId: dev.kreienbuehl.ksecuremessage.model.RecoveryKeyResetId,
            signer: ServerRequestSigner,
        ) = error("not used")

        override suspend fun lastDeviceRecoveryKeyResetStatusByRecoveryKey(
            query: dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyResetStatusQuery,
        ): dev.kreienbuehl.ksecuremessage.model.RecoveryKeyResetStatus = error("not used")

        override suspend fun cancelLastDeviceRecoveryKeyResetByRecoveryKey(
            authorization: dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyResetCancellationAuthorization,
        ) = error("not used")

        override suspend fun recoverLastDevice(authorization: LastDeviceRecoveryAuthorization) {
            attempts++
            val statement = authorization.statement
            val target = statement.target
            fun reject(failure: SecureMessageTransportException.LastDeviceRecoveryFailure): Nothing =
                throw SecureMessageTransportException.LastDeviceRecoveryRejected(failure)
            val recoveryKey = recoveryKeys[target.userId] ?: reject(SecureMessageTransportException.LastDeviceRecoveryFailure.NOT_CONFIGURED)
            if (!LastDeviceRecovery.verifyRecoverySignature(recoveryKey, authorization) || !LastDeviceRecovery.verifyProofOfPossession(authorization)) {
                reject(SecureMessageTransportException.LastDeviceRecoveryFailure.INVALID_PROOF)
            }
            val id = LastDeviceRecovery.recoveryId(statement)
            if (recoveryIds[target] != id) {
                val (challenge, issuedFor) = challenges[target] ?: reject(SecureMessageTransportException.LastDeviceRecoveryFailure.CHALLENGE_INVALID)
                if (challenge.id != statement.challenge.id || !challenge.nonce.contentEquals(statement.challenge.nonce)) {
                    reject(SecureMessageTransportException.LastDeviceRecoveryFailure.CHALLENGE_INVALID)
                }
                val registered = keys.getValue(target)
                if (!issuedFor.contentEquals(registered) || epochs[target] != challenge.authEpoch ||
                    registered.contentEquals(statement.replacementPublicKey)
                ) {
                    reject(SecureMessageTransportException.LastDeviceRecoveryFailure.CONFLICT)
                }
                challenges.remove(target)
                keys[target] = statement.replacementPublicKey
                epochs[target] = challenge.authEpoch + 1
                recoveryIds[target] = id
            }
            afterRecovery()
        }

        override suspend fun rotateDeviceAuthenticationKey(authorization: DeviceAuthenticationRotationAuthorization) = error("not used")

        override suspend fun recoverDevice(authorization: DeviceRecoveryAuthorization) = error("not used")

        override suspend fun publishPreKeys(publication: PreKeyPublication, signer: ServerRequestSigner) {
            verify(publication.address, ServerApiPaths.PRE_KEYS, "PUT", keys[publication.address], signer)
            bundles[publication.address] = PreKeyBundle(publication.address, publication.identityKey, publication.signedPreKey, publication.oneTimePreKeys.firstOrNull())
        }

        override suspend fun fetchPreKeyBundle(address: DeviceAddress): PreKeyBundle = bundles.getValue(address)

        override suspend fun send(envelope: EncryptedEnvelope, signer: ServerRequestSigner) {
            mailboxes.getOrPut(envelope.recipient) { mutableListOf() }.add(envelope)
        }

        override suspend fun receive(address: DeviceAddress, signer: ServerRequestSigner): List<EncryptedEnvelope> {
            verify(address, ServerApiPaths.MESSAGES, "GET", keys[address], signer)
            return mailboxes.remove(address)?.toList().orEmpty()
        }
    }
}
