package dev.kreienbuehl.ksecuremessage.storage.client.sqldelight

import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryChallenge
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryKeyRegistration
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationRotationAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecoveryAuthorization
import dev.kreienbuehl.ksecuremessage.client.PreKeyConfiguration
import dev.kreienbuehl.ksecuremessage.client.ReceiveResult
import dev.kreienbuehl.ksecuremessage.client.SecureMessageClient
import dev.kreienbuehl.ksecuremessage.client.SecureMessageClientException
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransport
import dev.kreienbuehl.ksecuremessage.client.ServerRequestSigner
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceAuthenticationRegistrationStatus
import dev.kreienbuehl.ksecuremessage.model.DeviceRegistration
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.model.PreKeyMessage
import dev.kreienbuehl.ksecuremessage.protocol.CiphertextMessageCodec
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.SecureSession
import dev.kreienbuehl.ksecuremessage.protocol.SessionInitiationId
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage
import dev.kreienbuehl.ksecuremessage.storage.PreKeyStore
import dev.kreienbuehl.ksecuremessage.storage.SignedPreKeyInfo
import dev.kreienbuehl.ksecuremessage.storage.testing.ClientStorageContractTest.Companion.bytes
import dev.kreienbuehl.ksecuremessage.storage.testing.ClientStorageContractTest.Companion.identity
import dev.kreienbuehl.ksecuremessage.storage.testing.ClientStorageContractTest.Companion.messageId
import dev.kreienbuehl.ksecuremessage.storage.testing.ClientStorageContractTest.Companion.oneTimePreKey
import dev.kreienbuehl.ksecuremessage.storage.testing.ClientStorageContractTest.Companion.signedPreKey
import dev.kreienbuehl.ksecuremessage.storage.client.inmemory.InMemoryClientStorage
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
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Instant

private val ALICE = DeviceAddress(UserId("alice"), DeviceId("phone"))
private val BOB = DeviceAddress(UserId("bob"), DeviceId("laptop"))
private val CAROL = DeviceAddress(UserId("carol"), DeviceId("tablet"))

/** Closes and reopens the database file between steps, like an application restart. */
class SqlDelightPersistenceTest {
    private val database = TestDatabase()
    private val engine = KodiumProtocolEngine()
    private val network = Relay()

    @AfterTest
    fun close() = database.close()

    /** Closes the open connection and opens a new one on the same file. */
    private suspend fun reopen(): SqlDelightClientStorage {
        database.closeOpenDrivers()
        return openStorage(database.open())
    }

    private suspend fun ClientStorage.oneTimePreKeyIds() = preKeys.publicOneTimePreKeys().map { it.id.value }

    @Test
    fun dataSurvivesReopen() = runTest {
        val before = reopen()
        before.identity.store(identity(1))
        before.preKeys.storeCurrentSignedPreKey(signedPreKey(0), Instant.fromEpochMilliseconds(1_000))
        before.preKeys.storeCurrentSignedPreKey(signedPreKey(1), Instant.fromEpochMilliseconds(2_000))
        before.preKeys.storeOneTimePreKeys(listOf(oneTimePreKey(0), oneTimePreKey(1), oneTimePreKey(2)))
        before.preKeys.removeOneTimePreKey(OneTimePreKeyId(2))
        before.sessions.store(SecureSession(ALICE, bytes(7)))
        before.remoteIdentities.store(ALICE, bytes(8))

        val after = reopen()
        assertContentEquals(bytes(-1), after.identity.identity()?.privateKey)
        assertEquals(SignedPreKeyId(1), after.preKeys.currentSignedPreKey()?.id)
        assertContentEquals(bytes(0), after.preKeys.signedPreKey(SignedPreKeyId(0))?.publicKey)
        assertEquals(SignedPreKeyId(1), after.preKeys.highestSignedPreKeyId())
        assertEquals(listOf(0, 1), after.oneTimePreKeyIds())
        assertEquals(OneTimePreKeyId(2), after.preKeys.highestOneTimePreKeyId())
        assertContentEquals(bytes(7), after.sessions.load(ALICE)?.state)
        assertContentEquals(bytes(8), after.remoteIdentities.identityKey(ALICE))
        assertFailsWith<IllegalStateException> { after.remoteIdentities.store(ALICE, bytes(9)) }
        assertContentEquals(bytes(8), reopen().remoteIdentities.identityKey(ALICE))
    }

    @Test
    fun rolledBackTransactionLeavesNothingOnDisk() = runTest {
        val before = reopen()
        before.preKeys.storeOneTimePreKeys(listOf(oneTimePreKey(0)))

        assertFailsWith<IllegalStateException> {
            before.transaction {
                identity.store(identity(1))
                sessions.store(SecureSession(ALICE, bytes(1)))
                remoteIdentities.store(ALICE, bytes(2))
                preKeys.removeOneTimePreKey(OneTimePreKeyId(0))
                preKeys.storeOneTimePreKeys(listOf(oneTimePreKey(1)))
                error("fail")
            }
        }

        val after = reopen()
        assertNull(after.identity.identity())
        assertNull(after.sessions.load(ALICE))
        assertNull(after.remoteIdentities.identityKey(ALICE))
        assertEquals(listOf(0), after.oneTimePreKeyIds())
        assertEquals(OneTimePreKeyId(0), after.preKeys.highestOneTimePreKeyId())
    }

    @Test
    fun clientContinuesAfterRestart() = runTest {
        val config = PreKeyConfiguration(oneTimePreKeyTarget = 3)
        val alice = SecureMessageClient(ALICE, InMemoryClientStorage(), engine, network, config)
        alice.initialize()
        network.publish(alice)

        val bobStorage = reopen()
        val bob = SecureMessageClient(BOB, bobStorage, engine, network, config)
        bob.initialize()
        network.publish(bob)
        val identity = assertNotNull(bobStorage.identity.identity())
        val signedPreKeyId = bob.currentPreKeyBundle().signedPreKey.id

        alice.send(BOB, "Hello Bob".encodeToByteArray())
        assertEquals("Hello Bob", bob.receiveText())
        bob.send(ALICE, "Hello Alice".encodeToByteArray())
        assertEquals("Hello Alice", alice.receiveText())
        assertEquals(listOf(1, 2), bobStorage.oneTimePreKeyIds())

        val restartedStorage = reopen()
        val restarted = SecureMessageClient(BOB, restartedStorage, engine, network, config)
        restarted.initialize()

        val after = assertNotNull(restartedStorage.identity.identity())
        assertContentEquals(identity.publicKey, after.publicKey)
        assertContentEquals(identity.privateKey, after.privateKey)
        assertEquals(signedPreKeyId, restarted.currentPreKeyBundle().signedPreKey.id)
        assertEquals(listOf(1, 2, 3), restartedStorage.oneTimePreKeyIds(), "only the consumed key is replaced")

        assertContentEquals(alice.currentPreKeyBundle().identityKey, restarted.remoteIdentityKey(ALICE), "pin survives restart")

        alice.send(BOB, "Still there?".encodeToByteArray())
        assertEquals("Still there?", restarted.receiveText())
        restarted.send(ALICE, "Yes".encodeToByteArray())
        assertEquals("Yes", alice.receiveText())
    }

    @Test
    fun failedOneTimePreKeyRemovalRollsBackTheSession() = runTest {
        val config = PreKeyConfiguration(oneTimePreKeyTarget = 2)
        val alice = SecureMessageClient(ALICE, InMemoryClientStorage(), engine, network, config)
        alice.initialize()

        val bobStorage = FailingRemoval(reopen())
        val bob = SecureMessageClient(BOB, bobStorage, engine, network, config)
        bob.initialize()
        network.publish(bob)

        alice.send(BOB, "Hello Bob".encodeToByteArray())
        val envelope = network.receive(BOB).single()
        assertFailsWith<IllegalStateException> { bob.decrypt(envelope) }

        val after = reopen()
        assertNull(after.sessions.load(ALICE))
        assertNull(after.remoteIdentities.identityKey(ALICE))
        assertNotNull(after.preKeys.oneTimePreKey(OneTimePreKeyId(0)))
    }

    @Test
    fun remoteTrustSurvivesRestart() = runTest {
        val config = PreKeyConfiguration(oneTimePreKeyTarget = 3)
        val bob = SecureMessageClient(BOB, InMemoryClientStorage(), engine, network, config)
        bob.initialize()
        network.publish(bob)

        val alice = SecureMessageClient(ALICE, reopen(), engine, network, config)
        alice.initialize()
        alice.send(BOB, "Hello Bob".encodeToByteArray())
        val bobIdentity = bob.currentPreKeyBundle().identityKey

        // Restart; a new session with the same identity is accepted.
        val storage = reopen()
        val restarted = SecureMessageClient(ALICE, storage, engine, network, config)
        restarted.initialize()
        assertContentEquals(bobIdentity, restarted.remoteIdentityKey(BOB))
        storage.sessions.remove(BOB)
        restarted.send(BOB, "same identity".encodeToByteArray())
        assertNotNull(storage.sessions.load(BOB))

        // Restart; a valid bundle of another identity for BOB is rejected.
        val impostor = SecureMessageClient(BOB, InMemoryClientStorage(), engine, network, config)
        impostor.initialize()
        network.publish(impostor)
        val storageAgain = reopen()
        storageAgain.sessions.remove(BOB)
        val again = SecureMessageClient(ALICE, storageAgain, engine, network, config)
        assertFailsWith<SecureMessageClientException.IdentityChanged> { again.send(BOB, "secret".encodeToByteArray()) }
        assertContentEquals(bobIdentity, reopen().remoteIdentities.identityKey(BOB))
        assertNull(reopen().sessions.load(BOB))
    }

    @Test
    fun version1DatabaseIsMigratedWithoutLosingData() = runTest {
        val old = database.open(Version1Schema)
        old.execute(null, "INSERT INTO local_identity (id, public_key, private_key) VALUES (0, X'0102', X'0304')", 0)
        old.execute(null, "INSERT INTO session (remote_user_id, remote_device_id, state) VALUES ('alice', 'phone', X'0506')", 0)
        database.closeOpenDrivers()

        val migrated = openStorage(database.open())
        assertContentEquals(byteArrayOf(1, 2), migrated.identity.identity()?.publicKey)
        assertContentEquals(byteArrayOf(5, 6), migrated.sessions.load(ALICE)?.state)
        assertNull(migrated.remoteIdentities.identityKey(ALICE), "a pin is never invented for an old session")
        migrated.remoteIdentities.store(ALICE, bytes(1))

        val after = reopen()
        assertContentEquals(bytes(1), after.remoteIdentities.identityKey(ALICE))
        assertContentEquals(byteArrayOf(5, 6), after.sessions.load(ALICE)?.state)
    }

    @Test
    fun version2DatabaseIsMigratedWithoutLosingData() = runTest {
        val old = database.open(Version2Schema)
        old.execute(null, "INSERT INTO local_identity (id, public_key, private_key) VALUES (0, X'0102', X'0304')", 0)
        old.execute(null, "INSERT INTO session (remote_user_id, remote_device_id, state) VALUES ('alice', 'phone', X'0506')", 0)
        old.execute(null, "INSERT INTO remote_identity (remote_user_id, remote_device_id, identity_key) VALUES ('alice', 'phone', X'0708')", 0)
        old.execute(null, "INSERT INTO one_time_pre_key (id, public_key, private_key) VALUES (4, X'09', X'0A')", 0)
        database.closeOpenDrivers()

        val migrated = openStorage(database.open())
        assertContentEquals(byteArrayOf(1, 2), migrated.identity.identity()?.publicKey)
        assertContentEquals(byteArrayOf(5, 6), migrated.sessions.load(ALICE)?.state)
        assertContentEquals(byteArrayOf(7, 8), migrated.remoteIdentities.identityKey(ALICE))
        assertEquals(listOf(4), migrated.oneTimePreKeyIds())
        val initiation = SessionInitiationId(bytes(3))
        assertFalse(migrated.sessionInitiations.isRetired(ALICE, initiation), "nothing is retired by the migration")
        migrated.sessionInitiations.retire(ALICE, initiation, null)

        val after = reopen()
        assertTrue(after.sessionInitiations.isRetired(ALICE, initiation))
        assertContentEquals(byteArrayOf(5, 6), after.sessions.load(ALICE)?.state)
        assertContentEquals(byteArrayOf(7, 8), after.remoteIdentities.identityKey(ALICE))
    }

    @Test
    fun version3DatabaseIsMigratedWithoutLosingData() = runTest {
        val old = database.open(Version3Schema)
        old.execute(null, "INSERT INTO local_identity (id, public_key, private_key) VALUES (0, X'0102', X'0304')", 0)
        old.execute(null, "INSERT INTO signed_pre_key (id, public_key, signature, private_key) VALUES (0, X'10', X'11', X'12')", 0)
        old.execute(null, "INSERT INTO signed_pre_key (id, public_key, signature, private_key) VALUES (1, X'20', X'21', X'22')", 0)
        old.execute(null, "UPDATE pre_key_state SET current_signed_pre_key_id = 1, highest_signed_pre_key_id = 1, highest_one_time_pre_key_id = 4", 0)
        old.execute(null, "INSERT INTO one_time_pre_key (id, public_key, private_key) VALUES (4, X'09', X'0A')", 0)
        old.execute(null, "INSERT INTO session (remote_user_id, remote_device_id, state) VALUES ('alice', 'phone', X'0506')", 0)
        old.execute(null, "INSERT INTO remote_identity (remote_user_id, remote_device_id, identity_key) VALUES ('alice', 'phone', X'0708')", 0)
        val initiation = SessionInitiationId(bytes(3))
        old.execute(null, "INSERT INTO retired_session_initiation (remote_user_id, remote_device_id, initiation_id) VALUES ('alice', 'phone', ?)", 1) {
            bindBytes(0, initiation.bytes)
        }
        database.closeOpenDrivers()

        val migrated = openStorage(database.open())
        assertContentEquals(byteArrayOf(1, 2), migrated.identity.identity()?.publicKey)
        assertEquals(SignedPreKeyId(1), migrated.preKeys.currentSignedPreKey()?.id)
        assertContentEquals(byteArrayOf(0x12), migrated.preKeys.signedPreKey(SignedPreKeyId(0))?.privateKey)
        assertEquals(SignedPreKeyId(1), migrated.preKeys.highestSignedPreKeyId())
        assertEquals(OneTimePreKeyId(4), migrated.preKeys.highestOneTimePreKeyId())
        assertEquals(listOf(4), migrated.oneTimePreKeyIds())
        assertContentEquals(byteArrayOf(5, 6), migrated.sessions.load(ALICE)?.state)
        assertContentEquals(byteArrayOf(7, 8), migrated.remoteIdentities.identityKey(ALICE))
        assertTrue(migrated.sessionInitiations.isRetired(ALICE, initiation))
        assertEquals(emptySet(), migrated.sessionInitiations.retiredSignedPreKeyIds(), "old entries name no signed prekey")
        assertEquals(
            listOf(
                SignedPreKeyInfo(SignedPreKeyId(0), false, null, null),
                SignedPreKeyInfo(SignedPreKeyId(1), true, null, null),
            ),
            migrated.preKeys.signedPreKeyInfos(),
            "no timestamps are invented by the migration",
        )

        // First start after the upgrade: old keys enter their grace period now, nothing is deleted.
        val clock = TestClock(Instant.parse("2026-03-01T00:00:00Z"))
        val config = PreKeyConfiguration(1, signedPreKeyRotationAge = Duration.INFINITE, signedPreKeyGracePeriod = 30.days)
        SecureMessageClient(BOB, reopen(), engine, network, config, clock).initialize()
        val stamped = reopen()
        assertEquals(
            listOf(
                SignedPreKeyInfo(SignedPreKeyId(0), false, clock.now, clock.now),
                SignedPreKeyInfo(SignedPreKeyId(1), true, clock.now, null),
            ),
            stamped.preKeys.signedPreKeyInfos(),
        )
        assertTrue(stamped.sessionInitiations.isRetired(ALICE, initiation))

        clock.now += 30.days
        SecureMessageClient(BOB, reopen(), engine, network, config, clock).initialize()
        val expired = reopen()
        assertNull(expired.preKeys.signedPreKey(SignedPreKeyId(0)))
        assertEquals(SignedPreKeyId(1), expired.preKeys.currentSignedPreKey()?.id)
        assertEquals(SignedPreKeyId(1), expired.preKeys.highestSignedPreKeyId())
        assertTrue(expired.sessionInitiations.isRetired(ALICE, initiation), "an entry without a signed prekey is kept")
        assertContentEquals(byteArrayOf(5, 6), expired.sessions.load(ALICE)?.state)
        assertContentEquals(byteArrayOf(7, 8), expired.remoteIdentities.identityKey(ALICE))
    }

    @Test
    fun signedPreKeyLifecycleSurvivesRestarts() = runTest {
        val clock = TestClock(Instant.parse("2026-03-01T00:00:00Z"))
        val start = clock.now
        val config = PreKeyConfiguration(oneTimePreKeyTarget = 3)
        suspend fun bob(): SecureMessageClient =
            SecureMessageClient(BOB, reopen(), engine, network, config, clock).also { it.initialize() }
        val aliceStorage = InMemoryClientStorage()
        val alice = SecureMessageClient(ALICE, aliceStorage, engine, network, config, clock)
        alice.initialize()
        val carol = SecureMessageClient(CAROL, InMemoryClientStorage(), engine, network, config, clock)
        carol.initialize()
        network.publish(bob())

        // Two first contacts with signed prekey 0, held back by the network.
        alice.send(BOB, "from alice".encodeToByteArray())
        val fromAlice = network.receive(BOB).single()
        carol.send(BOB, "from carol".encodeToByteArray())
        val fromCarol = network.receive(BOB).single()
        bob().rotateSignedPreKey()

        // Restart during the grace period: still accepted.
        clock.now += 15.days
        val restarted = bob()
        assertEquals("from alice", restarted.decrypt(fromAlice).text())
        restarted.send(ALICE, "ack".encodeToByteArray())
        alice.receiveText()
        val first = assertNotNull(engine.sessionInfo(assertNotNull(reopen().sessions.load(ALICE))).initiationId)

        // Alice replaces the session; the old initiation is retired with signed prekey 0.
        aliceStorage.sessions.remove(BOB)
        network.publish(bob())
        alice.send(BOB, "second".encodeToByteArray())
        assertEquals("second", bob().receiveText())
        assertTrue(reopen().sessionInitiations.isRetired(ALICE, first))

        // Grace over: restart, maintenance deletes key 0 and prunes the entry.
        clock.now = start + 30.days
        bob()
        val storage = reopen()
        assertNull(storage.preKeys.signedPreKey(SignedPreKeyId(0)))
        assertFalse(storage.sessionInitiations.isRetired(ALICE, first))
        assertEquals(SignedPreKeyId(3), storage.preKeys.highestSignedPreKeyId(), "age-based rotations on day 15 and 30")

        val afterExpiry = SecureMessageClient(BOB, reopen(), engine, network, config, clock)
        assertFailsWith<SecureMessageClientException.ExpiredSignedPreKey> { afterExpiry.decrypt(fromCarol) }
        assertFailsWith<SecureMessageClientException.ExpiredSignedPreKey> { afterExpiry.decrypt(fromAlice) }
        alice.send(BOB, "still works".encodeToByteArray())
        assertEquals("still works", afterExpiry.receiveText())
        afterExpiry.send(ALICE, "yes".encodeToByteArray())
        assertEquals("yes", alice.receiveText())

        // The clock moving back does not bring anything back.
        clock.now = start - 1.days
        bob()
        val rewound = reopen()
        assertNull(rewound.preKeys.signedPreKey(SignedPreKeyId(0)))
        assertFalse(rewound.sessionInitiations.isRetired(ALICE, first))
        assertEquals(SignedPreKeyId(3), rewound.preKeys.highestSignedPreKeyId())
        assertFailsWith<SecureMessageClientException.ExpiredSignedPreKey> {
            SecureMessageClient(BOB, reopen(), engine, network, config, clock).decrypt(fromCarol)
        }
    }

    @Test
    fun replayProtectionSurvivesRestart() = runTest {
        val config = PreKeyConfiguration(oneTimePreKeyTarget = 3)
        val aliceStorage = InMemoryClientStorage()
        val alice = SecureMessageClient(ALICE, aliceStorage, engine, network, config)
        alice.initialize()
        val bob = SecureMessageClient(BOB, reopen(), engine, network, config)
        bob.initialize()
        network.publish(bob)

        alice.send(BOB, "old session".encodeToByteArray())
        val old = network.receive(BOB).single()
        assertEquals("old session", bob.decrypt(old).text())
        bob.send(ALICE, "ack".encodeToByteArray())
        alice.receiveText()

        // Alice lost her session; her new one replaces Bob's.
        aliceStorage.sessions.remove(BOB)
        network.publish(bob)
        alice.send(BOB, "new session".encodeToByteArray())
        assertEquals("new session", bob.receiveText())

        val storage = reopen()
        val restarted = SecureMessageClient(BOB, storage, engine, network, config)
        val session = assertNotNull(storage.sessions.load(ALICE)).state
        val oneTimePreKeys = storage.oneTimePreKeyIds()
        assertFailsWith<SecureMessageClientException.StaleSessionInitiation> { restarted.decrypt(old) }
        assertContentEquals(session, reopen().sessions.load(ALICE)?.state)
        assertEquals(oneTimePreKeys, reopen().oneTimePreKeyIds())

        val bobAgain = SecureMessageClient(BOB, reopen(), engine, network, config)
        alice.send(BOB, "still new".encodeToByteArray())
        assertEquals("still new", bobAgain.receiveText())
        bobAgain.send(ALICE, "yes".encodeToByteArray())
        assertEquals("yes", alice.receiveText())
    }

    @Test
    fun simultaneousInitiationResolvesTheSameAfterRestart() = runTest {
        val config = PreKeyConfiguration(oneTimePreKeyTarget = 3)
        val bobStorage = InMemoryClientStorage()
        val bob = SecureMessageClient(BOB, bobStorage, engine, network, config)
        bob.initialize()
        network.publish(bob)
        val alice = SecureMessageClient(ALICE, reopen(), engine, network, config)
        alice.initialize()
        network.publish(alice)

        alice.send(BOB, "hello".encodeToByteArray())
        bob.receiveText()
        bob.send(ALICE, "hi".encodeToByteArray())
        alice.receiveText()
        // Alice's acknowledgement of "hi" is lost together with Bob's session.
        network.receive(BOB)
        bobStorage.sessions.remove(ALICE)
        network.publish(bob)
        val aliceBeforeRestart = reopen()
        aliceBeforeRestart.sessions.remove(BOB)
        network.publish(SecureMessageClient(ALICE, aliceBeforeRestart, engine, network, config))

        // Both start a session; Alice's pending initiation is only on disk.
        SecureMessageClient(ALICE, reopen(), engine, network, config).send(BOB, "from Alice".encodeToByteArray())
        bob.send(ALICE, "from Bob".encodeToByteArray())
        val toBob = network.receive(BOB).single()
        val toAlice = network.receive(ALICE).single()
        val aliceStorage = reopen()
        val restarted = SecureMessageClient(ALICE, aliceStorage, engine, network, config)
        val aliceIdentity = assertNotNull(aliceStorage.identity.identity()).publicKey
        val bobIdentity = assertNotNull(bobStorage.identity.identity()).publicKey
        val aliceInitiation = SessionInitiationId.of(assertIs<PreKeyMessage>(CiphertextMessageCodec.decode(toBob.payload)), bobIdentity)
        val bobInitiation = SessionInitiationId.of(assertIs<PreKeyMessage>(CiphertextMessageCodec.decode(toAlice.payload)), aliceIdentity)

        if (aliceInitiation < bobInitiation) {
            assertFailsWith<SecureMessageClientException.SessionCollision> { restarted.decrypt(toAlice) }
            assertEquals("from Alice", bob.decrypt(toBob).text())
        } else {
            assertEquals("from Bob", restarted.decrypt(toAlice).text())
            assertFailsWith<SecureMessageClientException.SessionCollision> { bob.decrypt(toBob) }
        }
        val winner = minOf(aliceInitiation, bobInitiation)
        assertEquals(winner, engine.sessionInfo(assertNotNull(reopen().sessions.load(BOB))).initiationId)
        assertEquals(winner, engine.sessionInfo(assertNotNull(bobStorage.sessions.load(ALICE))).initiationId)

        val aliceAgain = SecureMessageClient(ALICE, reopen(), engine, network, config)
        aliceAgain.send(BOB, "converged".encodeToByteArray())
        assertEquals("converged", bob.receiveText())
        bob.send(ALICE, "yes".encodeToByteArray())
        assertEquals("yes", aliceAgain.receiveText())
    }

    @Test
    fun version4DatabaseIsMigratedWithoutLosingData() = runTest {
        val old = database.open(Version4Schema)
        old.execute(null, "INSERT INTO local_identity (id, public_key, private_key) VALUES (0, X'0102', X'0304')", 0)
        old.execute(
            null,
            "INSERT INTO signed_pre_key (id, public_key, signature, private_key, created_at, replaced_at) VALUES (0, X'10', X'11', X'12', 1000, 2000)",
            0,
        )
        old.execute(null, "INSERT INTO signed_pre_key (id, public_key, signature, private_key, created_at) VALUES (1, X'20', X'21', X'22', 2000)", 0)
        old.execute(null, "UPDATE pre_key_state SET current_signed_pre_key_id = 1, highest_signed_pre_key_id = 1, highest_one_time_pre_key_id = 4", 0)
        old.execute(null, "INSERT INTO one_time_pre_key (id, public_key, private_key) VALUES (4, X'09', X'0A')", 0)
        old.execute(null, "INSERT INTO session (remote_user_id, remote_device_id, state) VALUES ('alice', 'phone', X'0506')", 0)
        old.execute(null, "INSERT INTO remote_identity (remote_user_id, remote_device_id, identity_key) VALUES ('alice', 'phone', X'0708')", 0)
        val initiation = SessionInitiationId(bytes(3))
        old.execute(
            null,
            "INSERT INTO retired_session_initiation (remote_user_id, remote_device_id, initiation_id, signed_pre_key_id) VALUES ('alice', 'phone', ?, 0)",
            1,
        ) { bindBytes(0, initiation.bytes) }
        database.closeOpenDrivers()

        val migrated = openStorage(database.open())
        assertContentEquals(byteArrayOf(1, 2), migrated.identity.identity()?.publicKey)
        assertEquals(SignedPreKeyId(1), migrated.preKeys.currentSignedPreKey()?.id)
        assertContentEquals(byteArrayOf(0x12), migrated.preKeys.signedPreKey(SignedPreKeyId(0))?.privateKey)
        assertEquals(
            listOf(
                SignedPreKeyInfo(SignedPreKeyId(0), false, Instant.fromEpochMilliseconds(1000), Instant.fromEpochMilliseconds(2000)),
                SignedPreKeyInfo(SignedPreKeyId(1), true, Instant.fromEpochMilliseconds(2000), null),
            ),
            migrated.preKeys.signedPreKeyInfos(),
        )
        assertEquals(OneTimePreKeyId(4), migrated.preKeys.highestOneTimePreKeyId())
        assertEquals(listOf(4), migrated.oneTimePreKeyIds())
        assertContentEquals(byteArrayOf(5, 6), migrated.sessions.load(ALICE)?.state)
        assertContentEquals(byteArrayOf(7, 8), migrated.remoteIdentities.identityKey(ALICE))
        assertTrue(migrated.sessionInitiations.isRetired(ALICE, initiation))
        assertEquals(setOf(SignedPreKeyId(0)), migrated.sessionInitiations.retiredSignedPreKeyIds())

        // The new tables start empty: no message is invented as pending or processed.
        assertEquals(emptyList(), migrated.pendingOutbound.list(ALICE))
        assertFalse(migrated.processedInbound.isProcessed(ALICE, messageId(1)))
        migrated.pendingOutbound.store(ALICE, messageId(1), bytes(1))
        migrated.processedInbound.markProcessed(ALICE, messageId(2))
        val reopened = reopen()
        assertEquals(listOf(messageId(1)), reopened.pendingOutbound.list(ALICE).map { it.id })
        assertTrue(reopened.processedInbound.isProcessed(ALICE, messageId(2)))
    }

    @Test
    fun reliabilityStateSurvivesReopen() = runTest {
        val before = reopen()
        val first = before.pendingOutbound.store(BOB, messageId(5), bytes(5))
        val second = before.pendingOutbound.store(BOB, messageId(1), bytes(1))
        before.processedInbound.markProcessed(ALICE, messageId(7))

        val after = reopen()
        assertEquals(listOf(messageId(5), messageId(1)), after.pendingOutbound.list(BOB).map { it.id })
        assertEquals(listOf(first, second), after.pendingOutbound.list(BOB).map { it.sequence })
        assertContentEquals(bytes(1), after.pendingOutbound.get(BOB, messageId(1))?.frame)
        assertTrue(after.processedInbound.isProcessed(ALICE, messageId(7)))

        // Sequence numbers are not reused after a removal and a restart.
        assertTrue(after.pendingOutbound.remove(BOB, messageId(1)))
        val third = reopen().pendingOutbound.store(BOB, messageId(9), bytes(9))
        assertTrue(third > second)
        assertEquals(listOf(messageId(5), messageId(9)), reopen().pendingOutbound.list(BOB).map { it.id })
    }

    @Test
    fun pendingMessagesAndDuplicateSuppressionSurviveRestarts() = runTest {
        val config = PreKeyConfiguration(oneTimePreKeyTarget = 3)
        val alice = SecureMessageClient(ALICE, InMemoryClientStorage(), engine, network, config)
        alice.initialize()
        network.publish(alice)
        val bob = SecureMessageClient(BOB, reopen(), engine, network, config)
        bob.initialize()
        network.publish(bob)
        suspend fun restartedBob() = SecureMessageClient(BOB, reopen(), engine, network, config)

        // Bob's messages are lost in transit, then Bob restarts.
        val ids = listOf("one", "two").map { bob.send(ALICE, it.encodeToByteArray()).id }
        network.receive(ALICE)
        assertEquals(ids, restartedBob().pendingMessages(ALICE).map { it.id })

        assertEquals(ids, restartedBob().retryPendingMessages(ALICE))
        assertEquals(listOf("one", "two"), network.receive(ALICE).map { alice.decrypt(it).text() })

        // Acknowledgements are processed by a restarted client and survive the next restart.
        val acks = network.receive(BOB).map { assertIs<ReceiveResult.Acknowledgement>(restartedBob().decrypt(it)) }
        assertEquals(ids, acks.map { it.id })
        assertTrue(acks.all { it.cleared })
        assertEquals(emptyList(), restartedBob().pendingMessages(ALICE))

        // A retry of an already processed message after a restart is a duplicate.
        val sent = alice.send(BOB, "lost ack".encodeToByteArray())
        assertEquals("lost ack", restartedBob().decrypt(network.receive(BOB).single()).text())
        network.receive(ALICE) // the acknowledgement is lost
        assertTrue(reopen().processedInbound.isProcessed(ALICE, sent.id))
        assertEquals(listOf(sent.id), alice.retryPendingMessages(BOB))
        val duplicate = assertIs<ReceiveResult.Duplicate>(restartedBob().decrypt(network.receive(BOB).single()))
        assertEquals(sent.id, duplicate.id)
        assertTrue(assertIs<ReceiveResult.Acknowledgement>(alice.decrypt(network.receive(ALICE).single())).cleared)
        assertEquals(emptyList(), alice.pendingMessages(BOB))
    }

    @Test
    fun collisionLostMessageIsRecoveredAfterRestart() = runTest {
        val config = PreKeyConfiguration(oneTimePreKeyTarget = 3)
        val bobStorage = InMemoryClientStorage()
        val bob = SecureMessageClient(BOB, bobStorage, engine, network, config)
        bob.initialize()
        network.publish(bob)
        suspend fun alice() = SecureMessageClient(ALICE, reopen(), engine, network, config)
        alice().initialize()
        network.publish(alice())

        // Both start a session at once; every Alice step runs on a reopened database.
        val fromAlice = alice().send(BOB, "from Alice".encodeToByteArray())
        val fromBob = bob.send(ALICE, "from Bob".encodeToByteArray())
        val toBob = network.receive(BOB).single()
        val toAlice = network.receive(ALICE).single()
        val aliceIdentity = assertNotNull(reopen().identity.identity()).publicKey
        val bobIdentity = assertNotNull(bobStorage.identity.identity()).publicKey
        val aliceInitiation = SessionInitiationId.of(assertIs<PreKeyMessage>(CiphertextMessageCodec.decode(toBob.payload)), bobIdentity)
        val bobInitiation = SessionInitiationId.of(assertIs<PreKeyMessage>(CiphertextMessageCodec.decode(toAlice.payload)), aliceIdentity)

        if (aliceInitiation < bobInitiation) {
            // Bob's message is lost: Alice discards it, Bob keeps it pending.
            assertFailsWith<SecureMessageClientException.SessionCollision> { alice().decrypt(toAlice) }
            assertEquals("from Alice", bob.decrypt(toBob).text())
            assertTrue(assertIs<ReceiveResult.Acknowledgement>(alice().decrypt(network.receive(ALICE).single())).cleared)
            assertEquals(listOf(fromBob.id), bob.pendingMessages(ALICE).map { it.id })
            bob.retryPendingMessages(ALICE)
            val resent = assertIs<ReceiveResult.Message>(alice().decrypt(network.receive(ALICE).single()))
            assertEquals(fromBob.id, resent.id)
            assertEquals("from Bob", resent.plaintext.decodeToString())
            assertTrue(assertIs<ReceiveResult.Acknowledgement>(bob.decrypt(network.receive(BOB).single())).cleared)
            assertEquals(emptyList(), bob.pendingMessages(ALICE))
        } else {
            // Alice's message is lost; her pending copy is only on disk.
            assertFailsWith<SecureMessageClientException.SessionCollision> { bob.decrypt(toBob) }
            assertEquals("from Bob", alice().decrypt(toAlice).text())
            assertTrue(assertIs<ReceiveResult.Acknowledgement>(bob.decrypt(network.receive(BOB).single())).cleared)
            assertEquals(listOf(fromAlice.id), alice().pendingMessages(BOB).map { it.id })
            alice().retryPendingMessages(BOB)
            val resent = assertIs<ReceiveResult.Message>(bob.decrypt(network.receive(BOB).single()))
            assertEquals(fromAlice.id, resent.id)
            assertEquals("from Alice", resent.plaintext.decodeToString())
            assertTrue(assertIs<ReceiveResult.Acknowledgement>(alice().decrypt(network.receive(ALICE).single())).cleared)
            assertEquals(emptyList(), alice().pendingMessages(BOB))
        }
    }

    /**
     * Processes everything waiting for this client and returns the single new
     * message. Acknowledgements of earlier messages may come before it.
     */
    private suspend fun SecureMessageClient.receiveText(): String {
        val results = network.receive(localAddress).map { decrypt(it) }
        results.forEach { assertTrue(it is ReceiveResult.Message || it is ReceiveResult.Acknowledgement, "unexpected $it") }
        return results.filterIsInstance<ReceiveResult.Message>().single().text()
    }

    private fun ReceiveResult.text(): String = assertIs<ReceiveResult.Message>(this).plaintext.decodeToString()

    private class TestClock(var now: Instant) : Clock {
        override fun now(): Instant = now
    }

    private class Relay : SecureMessageTransport {
        private val bundles = mutableMapOf<DeviceAddress, PreKeyBundle>()
        private val mailboxes = mutableMapOf<DeviceAddress, MutableList<EncryptedEnvelope>>()

        suspend fun publish(client: SecureMessageClient) {
            bundles[client.localAddress] =
                client.currentPreKeyBundle().copy(oneTimePreKey = client.publicOneTimePreKeys().first())
        }

        override suspend fun registerDevice(registration: DeviceRegistration, signer: ServerRequestSigner) =
            error("These tests set bundles directly, see publish")

        override suspend fun publishPreKeys(publication: PreKeyPublication, signer: ServerRequestSigner) =
            error("These tests set bundles directly, see publish")

        override suspend fun recoverDevice(authorization: DeviceRecoveryAuthorization) = error("These tests set bundles directly, see publish")

        override suspend fun registrationStatus(address: DeviceAddress, signer: ServerRequestSigner): DeviceAuthenticationRegistrationStatus =
            error("These tests set bundles directly, see publish")

        override suspend fun registerLastDeviceRecoveryKey(address: DeviceAddress, registration: LastDeviceRecoveryKeyRegistration, signer: ServerRequestSigner) =
            error("not used")

        override suspend fun lastDeviceRecoveryChallenge(target: DeviceAddress): LastDeviceRecoveryChallenge = error("not used")

        override suspend fun recoverLastDevice(authorization: LastDeviceRecoveryAuthorization) = error("not used")

        override suspend fun rotateDeviceAuthenticationKey(authorization: DeviceAuthenticationRotationAuthorization) =
            error("These tests set bundles directly, see publish")

        override suspend fun fetchPreKeyBundle(address: DeviceAddress) = bundles.getValue(address)

        override suspend fun send(envelope: EncryptedEnvelope) {
            mailboxes.getOrPut(envelope.recipient) { mutableListOf() }.add(envelope)
        }

        override suspend fun receive(address: DeviceAddress, signer: ServerRequestSigner) = receive(address)

        fun receive(address: DeviceAddress) = mailboxes.remove(address)?.toList().orEmpty()
    }

    /** Fails every one-time prekey removal inside a transaction. */
    private class FailingRemoval(private val delegate: ClientStorage) : ClientStorage by delegate {
        override suspend fun <T> transaction(block: suspend ClientStorage.() -> T): T = delegate.transaction {
            val tx = this
            object : ClientStorage by tx {
                override val preKeys: PreKeyStore = object : PreKeyStore by tx.preKeys {
                    override suspend fun removeOneTimePreKey(id: OneTimePreKeyId) = error("Injected failure")
                }
            }.block()
        }
    }
}
