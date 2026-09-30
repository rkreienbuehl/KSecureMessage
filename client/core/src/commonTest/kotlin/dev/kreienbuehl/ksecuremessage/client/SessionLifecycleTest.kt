package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.SessionInitiationVersion
import dev.kreienbuehl.ksecuremessage.protocol.LocalIdentity
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.LogicalMessageId
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyMessage
import dev.kreienbuehl.ksecuremessage.model.RatchetMessage
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.protocol.CiphertextMessageCodec
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.ProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.ProtocolException
import dev.kreienbuehl.ksecuremessage.protocol.SecurePayload
import dev.kreienbuehl.ksecuremessage.protocol.SecurePayloadCodec
import dev.kreienbuehl.ksecuremessage.protocol.SecureSession
import dev.kreienbuehl.ksecuremessage.protocol.SessionInitiationId
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage
import dev.kreienbuehl.ksecuremessage.storage.client.inmemory.InMemoryClientStorage
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Clock

/**
 * Milestone 6 session lifecycle (docs/session-lifecycle.md): a peer with the
 * pinned identity may replace a session, simultaneous initiations converge on
 * the smaller initiation ID, and replaced or losing initiations never become
 * current again.
 */
class SessionLifecycleTest {
    private val engine: ProtocolEngine = KodiumProtocolEngine()
    private val network = FakeNetwork()

    private inner class Device(val address: DeviceAddress, val storage: InMemoryClientStorage = InMemoryClientStorage()) {
        var client = newClient()
            private set

        private fun newClient() = SecureMessageClient(address, storage, engine, network, PreKeyConfiguration(oneTimePreKeyTarget = 4))

        /** A new client instance on the same storage, like an application restart. */
        fun restart() {
            client = newClient()
        }

        suspend fun publish(withOneTimePreKey: Boolean = true) = network.publish(client, withOneTimePreKey)

        suspend fun identityKey(): ByteArray = assertNotNull(storage.identity.identity()).publicKey

        suspend fun send(to: Device, text: String) = client.sendRaw(to.address, text.encodeToByteArray())

        /** A version 1 repetition this device sent before its S1.1 upgrade (still in flight). */
        suspend fun legacyRepetition(to: Device, text: String) =
            legacyV1Repetition(engine, storage, address, to.address, text.encodeToByteArray())

        suspend fun receiveAll(): List<EncryptedEnvelope> = network.receive(address)

        suspend fun receiveOne(): EncryptedEnvelope = receiveAll().single()

        suspend fun decryptText(envelope: EncryptedEnvelope): String = client.decryptRaw(envelope).decodeToString()

        suspend fun sessionWith(remote: Device): SecureSession = assertNotNull(storage.sessions.load(remote.address))

        suspend fun origin(remote: Device): SessionInitiationId? = engine.sessionInfo(sessionWith(remote)).initiationId

        suspend fun isRetired(remote: Device, id: SessionInitiationId) = storage.sessionInitiations.isRetired(remote.address, id)

        /** The initiation [envelope] (a PreKeyMessage to this device) belongs to. */
        suspend fun initiationOf(envelope: EncryptedEnvelope): SessionInitiationId =
            SessionInitiationId.v2Of(assertIs<PreKeyMessage>(CiphertextMessageCodec.decode(envelope.payload)), envelope.sender, envelope.recipient, identityKey())
    }

    private suspend fun device(address: DeviceAddress, withOneTimePreKey: Boolean = true) =
        Device(address).also {
            it.client.initialize()
            it.publish(withOneTimePreKey)
        }

    /** First contact and one reply: both sides pinned, one established session. */
    private suspend fun establish(initiator: Device, responder: Device, text: String = "hello") {
        initiator.send(responder, text)
        assertEquals(text, responder.decryptText(responder.receiveOne()))
        responder.send(initiator, "re: $text")
        assertEquals("re: $text", initiator.decryptText(initiator.receiveOne()))
    }

    private suspend fun assertBidirectional(one: Device, other: Device, round: Int) {
        one.send(other, "ping $round")
        assertEquals("ping $round", other.decryptText(other.receiveOne()))
        other.send(one, "pong $round")
        assertEquals("pong $round", one.decryptText(one.receiveOne()))
    }

    /** Everything a rejected message must leave untouched. */
    private class Snapshot(
        val session: ByteArray?,
        val pin: ByteArray?,
        val oneTimePreKeys: List<Int>,
    )

    private suspend fun Device.snapshot(remote: Device) = Snapshot(
        session = storage.sessions.load(remote.address)?.state,
        pin = storage.remoteIdentities.identityKey(remote.address),
        oneTimePreKeys = storage.preKeys.publicOneTimePreKeys().map { it.id.value },
    )

    private fun assertUnchanged(expected: Snapshot, actual: Snapshot) {
        assertContentEquals(expected.session, actual.session, "session bytes unchanged")
        assertContentEquals(expected.pin, actual.pin, "pin unchanged")
        assertEquals(expected.oneTimePreKeys, actual.oneTimePreKeys, "one-time prekeys unchanged")
    }

    // Same-identity replacement

    @Test
    fun establishedSessionIsReplacedByANewInitiationOfTheSameIdentity() = runTest {
        for (withOneTimePreKey in listOf(true, false)) {
            val alice = device(ALICE)
            val bob = device(BOB, withOneTimePreKey)
            establish(alice, bob)
            val first = assertNotNull(bob.origin(alice))

            // Alice loses her session state but keeps her identity.
            alice.storage.sessions.remove(BOB)
            bob.publish(withOneTimePreKey)
            val oneTimePreKeysBefore = bob.snapshot(alice).oneTimePreKeys
            alice.send(bob, "new session")
            val envelope = bob.receiveOne()
            val second = bob.initiationOf(envelope)
            assertNotEquals(first, second)

            assertEquals("new session", bob.decryptText(envelope))
            assertEquals(second, bob.origin(alice))
            assertTrue(bob.isRetired(alice, first), "the replaced initiation is retired")
            assertFalse(bob.isRetired(alice, second))
            assertContentEquals(alice.identityKey(), bob.storage.remoteIdentities.identityKey(ALICE))
            val consumed = if (withOneTimePreKey) oneTimePreKeysBefore.drop(1) else oneTimePreKeysBefore
            assertEquals(consumed, bob.snapshot(alice).oneTimePreKeys, "only the referenced one-time prekey is consumed")

            assertBidirectional(alice, bob, 1)
            assertBidirectional(bob, alice, 2)
        }
    }

    @Test
    fun replacementCanRepeat() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        establish(alice, bob)
        repeat(3) { round ->
            val previous = assertNotNull(alice.origin(bob))
            bob.storage.sessions.remove(ALICE)
            alice.publish()
            bob.send(alice, "restart $round")
            assertEquals("restart $round", alice.decryptText(alice.receiveOne()))
            assertTrue(alice.isRetired(bob, previous))
            assertBidirectional(alice, bob, round)
        }
    }

    @Test
    fun repeatedPreKeyMessagesOfTheCurrentInitiationStillDecrypt() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        alice.send(bob, "one")
        alice.send(bob, "two")
        alice.send(bob, "three")
        val (one, two, three) = bob.receiveAll()

        // Out of order, too: all belong to the accepted initiation.
        assertEquals("two", bob.decryptText(two))
        assertEquals("one", bob.decryptText(one))
        val origin = bob.origin(alice)
        assertEquals("three", bob.decryptText(three))
        assertEquals(origin, bob.origin(alice))

        // A duplicate is not a new initiation: it fails on the session and changes nothing.
        val before = bob.snapshot(alice)
        assertFailsWith<ProtocolException.DecryptionFailed> { bob.client.decryptRaw(two) }
        assertUnchanged(before, bob.snapshot(alice))
    }

    // Replay

    @Test
    fun replayedSupersededInitiationCannotReplaceTheCurrentSession() = runTest {
        // No one-time prekeys: only the retired initiation protects Bob.
        val alice = device(ALICE)
        val bob = device(BOB, withOneTimePreKey = false)
        alice.send(bob, "old one")
        alice.send(bob, "old two")
        val (oldFirst, oldSecond) = bob.receiveAll()
        assertEquals("old one", bob.decryptText(oldFirst))
        bob.send(alice, "ack")
        alice.decryptText(alice.receiveOne())
        val old = bob.initiationOf(oldFirst)

        alice.storage.sessions.remove(BOB)
        alice.send(bob, "new")
        assertEquals("new", bob.decryptText(bob.receiveOne()))
        val current = assertNotNull(bob.origin(alice))

        val before = bob.snapshot(alice)
        assertFailsWith<SecureMessageClientException.StaleSessionInitiation> { bob.client.decryptRaw(oldFirst) }
        assertFailsWith<SecureMessageClientException.StaleSessionInitiation> { bob.client.decryptRaw(oldSecond) }
        assertUnchanged(before, bob.snapshot(alice))
        assertEquals(current, bob.origin(alice))
        assertTrue(bob.isRetired(alice, old))
        assertFalse(bob.isRetired(alice, current))

        // Also after a restart of the client.
        bob.restart()
        assertFailsWith<SecureMessageClientException.StaleSessionInitiation> { bob.client.decryptRaw(oldFirst) }
        assertUnchanged(before, bob.snapshot(alice))

        assertBidirectional(alice, bob, 1)
    }

    @Test
    fun retiredInitiationIsRejectedEvenWithoutASession() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB, withOneTimePreKey = false)
        alice.send(bob, "old")
        val old = bob.receiveOne()
        bob.decryptText(old)
        alice.storage.sessions.remove(BOB)
        alice.send(bob, "new")
        bob.decryptText(bob.receiveOne())

        bob.storage.sessions.remove(ALICE)
        assertFailsWith<SecureMessageClientException.StaleSessionInitiation> { bob.client.decryptRaw(old) }
        assertNull(bob.storage.sessions.load(ALICE))
    }

    // Simultaneous initiation

    /** Alice and Bob trust each other, have no session, and both start one at once. */
    private suspend fun simultaneousInitiations(): Triple<Device, Device, Pair<EncryptedEnvelope, EncryptedEnvelope>> {
        val alice = device(ALICE)
        val bob = device(BOB)
        establish(alice, bob)
        alice.storage.sessions.remove(BOB)
        bob.storage.sessions.remove(ALICE)
        alice.publish()
        bob.publish()

        alice.send(bob, "from Alice")
        bob.send(alice, "from Bob")
        assertTrue(engine.sessionInfo(alice.sessionWith(bob)).awaitingReply)
        assertTrue(engine.sessionInfo(bob.sessionWith(alice)).awaitingReply)
        return Triple(alice, bob, bob.receiveOne() to alice.receiveOne())
    }

    /** A copy of [device]'s storage, so the same state can be run through another delivery order. */
    private suspend fun Device.fork(remote: Device): Device {
        val copy = InMemoryClientStorage()
        val source: ClientStorage = storage
        copy.transaction {
            identity.store(assertNotNull(source.identity.identity()))
            // Submissions are signed with the device authentication key (S1).
            deviceAuthentication.store(assertNotNull(source.deviceAuthentication.keyPair()))
            source.remoteIdentities.identityKey(remote.address)?.let { remoteIdentities.store(remote.address, it) }
            source.sessions.load(remote.address)?.let { sessions.store(it) }
            val highest = assertNotNull(source.preKeys.highestSignedPreKeyId()).value
            for (id in 0..highest) source.preKeys.signedPreKey(SignedPreKeyId(id))?.let { preKeys.storeCurrentSignedPreKey(it, Clock.System.now()) }
            preKeys.storeOneTimePreKeys(
                source.preKeys.publicOneTimePreKeys().map { assertNotNull(source.preKeys.oneTimePreKey(it.id)) },
            )
        }
        return Device(address, copy)
    }

    private suspend fun deliver(alice: Device, bob: Device, toBob: EncryptedEnvelope, toAlice: EncryptedEnvelope, aliceFirst: Boolean) {
        val winner = minOf(bob.initiationOf(toBob), alice.initiationOf(toAlice))
        val aliceWins = winner == bob.initiationOf(toBob)

        suspend fun deliverToBob() = if (aliceWins) {
            assertEquals("from Alice", bob.decryptText(toBob))
        } else {
            assertFailsWith<SecureMessageClientException.SessionCollision> { bob.client.decryptRaw(toBob) }
        }

        suspend fun deliverToAlice() = if (aliceWins) {
            assertFailsWith<SecureMessageClientException.SessionCollision> { alice.client.decryptRaw(toAlice) }
        } else {
            assertEquals("from Bob", alice.decryptText(toAlice))
        }

        if (aliceFirst) {
            deliverToBob()
            deliverToAlice()
        } else {
            deliverToAlice()
            deliverToBob()
        }
        assertEquals(winner, alice.origin(bob), "Alice uses the winning initiation")
        assertEquals(winner, bob.origin(alice), "Bob uses the winning initiation")
    }

    @Test
    fun simultaneousInitiationsConvergeInBothDeliveryOrders() = runTest {
        val (alice, bob, messages) = simultaneousInitiations()
        val (toBob, toAlice) = messages
        val aliceCopy = alice.fork(bob)
        val bobCopy = bob.fork(alice)

        deliver(alice, bob, toBob, toAlice, aliceFirst = true)
        deliver(aliceCopy, bobCopy, toBob, toAlice, aliceFirst = false)
        assertEquals(alice.origin(bob), aliceCopy.origin(bobCopy), "same winner in both orders")

        for ((a, b) in listOf(alice to bob, aliceCopy to bobCopy)) {
            assertBidirectional(a, b, 1)
            assertBidirectional(b, a, 2)
            assertIs<RatchetMessage>(CiphertextMessageCodec.decode(a.client.encryptRaw(BOB, byteArrayOf(1)).payload))
            assertIs<RatchetMessage>(CiphertextMessageCodec.decode(b.client.encryptRaw(ALICE, byteArrayOf(1)).payload))
        }
    }

    @Test
    fun losingInitiationIsRetiredAndKeepsItsOneTimePreKey() = runTest {
        val (alice, bob, messages) = simultaneousInitiations()
        val (toBob, toAlice) = messages
        val aliceWins = bob.initiationOf(toBob) < alice.initiationOf(toAlice)
        val (winner, loser) = if (aliceWins) alice to bob else bob to alice
        val toWinner = if (aliceWins) toAlice else toBob
        val toLoser = if (aliceWins) toBob else toAlice
        val losing = winner.initiationOf(toWinner)
        val otpk = assertNotNull(assertIs<PreKeyMessage>(CiphertextMessageCodec.decode(toWinner.payload)).oneTimePreKeyId)

        val before = winner.snapshot(loser)
        assertFailsWith<SecureMessageClientException.SessionCollision> { winner.client.decryptRaw(toWinner) }
        assertUnchanged(before, winner.snapshot(loser))
        assertNotNull(winner.storage.preKeys.oneTimePreKey(otpk), "a rejected initiation consumes no one-time prekey")
        assertTrue(winner.isRetired(loser, losing))

        // The loser switches to the winning session.
        loser.decryptText(toLoser)
        assertBidirectional(loser, winner, 1)

        // A replay of the losing initiation can never become current.
        val current = winner.origin(loser)
        assertFailsWith<SecureMessageClientException.StaleSessionInitiation> { winner.client.decryptRaw(toWinner) }
        assertEquals(current, winner.origin(loser))
        assertNotNull(winner.storage.preKeys.oneTimePreKey(otpk))
    }

    @Test
    fun laterMessagesOfTheLosingInitiationAreRejected() = runTest {
        val (alice, bob, messages) = simultaneousInitiations()
        val (toBob, toAlice) = messages
        val aliceWins = bob.initiationOf(toBob) < alice.initiationOf(toAlice)
        val (winner, loser) = if (aliceWins) alice to bob else bob to alice
        val toWinner = if (aliceWins) toAlice else toBob
        val toLoser = if (aliceWins) toBob else toAlice

        loser.send(winner, "second on the losing session")
        val second = winner.receiveOne()
        assertFailsWith<SecureMessageClientException.SessionCollision> { winner.client.decryptRaw(toWinner) }
        assertFailsWith<SecureMessageClientException.StaleSessionInitiation> { winner.client.decryptRaw(second) }

        loser.decryptText(toLoser)
        assertBidirectional(winner, loser, 1)
    }

    @Test
    fun pendingInitiatorDecidesTheSameAfterRestart() = runTest {
        val (alice, bob, messages) = simultaneousInitiations()
        val (toBob, toAlice) = messages
        alice.restart()
        bob.restart()
        deliver(alice, bob, toBob, toAlice, aliceFirst = false)
        assertBidirectional(alice, bob, 1)
    }

    // Trust

    @Test
    fun changedIdentityIsRejectedBeforeReplacementOrCollision() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        establish(alice, bob)
        bob.storage.sessions.remove(ALICE)
        alice.publish()
        bob.send(alice, "pending") // Bob now waits for a reply on his initiation.
        alice.receiveAll()

        val before = bob.snapshot(alice)
        // Up to a few impostors, so at least one would win the collision on ID alone.
        repeat(4) {
            val impostor = Device(ALICE).apply { client.initialize() }
            bob.publish()
            impostor.client.sendRaw(BOB, "I am Alice".encodeToByteArray())
            val envelope = bob.receiveOne()
            val error = assertFailsWith<SecureMessageClientException.IdentityChanged> { bob.client.decryptRaw(envelope) }
            assertEquals(ALICE, error.address)
            assertUnchanged(before, bob.snapshot(alice))
            assertFalse(bob.isRetired(alice, bob.initiationOf(envelope)))
        }
    }

    @Test
    fun collisionsAreIsolatedPerDevice() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val carol = device(CAROL)
        establish(alice, bob)
        bob.publish()
        establish(carol, bob)
        val aliceOrigin = bob.origin(alice)

        carol.storage.sessions.remove(BOB)
        bob.publish()
        carol.send(bob, "new")
        assertEquals("new", bob.decryptText(bob.receiveOne()))
        assertEquals(aliceOrigin, bob.origin(alice))
        assertFalse(bob.isRetired(alice, assertNotNull(bob.origin(carol))))
        assertBidirectional(alice, bob, 1)
        assertBidirectional(carol, bob, 1)
    }

    // Sessions from before S1 (session initiation version 1), from the frozen LegacySessionFixture

    /**
     * A device whose storage holds [identity] and the pre-S1 [session], as an
     * upgraded device would; pinned to [pin] unless `null`. Initialized and
     * published like any other device; the identity is kept.
     */
    private suspend fun legacyDevice(
        address: DeviceAddress,
        identity: LocalIdentity,
        session: SecureSession?,
        pin: ByteArray?,
    ): Device {
        val storage = InMemoryClientStorage()
        val deviceKey = engine.createDeviceAuthenticationKey()
        storage.transaction {
            this.identity.store(identity)
            deviceAuthentication.store(deviceKey)
            session?.let { sessions.store(it) }
            val remote = if (address == ALICE) BOB else ALICE
            pin?.let { remoteIdentities.store(remote, it) }
        }
        return Device(address, storage).also {
            it.client.initialize()
            it.publish()
        }
    }

    private suspend fun legacyPair(aliceSession: SecureSession, bobSession: SecureSession?): Pair<Device, Device> {
        val fixture = LegacySessionFixture
        val alice = legacyDevice(ALICE, fixture.aliceIdentity, aliceSession, fixture.bobIdentity.publicKey)
        val bob = legacyDevice(BOB, fixture.bobIdentity, bobSession, bobSession?.let { fixture.aliceIdentity.publicKey })
        return alice to bob
    }

    @Test
    fun preS1EstablishedSessionsKeepRatchetingAfterTheUpgrade() = runTest {
        val (alice, bob) = legacyPair(LegacySessionFixture.aliceEstablishedV1, LegacySessionFixture.bobEstablishedV1)
        assertNull(bob.origin(alice), "a pre-milestone-6 session has no recorded origin")
        assertEquals(SessionInitiationVersion.V1, engine.sessionInfo(bob.sessionWith(alice)).initiationVersion)
        repeat(3) { assertBidirectional(alice, bob, it) }
        assertEquals(SessionInitiationVersion.V1, engine.sessionInfo(bob.sessionWith(alice)).initiationVersion, "no new X3DH")
        assertNull(bob.origin(alice))
    }

    @Test
    fun preS1PendingInitiationContinuesWhenTheResponderAcceptedItBefore() = runTest {
        val (alice, bob) = legacyPair(LegacySessionFixture.alicePendingV3, LegacySessionFixture.bobAcceptedV3)
        val origin = assertNotNull(bob.origin(alice))
        // A version 1 repetition Alice sent before upgrading is still accepted as that repetition.
        val envelope = alice.legacyRepetition(bob, "still pending")
        assertEquals(SessionInitiationVersion.V1, assertIs<PreKeyMessage>(CiphertextMessageCodec.decode(envelope.payload)).initiationVersion)
        assertEquals("still pending", bob.decryptText(envelope))
        assertEquals(origin, bob.origin(alice))
        // Bob's reply completes Alice's initiation: the version 1 session continues, no new X3DH.
        assertBidirectional(bob, alice, 0)
        assertEquals(origin, alice.origin(bob))
        assertEquals(SessionInitiationVersion.V1, engine.sessionInfo(alice.sessionWith(bob)).initiationVersion)
    }

    @Test
    fun preS1InitiationTheResponderNeverAcceptedIsRejected() = runTest {
        // Upgrade peers together: a version 1 initiation never creates a session,
        // even though Bob still holds exactly the prekeys it names.
        val (alice, bob) = legacyPair(LegacySessionFixture.alicePendingV3, bobSession = null)
        bob.storage.transaction {
            preKeys.storeCurrentSignedPreKey(LegacySessionFixture.bobSignedPreKey, Clock.System.now())
            preKeys.storeOneTimePreKeys(listOf(LegacySessionFixture.bobOneTimePreKey))
        }
        val envelope = alice.legacyRepetition(bob, "too late")
        val before = bob.snapshot(alice)
        val error = assertFailsWith<ProtocolException.InvalidMessage> { bob.client.decryptRaw(envelope) }
        assertEquals("Version 1 session initiations are not accepted", error.message)
        assertUnchanged(before, bob.snapshot(alice))
        assertNull(bob.storage.sessions.load(ALICE), "no session")
        assertNull(bob.storage.remoteIdentities.identityKey(ALICE), "no pin")
    }

    @Test
    fun preS1InitiationNeverReplacesAVersion2Session() = runTest {
        val (alice, bob) = legacyPair(LegacySessionFixture.alicePendingV3, bobSession = null)
        // Bob and a new Alice instance with the same identity set up a version 2 session.
        val newAlice = legacyDevice(ALICE, LegacySessionFixture.aliceIdentity, session = null, pin = null)
        establish(newAlice, bob)
        val v2Origin = assertNotNull(bob.origin(alice))
        // The old pending version 1 initiation arrives later.
        val envelope = alice.legacyRepetition(bob, "old initiation")
        val before = bob.snapshot(alice)
        val error = assertFailsWith<ProtocolException.InvalidMessage> { bob.client.decryptRaw(envelope) }
        assertEquals("Version 1 session initiations are not accepted", error.message)
        assertUnchanged(before, bob.snapshot(alice))
        assertEquals(v2Origin, bob.origin(alice))
        assertFalse(bob.storage.sessionInitiations.isRetired(ALICE, v2Origin))
    }

    @Test
    fun preS1SessionIsReplacedByAVersion2Initiation() = runTest {
        val (alice, bob) = legacyPair(LegacySessionFixture.aliceEstablishedV1, LegacySessionFixture.bobEstablishedV1)
        alice.storage.sessions.remove(BOB)
        alice.send(bob, "new")
        val envelope = bob.receiveOne()
        assertEquals("new", bob.decryptText(envelope))
        assertEquals(bob.initiationOf(envelope), bob.origin(alice))
        assertEquals(SessionInitiationVersion.V2, engine.sessionInfo(bob.sessionWith(alice)).initiationVersion)
        assertBidirectional(alice, bob, 1)
    }

    @Test
    fun sessionWithoutPinIsNeverReplacedByAnotherIdentity() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        establish(alice, bob)
        // A session whose pin is missing, as stored before milestone 5.
        val unpinned = InMemoryClientStorage()
        val deviceKey = engine.createDeviceAuthenticationKey()
        unpinned.transaction {
            identity.store(assertNotNull(bob.storage.identity.identity()))
            deviceAuthentication.store(deviceKey)
            sessions.store(bob.sessionWith(alice))
            val signedPreKey = assertNotNull(bob.storage.preKeys.currentSignedPreKey())
            preKeys.storeCurrentSignedPreKey(signedPreKey, Clock.System.now())
            preKeys.storeOneTimePreKeys(bob.storage.preKeys.publicOneTimePreKeys().map { assertNotNull(bob.storage.preKeys.oneTimePreKey(it.id)) })
        }
        val legacyBob = Device(BOB, unpinned)
        network.publish(legacyBob.client)

        // Another identity key at Alice's address: nothing to hold it against, refused.
        val otherAlice = device(ALICE)
        otherAlice.send(legacyBob, "new")
        val before = legacyBob.snapshot(alice)
        val error = assertFailsWith<ProtocolException.InvalidMessage> { legacyBob.client.decryptRaw(legacyBob.receiveOne()) }
        assertEquals("Session without a pinned identity cannot be replaced", error.message)
        assertUnchanged(before, legacyBob.snapshot(alice))
        assertNull(before.pin)

        // The identity the session was established with may replace it (S1.1, N3), and is pinned.
        alice.storage.sessions.remove(BOB)
        alice.send(legacyBob, "same identity")
        assertEquals("same identity", legacyBob.decryptText(legacyBob.receiveOne()))
        assertContentEquals(alice.identityKey(), legacyBob.storage.remoteIdentities.identityKey(ALICE))
        assertBidirectional(alice, legacyBob, 0)
    }

    @Test
    fun consumedOneTimePreKeyIdIsUnrelatedToInitiationIdentity() = runTest {
        // Two initiations naming the same (unused) one-time prekey are still
        // told apart by their ephemeral keys.
        val alice = device(ALICE)
        val bob = device(BOB)
        val bundle = network.bundles.getValue(BOB)
        alice.send(bob, "one")
        val first = bob.receiveOne()
        alice.storage.sessions.remove(BOB)
        network.bundles[BOB] = bundle
        alice.send(bob, "two")
        val second = bob.receiveOne()
        assertEquals(
            assertIs<PreKeyMessage>(CiphertextMessageCodec.decode(first.payload)).oneTimePreKeyId,
            assertIs<PreKeyMessage>(CiphertextMessageCodec.decode(second.payload)).oneTimePreKeyId,
        )
        assertNotEquals(bob.initiationOf(first), bob.initiationOf(second))

        assertEquals("one", bob.decryptText(first))
        // Its one-time prekey is gone now, so the second one cannot be accepted.
        assertFailsWith<ProtocolException.InvalidMessage> { bob.client.decryptRaw(second) }
        assertNotNull(bob.storage.preKeys.oneTimePreKey(OneTimePreKeyId(1)))
    }

    // N3 (S1.1): an unanswered version 1 initiation never blocks version 2.

    private fun preKeyMessageOf(envelope: EncryptedEnvelope) = assertIs<PreKeyMessage>(CiphertextMessageCodec.decode(envelope.payload))

    /** Alice with the unanswered version 1 initiation of the fixture, and its origin. */
    private suspend fun upgradedAliceWithUnansweredInitiation(pinned: Boolean = true): Pair<Device, SessionInitiationId> {
        val fixture = LegacySessionFixture
        val alice = legacyDevice(ALICE, fixture.aliceIdentity, fixture.alicePendingV3, if (pinned) fixture.bobIdentity.publicKey else null)
        val info = engine.sessionInfo(alice.storage.sessions.load(BOB)!!)
        assertEquals(SessionInitiationVersion.V1, info.initiationVersion)
        assertTrue(info.awaitingReply)
        return alice to assertNotNull(info.initiationId)
    }

    @Test
    fun n3PendingV1CanNeverBlockIncomingV2AfterUpgrade() = runTest {
        // Both orders: v2 ID larger than the v1 origin (ordinary comparison would let v1 win,
        // the old deadlock) and smaller.
        for (v2Larger in listOf(true, false)) {
            val (alice, v1Origin) = upgradedAliceWithUnansweredInitiation()
            // Bob, upgraded, never accepted Alice's version 1 initiation and starts version 2.
            val bob = legacyDevice(BOB, LegacySessionFixture.bobIdentity, session = null, pin = LegacySessionFixture.aliceIdentity.publicKey)
            var envelope: EncryptedEnvelope? = null
            for (attempt in 0 until 512) {
                bob.storage.sessions.remove(ALICE)
                bob.send(alice, "v2 hello")
                val candidate = alice.receiveOne()
                if ((alice.initiationOf(candidate) > v1Origin) == v2Larger) {
                    envelope = candidate
                    break
                }
            }
            val initiation = assertNotNull(envelope, "no v2 initiation in the required order")
            val v2Id = alice.initiationOf(initiation)
            assertEquals(v2Larger, v2Id > v1Origin, "precondition: the order under test")
            assertEquals(SessionInitiationVersion.V2, preKeyMessageOf(initiation).initiationVersion)

            assertEquals("v2 hello", alice.decryptText(initiation), "v2 wins regardless of the ID order")
            assertEquals(v2Id, alice.origin(bob))
            assertEquals(SessionInitiationVersion.V2, engine.sessionInfo(alice.sessionWith(bob)).initiationVersion)
            assertTrue(alice.isRetired(bob, v1Origin), "the unanswered v1 initiation is retired")
            assertBidirectional(alice, bob, 0)
            assertBidirectional(bob, alice, 1)
        }
    }

    @Test
    fun n3UnpinnedPendingV1IsReplacedByV2() = runTest {
        // Created before pinning: no pin, still no authority to block v2.
        val (alice, v1Origin) = upgradedAliceWithUnansweredInitiation(pinned = false)
        val bob = legacyDevice(BOB, LegacySessionFixture.bobIdentity, session = null, pin = null)
        bob.send(alice, "v2 hello")
        assertEquals("v2 hello", alice.decryptText(alice.receiveOne()))
        assertTrue(alice.isRetired(bob, v1Origin))
        assertContentEquals(LegacySessionFixture.bobIdentity.publicKey, alice.storage.remoteIdentities.identityKey(BOB), "pinned on acceptance")
        assertBidirectional(alice, bob, 0)
    }

    @Test
    fun n3PinnedPendingV1StillRefusesAnotherIdentity() = runTest {
        val (alice, _) = upgradedAliceWithUnansweredInitiation()
        val impostor = device(BOB)
        impostor.send(alice, "I am Bob")
        val before = alice.snapshot(impostor)
        assertFailsWith<SecureMessageClientException.IdentityChanged> { alice.client.decryptRaw(alice.receiveOne()) }
        assertUnchanged(before, alice.snapshot(impostor))
    }

    @Test
    fun n3BothPeersPendingV1ConvergeAfterUpgrade() = runTest {
        val fixture = LegacySessionFixture
        for (simultaneous in listOf(false, true)) {
            val alice = legacyDevice(ALICE, fixture.aliceIdentity, fixture.alicePendingV3, fixture.bobIdentity.publicKey)
            val bob = legacyDevice(BOB, fixture.bobIdentity, fixture.bobPendingV3, fixture.aliceIdentity.publicKey)
            // Repetitions sent before the upgrade: neither side can accept the other's v1 initiation.
            val toBobV1 = alice.legacyRepetition(bob, "old to bob")
            val toAliceV1 = bob.legacyRepetition(alice, "old to alice")
            assertFailsWith<ProtocolException.InvalidMessage> { bob.client.decryptRaw(toBobV1) }
            assertFailsWith<ProtocolException.InvalidMessage> { alice.client.decryptRaw(toAliceV1) }

            if (!simultaneous) {
                // One side sends after the upgrade: version 2, which the other side accepts.
                alice.send(bob, "from Alice")
                val toBob = bob.receiveOne()
                assertEquals(SessionInitiationVersion.V2, preKeyMessageOf(toBob).initiationVersion)
                assertEquals("from Alice", bob.decryptText(toBob))
            } else {
                // Both send at once: an ordinary v2 collision, which converges.
                alice.send(bob, "from Alice")
                bob.send(alice, "from Bob")
                val toBob = bob.receiveOne()
                val toAlice = alice.receiveOne()
                assertEquals(SessionInitiationVersion.V2, preKeyMessageOf(toBob).initiationVersion)
                assertEquals(SessionInitiationVersion.V2, preKeyMessageOf(toAlice).initiationVersion)
                deliver(alice, bob, toBob, toAlice, aliceFirst = true)
            }
            assertBidirectional(alice, bob, 0)
            assertBidirectional(bob, alice, 1)
            assertEquals(SessionInitiationVersion.V2, engine.sessionInfo(alice.sessionWith(bob)).initiationVersion)
            assertEquals(alice.origin(bob), bob.origin(alice))
        }
    }

    @Test
    fun n3PendingV1IsNeverRetransmittedAndItsLogicalMessageMovesToV2() = runTest {
        val fixture = LegacySessionFixture
        // Bob never accepted it, or accepted it before upgrading (and never replied).
        for (bobSession in listOf(null, fixture.bobAcceptedV3)) {
            val (alice, v1Origin) = upgradedAliceWithUnansweredInitiation()
            val bob = legacyDevice(BOB, fixture.bobIdentity, bobSession, fixture.aliceIdentity.publicKey)
            // A logical message Alice's application sent before the upgrade, still pending.
            val id = LogicalMessageId.random()
            alice.storage.transaction {
                pendingOutbound.store(BOB, id, SecurePayloadCodec.encode(SecurePayload.ApplicationMessage(id, "kept".encodeToByteArray())))
            }

            assertEquals(listOf(id), alice.client.retryPendingMessages(BOB))
            val retry = bob.receiveOne()
            assertEquals(SessionInitiationVersion.V2, preKeyMessageOf(retry).initiationVersion, "never v1 again")
            assertTrue(alice.isRetired(bob, v1Origin))
            val delivery = assertIs<ReceiveResult.Delivery>(bob.client.decrypt(retry))
            assertEquals(id, delivery.id, "same logical message")
            assertEquals("kept", delivery.message.plaintext.decodeToString())
            assertEquals(1L, alice.client.pendingMessageCount(BOB), "pending until acknowledged")

            assertTrue(bob.client.commitReceivedMessage(delivery.message).ackSent)
            val ack = assertIs<ReceiveResult.Acknowledgement>(alice.client.decrypt(alice.receiveOne()))
            assertEquals(id, ack.id)
            assertEquals(0L, alice.client.pendingMessageCount(BOB))
            assertEquals(0L, bob.client.pendingReceivedMessageCount(), "delivered once, committed")
            assertTrue(bob.receiveAll().isEmpty())
        }
    }

    @Test
    fun n3AckIsNeverSentOverPendingV1() = runTest {
        val (alice, _) = upgradedAliceWithUnansweredInitiation()
        val bob = legacyDevice(BOB, LegacySessionFixture.bobIdentity, LegacySessionFixture.bobAcceptedV3, LegacySessionFixture.aliceIdentity.publicKey)
        // A delivery Alice received before the upgrade and commits now, while her session is still unanswered v1.
        val id = LogicalMessageId.random()
        alice.storage.transaction {
            pendingInbound.store(BOB, id, SecurePayloadCodec.encode(SecurePayload.ApplicationMessage(id, "earlier".encodeToByteArray())), Clock.System.now())
        }
        val before = alice.snapshot(bob)
        val result = alice.client.commitReceivedMessage(BOB, id)
        assertEquals(CommitStatus.COMMITTED, result.status)
        assertFalse(result.ackSent, "no ACK over an unanswered v1 initiation")
        assertUnchanged(before, alice.snapshot(bob))
        assertTrue(bob.receiveAll().isEmpty(), "nothing sent")
    }

    @Test
    fun n3DiscardedV1InitiationCannotRevive() = runTest {
        val (alice, bob) = legacyPair(LegacySessionFixture.alicePendingV3, LegacySessionFixture.bobAcceptedV3)
        val v1Origin = assertNotNull(alice.origin(bob))
        // Captured before the upgrade, delivered late.
        val late = alice.legacyRepetition(bob, "late v1")
        alice.send(bob, "v2 after upgrade")
        assertEquals("v2 after upgrade", bob.decryptText(bob.receiveOne()))
        assertTrue(alice.isRetired(bob, v1Origin))
        assertTrue(bob.isRetired(alice, v1Origin), "Bob retired the replaced v1 session's origin too")
        val v2Origin = assertNotNull(bob.origin(alice))

        val before = bob.snapshot(alice)
        val error = assertFailsWith<ProtocolException.InvalidMessage> { bob.client.decryptRaw(late) }
        assertEquals("Version 1 session initiations are not accepted", error.message)
        assertUnchanged(before, bob.snapshot(alice))
        assertEquals(v2Origin, bob.origin(alice))
        assertBidirectional(alice, bob, 0)
    }
}
