package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyMessage
import dev.kreienbuehl.ksecuremessage.model.RatchetMessage
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.protocol.CiphertextMessageCodec
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.ProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.ProtocolException
import dev.kreienbuehl.ksecuremessage.protocol.SecureSession
import dev.kreienbuehl.ksecuremessage.protocol.SessionInitiationId
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage
import dev.kreienbuehl.ksecuremessage.storage.inmemory.InMemoryClientStorage
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

        suspend fun send(to: Device, text: String) = client.send(to.address, text.encodeToByteArray())

        suspend fun receiveAll(): List<EncryptedEnvelope> = network.receive(address)

        suspend fun receiveOne(): EncryptedEnvelope = receiveAll().single()

        suspend fun decryptText(envelope: EncryptedEnvelope): String = client.decrypt(envelope).decodeToString()

        suspend fun sessionWith(remote: Device): SecureSession = assertNotNull(storage.sessions.load(remote.address))

        suspend fun origin(remote: Device): SessionInitiationId? = engine.sessionInfo(sessionWith(remote)).initiationId

        suspend fun isRetired(remote: Device, id: SessionInitiationId) = storage.sessionInitiations.isRetired(remote.address, id)

        /** The initiation [envelope] (a PreKeyMessage to this device) belongs to. */
        suspend fun initiationOf(envelope: EncryptedEnvelope): SessionInitiationId =
            SessionInitiationId.of(assertIs<PreKeyMessage>(CiphertextMessageCodec.decode(envelope.payload)), identityKey())
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
        assertFailsWith<ProtocolException.DecryptionFailed> { bob.client.decrypt(two) }
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
        assertFailsWith<SecureMessageClientException.StaleSessionInitiation> { bob.client.decrypt(oldFirst) }
        assertFailsWith<SecureMessageClientException.StaleSessionInitiation> { bob.client.decrypt(oldSecond) }
        assertUnchanged(before, bob.snapshot(alice))
        assertEquals(current, bob.origin(alice))
        assertTrue(bob.isRetired(alice, old))
        assertFalse(bob.isRetired(alice, current))

        // Also after a restart of the client.
        bob.restart()
        assertFailsWith<SecureMessageClientException.StaleSessionInitiation> { bob.client.decrypt(oldFirst) }
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
        assertFailsWith<SecureMessageClientException.StaleSessionInitiation> { bob.client.decrypt(old) }
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
            assertFailsWith<SecureMessageClientException.SessionCollision> { bob.client.decrypt(toBob) }
        }

        suspend fun deliverToAlice() = if (aliceWins) {
            assertFailsWith<SecureMessageClientException.SessionCollision> { alice.client.decrypt(toAlice) }
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
            assertIs<RatchetMessage>(CiphertextMessageCodec.decode(a.client.encrypt(BOB, byteArrayOf(1)).payload))
            assertIs<RatchetMessage>(CiphertextMessageCodec.decode(b.client.encrypt(ALICE, byteArrayOf(1)).payload))
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
        assertFailsWith<SecureMessageClientException.SessionCollision> { winner.client.decrypt(toWinner) }
        assertUnchanged(before, winner.snapshot(loser))
        assertNotNull(winner.storage.preKeys.oneTimePreKey(otpk), "a rejected initiation consumes no one-time prekey")
        assertTrue(winner.isRetired(loser, losing))

        // The loser switches to the winning session.
        loser.decryptText(toLoser)
        assertBidirectional(loser, winner, 1)

        // A replay of the losing initiation can never become current.
        val current = winner.origin(loser)
        assertFailsWith<SecureMessageClientException.StaleSessionInitiation> { winner.client.decrypt(toWinner) }
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
        assertFailsWith<SecureMessageClientException.SessionCollision> { winner.client.decrypt(toWinner) }
        assertFailsWith<SecureMessageClientException.StaleSessionInitiation> { winner.client.decrypt(second) }

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
            impostor.client.send(BOB, "I am Alice".encodeToByteArray())
            val envelope = bob.receiveOne()
            val error = assertFailsWith<SecureMessageClientException.IdentityChanged> { bob.client.decrypt(envelope) }
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

    // Sessions from before milestone 6

    /** Rewrites an established session in the version 1 state format, which has no origin. */
    private fun SecureSession.asLegacyEstablished(): SecureSession {
        // v3 with pending absent: version | len+AD(128) | 0x00 | 0x01 id[32] | accepted flag [id:u32] | len+ratchet
        val originFlag = 1 + 4 + 128 + 1
        assertEquals(3, state[0].toInt())
        assertEquals(0, state[originFlag - 1].toInt(), "established session")
        assertEquals(1, state[originFlag].toInt())
        val acceptedFlag = originFlag + 33
        val ratchetStart = acceptedFlag + if (state[acceptedFlag].toInt() == 1) 5 else 1
        val legacy = state.copyOfRange(0, originFlag) + state.copyOfRange(ratchetStart, state.size)
        legacy[0] = 1
        return copy(state = legacy)
    }

    private suspend fun legacySession(withOneTimePreKey: Boolean): Pair<Device, Device> {
        val alice = device(ALICE)
        val bob = device(BOB, withOneTimePreKey)
        establish(alice, bob)
        bob.storage.sessions.store(bob.sessionWith(alice).asLegacyEstablished())
        assertNull(bob.origin(alice))
        assertBidirectional(alice, bob, 0)
        return alice to bob
    }

    @Test
    fun legacySessionIsReplacedByAnInitiationWithAnUnusedOneTimePreKey() = runTest {
        val (alice, bob) = legacySession(withOneTimePreKey = true)
        alice.storage.sessions.remove(BOB)
        bob.publish()
        alice.send(bob, "new")
        val envelope = bob.receiveOne()
        assertEquals("new", bob.decryptText(envelope))
        assertEquals(bob.initiationOf(envelope), bob.origin(alice))
        assertBidirectional(alice, bob, 1)
    }

    @Test
    fun legacySessionIsNotReplacedWithoutProofOfANewInitiation() = runTest {
        val (alice, bob) = legacySession(withOneTimePreKey = false)
        alice.storage.sessions.remove(BOB)
        alice.send(bob, "maybe a replay")
        val before = bob.snapshot(alice)
        assertFailsWith<ProtocolException> { bob.client.decrypt(bob.receiveOne()) }
        assertUnchanged(before, bob.snapshot(alice))
        assertNull(bob.origin(alice))
    }

    @Test
    fun legacySessionAcceptsItsOwnRepeatedPreKeyMessages() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        alice.send(bob, "one")
        alice.send(bob, "two")
        val (one, two) = bob.receiveAll()
        bob.decryptText(one)
        bob.storage.sessions.store(bob.sessionWith(alice).asLegacyEstablished())

        assertEquals("two", bob.decryptText(two))
        assertNull(bob.origin(alice), "no origin taken from unauthenticated header fields")
    }

    @Test
    fun sessionWithoutPinIsNeverReplaced() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        establish(alice, bob)
        // A session whose pin is missing, as stored before milestone 5.
        val unpinned = InMemoryClientStorage()
        unpinned.transaction {
            identity.store(assertNotNull(bob.storage.identity.identity()))
            sessions.store(bob.sessionWith(alice))
            val signedPreKey = assertNotNull(bob.storage.preKeys.currentSignedPreKey())
            preKeys.storeCurrentSignedPreKey(signedPreKey, Clock.System.now())
            preKeys.storeOneTimePreKeys(bob.storage.preKeys.publicOneTimePreKeys().map { assertNotNull(bob.storage.preKeys.oneTimePreKey(it.id)) })
        }
        val legacyBob = Device(BOB, unpinned)
        network.publish(legacyBob.client)

        alice.storage.sessions.remove(BOB)
        alice.send(legacyBob, "new")
        val before = legacyBob.snapshot(alice)
        assertFailsWith<ProtocolException.InvalidMessage> { legacyBob.client.decrypt(legacyBob.receiveOne()) }
        assertUnchanged(before, legacyBob.snapshot(alice))
        assertNull(before.pin)
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
        assertFailsWith<ProtocolException.InvalidMessage> { bob.client.decrypt(second) }
        assertNotNull(bob.storage.preKeys.oneTimePreKey(OneTimePreKeyId(1)))
    }
}
