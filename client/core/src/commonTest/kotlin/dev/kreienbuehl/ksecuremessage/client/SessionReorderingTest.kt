package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.PreKeyMessage
import dev.kreienbuehl.ksecuremessage.model.RatchetMessage
import dev.kreienbuehl.ksecuremessage.protocol.CiphertextMessageCodec
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.ProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.ProtocolException
import dev.kreienbuehl.ksecuremessage.protocol.SessionInitiationId
import dev.kreienbuehl.ksecuremessage.storage.inmemory.InMemoryClientStorage
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Session-level reordering (docs/transport-ordering.md). Sessions converge as
 * long as each (sender, recipient) stream is delivered and processed in the
 * order the sender handed it to the transport. Delivery is driven by hand:
 * mailboxes are drained explicitly and envelopes decrypted in a chosen order.
 */
class SessionReorderingTest {
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

        suspend fun publish() = network.publish(client)

        suspend fun send(to: Device, text: String) = client.send(to.address, text.encodeToByteArray())

        suspend fun receiveAll(): List<EncryptedEnvelope> = network.receive(address)

        suspend fun receiveOne(): EncryptedEnvelope = receiveAll().single()

        suspend fun decryptText(envelope: EncryptedEnvelope): String = client.decrypt(envelope).decodeToString()

        /** What processing [envelope] gives, as text: the plaintext or the kind of rejection. */
        suspend fun outcome(envelope: EncryptedEnvelope): String = try {
            decryptText(envelope)
        } catch (_: SecureMessageClientException.SessionCollision) {
            COLLISION
        } catch (_: SecureMessageClientException.StaleSessionInitiation) {
            STALE
        } catch (_: ProtocolException) {
            REJECTED
        }

        suspend fun origin(remote: Device): SessionInitiationId? =
            storage.sessions.load(remote.address)?.let { engine.sessionInfo(it).initiationId }

        suspend fun awaitingReply(remote: Device): Boolean =
            engine.sessionInfo(assertNotNull(storage.sessions.load(remote.address))).awaitingReply

        suspend fun isRetired(remote: Device, id: SessionInitiationId) = storage.sessionInitiations.isRetired(remote.address, id)

        suspend fun sessionBytes(remote: Device): ByteArray? = storage.sessions.load(remote.address)?.state
    }

    private suspend fun device(address: DeviceAddress) = Device(address).also {
        it.client.initialize()
        it.publish()
    }

    /**
     * Two devices that trust each other and have no session, each with its
     * own pending initiation ([SecureMessageClient.ensureSession]). Returned
     * as winner (smaller initiation ID) and loser, so every test runs the
     * same way whichever side's ID happens to be smaller.
     */
    private suspend fun pendingPair(): Pending {
        val alice = device(ALICE)
        val bob = device(BOB)
        alice.client.ensureSession(BOB)
        bob.client.ensureSession(ALICE)
        val aliceInitiation = assertNotNull(alice.origin(bob))
        val bobInitiation = assertNotNull(bob.origin(alice))
        return if (aliceInitiation < bobInitiation) {
            Pending(alice, bob, aliceInitiation, bobInitiation)
        } else {
            Pending(bob, alice, bobInitiation, aliceInitiation)
        }
    }

    private inner class Pending(val winner: Device, val loser: Device, val winning: SessionInitiationId, val losing: SessionInitiationId)

    private suspend fun assertConverged(p: Pending) {
        assertEquals(p.winning, p.winner.origin(p.loser), "winner stays on the winning initiation")
        assertEquals(p.winning, p.loser.origin(p.winner), "loser switched to the winning initiation")
        assertTrue(p.loser.isRetired(p.winner, p.losing))
        assertFalse(p.winner.isRetired(p.loser, p.winning))
        assertFalse(p.loser.isRetired(p.winner, p.winning))
        assertBidirectional(p.winner, p.loser, 1)
        assertBidirectional(p.loser, p.winner, 2)
    }

    private suspend fun assertBidirectional(one: Device, other: Device, round: Int) {
        one.send(other, "ping $round")
        assertEquals(listOf("ping $round"), other.receiveAll().map { other.outcome(it) })
        other.send(one, "pong $round")
        assertEquals(listOf("pong $round"), one.receiveAll().map { one.outcome(it) })
        assertIs<RatchetMessage>(CiphertextMessageCodec.decode(one.client.encrypt(other.address, byteArrayOf(1)).payload))
    }

    // Scenario 1: simultaneous initiation, both delivery orders, then a reply.

    @Test
    fun simultaneousInitiationConvergesInBothOrdersIncludingTheReply() = runTest {
        for (winnerReceivesFirst in listOf(false, true)) {
            val p = pendingPair()
            p.winner.send(p.loser, "from winner")
            p.loser.send(p.winner, "from loser")

            if (winnerReceivesFirst) {
                assertEquals(listOf(COLLISION), p.winner.receiveAll().map { p.winner.outcome(it) })
                assertTrue(p.winner.awaitingReply(p.loser), "the winner keeps waiting for a reply")
                assertEquals(listOf("from winner"), p.loser.receiveAll().map { p.loser.outcome(it) })
                p.loser.send(p.winner, "reply")
                assertEquals(listOf("reply"), p.winner.receiveAll().map { p.winner.outcome(it) })
            } else {
                assertEquals(listOf("from winner"), p.loser.receiveAll().map { p.loser.outcome(it) })
                p.loser.send(p.winner, "reply")
                // The losing PreKeyMessage was handed to the transport before the reply.
                assertEquals(listOf(COLLISION, "reply"), p.winner.receiveAll().map { p.winner.outcome(it) })
            }
            assertConverged(p)
        }
    }

    // Scenario 2: the reordered follow-up.

    /**
     * The divergence this milestone is about, reproduced by processing the
     * loser's reply on the winning session before its earlier losing
     * PreKeyMessage. This order breaks the (sender, recipient) ordering
     * contract; the test records what then happens.
     */
    @Test
    fun replyOvertakingTheLosingPreKeyMessageSplitsTheSessions() = runTest {
        val p = pendingPair()
        p.winner.send(p.loser, "from winner")
        p.loser.send(p.winner, "from loser")
        assertEquals(listOf("from winner"), p.loser.receiveAll().map { p.loser.outcome(it) })
        p.loser.send(p.winner, "reply")
        val (losingPreKeyMessage, reply) = p.winner.receiveAll()
        assertIs<PreKeyMessage>(CiphertextMessageCodec.decode(losingPreKeyMessage.payload))

        assertEquals("reply", p.winner.outcome(reply))
        assertFalse(p.winner.awaitingReply(p.loser), "the reply confirmed the winning session")
        // Now indistinguishable from a legitimate new initiation after a
        // state loss of the loser: accepted as a replacement.
        assertEquals("from loser", p.winner.outcome(losingPreKeyMessage))

        assertEquals(p.losing, p.winner.origin(p.loser))
        assertEquals(p.winning, p.loser.origin(p.winner))
        assertTrue(p.winner.isRetired(p.loser, p.winning))
        assertTrue(p.loser.isRetired(p.winner, p.losing))
        p.winner.send(p.loser, "lost")
        assertEquals(listOf(REJECTED), p.loser.receiveAll().map { p.loser.outcome(it) })
        p.loser.send(p.winner, "lost")
        assertEquals(listOf(REJECTED), p.winner.receiveAll().map { p.winner.outcome(it) })
    }

    /**
     * How the order above arises inside the library: the losing
     * PreKeyMessage is encrypted, its hand-off to the transport is slow, and
     * meanwhile the loser accepts the winning initiation and sends a reply.
     * The client must hand envelopes to the transport in encryption order.
     */
    @OptIn(ExperimentalCoroutinesApi::class)
    @Test
    fun slowSendOfTheLosingPreKeyMessageIsNotOvertakenByTheReply() = runTest {
        val p = pendingPair()
        p.winner.send(p.loser, "from winner")

        val held = network.holdNextSend(p.loser.address)
        val losingSend = launch { p.loser.send(p.winner, "from loser") }
        val losingEnvelope = held.reached.await()
        assertIs<PreKeyMessage>(CiphertextMessageCodec.decode(losingEnvelope.payload))

        assertEquals(listOf("from winner"), p.loser.receiveAll().map { p.loser.outcome(it) })
        val replySend = launch { p.loser.send(p.winner, "reply") }
        runCurrent()
        held.release.complete(Unit)
        losingSend.join()
        replySend.join()

        assertEquals(listOf(COLLISION, "reply"), p.winner.receiveAll().map { p.winner.outcome(it) })
        assertConverged(p)
    }

    // Scenario 3: delayed losing-initiation traffic.

    @Test
    fun delayedLosingTrafficNeverRollsTheWinningSessionBack() = runTest {
        val p = pendingPair()
        p.winner.send(p.loser, "from winner")
        p.loser.send(p.winner, "losing one")
        p.loser.send(p.winner, "losing two")
        assertEquals(listOf("from winner"), p.loser.receiveAll().map { p.loser.outcome(it) })
        p.loser.send(p.winner, "reply")

        val inbox = p.winner.receiveAll()
        assertEquals(listOf(COLLISION, STALE, "reply"), inbox.map { p.winner.outcome(it) })

        // The relay delivers the losing messages again, after the switch.
        val session = p.winner.sessionBytes(p.loser)
        assertEquals(listOf(STALE, STALE), inbox.take(2).map { p.winner.outcome(it) })
        assertContentEquals(session, p.winner.sessionBytes(p.loser), "no rollback")
        assertEquals(p.winning, p.winner.origin(p.loser))

        // Identity continuity still comes first: a different key for the
        // loser's address is rejected, whatever its initiation ID.
        val impostor = Device(p.loser.address).apply { client.initialize() }
        p.winner.publish()
        impostor.client.send(p.winner.address, "impostor".encodeToByteArray())
        assertFailsWith<SecureMessageClientException.IdentityChanged> { p.winner.client.decrypt(p.winner.receiveOne()) }
        assertContentEquals(session, p.winner.sessionBytes(p.loser))

        assertConverged(p)
    }

    // Scenario 4: replacement, then traffic of the replaced session.

    @Test
    fun trafficOfAReplacedSessionIsRejectedAndNeverSwitchesBack() = runTest {
        for (oldTrafficFirst in listOf(true, false)) {
            val alice = device(ALICE)
            val bob = device(BOB)
            alice.send(bob, "hello")
            val firstPreKeyMessage = bob.receiveOne()
            assertEquals("hello", bob.decryptText(firstPreKeyMessage))
            bob.send(alice, "re: hello")
            assertEquals("re: hello", alice.decryptText(alice.receiveOne()))
            val first = assertNotNull(bob.origin(alice))

            // Both have traffic of the first session in flight.
            alice.send(bob, "old from Alice")
            bob.send(alice, "old from Bob")
            // Alice loses her session state and starts a second session.
            alice.storage.sessions.remove(BOB)
            bob.publish()
            alice.send(bob, "new session")
            val second = assertNotNull(alice.origin(bob))
            assertNotEquals(first, second)

            val (oldFromAlice, newSession) = bob.receiveAll()
            if (oldTrafficFirst) {
                // Contract order: the old message still decrypts on the old session.
                assertEquals(listOf("old from Alice", "new session"), listOf(bob.outcome(oldFromAlice), bob.outcome(newSession)))
            } else {
                // Outside the contract: rejected on the new session, which stays.
                assertEquals("new session", bob.outcome(newSession))
                val session = bob.sessionBytes(alice)
                assertEquals(REJECTED, bob.outcome(oldFromAlice))
                assertContentEquals(session, bob.sessionBytes(alice))
            }
            assertEquals(second, bob.origin(alice))
            assertTrue(bob.isRetired(alice, first))

            // Bob's old message cannot be read by Alice's new session and changes nothing.
            val aliceSession = alice.sessionBytes(bob)
            assertEquals(listOf(REJECTED), alice.receiveAll().map { alice.outcome(it) })
            assertContentEquals(aliceSession, alice.sessionBytes(bob))

            // A late copy of the first session's PreKeyMessage never brings it back.
            assertEquals(STALE, bob.outcome(firstPreKeyMessage))
            assertEquals(second, bob.origin(alice))

            assertBidirectional(bob, alice, 1)
            assertBidirectional(alice, bob, 2)
            assertEquals(second, alice.origin(bob))
        }
    }

    // Scenario 5: restarts at the awkward points.

    @Test
    fun restartsDuringTheSwitchKeepTheSameOutcome() = runTest {
        val p = pendingPair()
        p.winner.send(p.loser, "from winner")
        p.loser.send(p.winner, "from loser")
        // Pending on both sides, both messages in flight.
        p.winner.restart()
        p.loser.restart()

        assertEquals(listOf("from winner"), p.loser.receiveAll().map { p.loser.outcome(it) })
        // The loser switched but has not replied yet.
        p.loser.restart()
        p.loser.send(p.winner, "reply")

        val (losing, reply) = p.winner.receiveAll()
        assertEquals(COLLISION, p.winner.outcome(losing))
        // The collision is decided, the reply not yet processed.
        p.winner.restart()
        assertEquals(STALE, p.winner.outcome(losing), "the retired initiation survives the restart")
        assertEquals("reply", p.winner.outcome(reply))
        p.winner.restart()
        p.loser.restart()
        assertConverged(p)
    }

    private companion object {
        const val COLLISION = "<collision>"
        const val STALE = "<stale>"
        const val REJECTED = "<rejected>"
    }
}
