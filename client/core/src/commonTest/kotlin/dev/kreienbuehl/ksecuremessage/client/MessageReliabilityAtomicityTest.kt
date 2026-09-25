package dev.kreienbuehl.ksecuremessage.client

import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Storage failures in the reliability layer roll back the whole step: the
 * transport never gets an envelope whose session or pending state was rolled
 * back, and no partial records stay. [FlakyNetwork] also checks that no
 * network call happens inside a transaction.
 */
class MessageReliabilityAtomicityTest {
    private val network = FlakyNetwork()

    private suspend fun devices() = ReliableDevice(ALICE, network).start() to ReliableDevice(BOB, network).start()

    @Test
    fun failedPendingStoreSendsNothingAndStoresNothing() = runTest {
        val (alice, bob) = devices()
        alice.failing.failPendingStore = true
        assertFailsWith<StorageFailure> { alice.send(bob, "hello") }

        assertEquals(emptyList(), network.sent)
        assertEquals(emptyList(), alice.pending(bob))
        assertNull(alice.storage.sessions.load(BOB), "the new session was rolled back")
        assertNull(alice.storage.remoteIdentities.identityKey(BOB))

        alice.failing.failPendingStore = false
        alice.send(bob, "hello")
        assertEquals("hello", bob.receiveOne().text())
    }

    @Test
    fun failedSessionStoreOnSendSendsNothingAndStoresNothing() = runTest {
        val (alice, bob) = devices()
        alice.send(bob, "first")
        bob.receiveOne()
        alice.receiveOne()
        val session = alice.storage.sessions.load(BOB)!!.state

        alice.failing.failSessionStore = true
        val sentBefore = network.sent.size
        assertFailsWith<StorageFailure> { alice.send(bob, "second") }
        assertEquals(sentBefore, network.sent.size)
        assertEquals(emptyList(), alice.pending(bob))
        assertContentEquals(session, alice.storage.sessions.load(BOB)!!.state)
    }

    @Test
    fun failedProcessedMarkerRollsBackTheWholeReceive() = runTest {
        val (alice, bob) = devices()
        val sent = alice.send(bob, "hello")
        val envelope = bob.inbox().single()

        bob.failing.failMarkProcessed = true
        assertFailsWith<StorageFailure> { bob.receive(envelope) }
        assertFalse(bob.isProcessed(alice, sent.id))
        assertNull(bob.storage.sessions.load(ALICE), "session acceptance rolled back")
        assertNull(bob.storage.remoteIdentities.identityKey(ALICE))
        assertEquals(emptyList(), alice.inbox(), "nothing acknowledged")

        // Nothing was consumed, so the same envelope is accepted afterwards.
        bob.failing.failMarkProcessed = false
        assertEquals("hello", bob.receive(envelope).text())
        assertTrue(assertIs<ReceiveResult.Acknowledgement>(alice.receiveOne()).cleared)
    }

    @Test
    fun failedPendingRemovalKeepsTheMessagePending() = runTest {
        val (alice, bob) = devices()
        val sent = alice.send(bob, "hello")
        bob.receiveOne()
        val ack = alice.inbox().single()
        val session = alice.storage.sessions.load(BOB)!!.state

        alice.failing.failPendingRemoval = true
        assertFailsWith<StorageFailure> { alice.receive(ack) }
        assertEquals(listOf(sent.id), alice.pending(bob))
        assertContentEquals(session, alice.storage.sessions.load(BOB)!!.state)

        alice.failing.failPendingRemoval = false
        assertTrue(assertIs<ReceiveResult.Acknowledgement>(alice.receive(ack)).cleared)
        assertEquals(emptyList(), alice.pending(bob))
    }

    @Test
    fun failedSessionStoreOnRetrySendsNothing() = runTest {
        val (alice, bob) = devices()
        val sent = alice.send(bob, "hello")
        bob.inbox() // lost
        val session = alice.storage.sessions.load(BOB)!!.state

        alice.failing.failSessionStore = true
        val sentBefore = network.sent.size
        assertFailsWith<StorageFailure> { alice.client.retryPendingMessages(BOB) }
        assertEquals(sentBefore, network.sent.size)
        assertEquals(listOf(sent.id), alice.pending(bob))
        assertContentEquals(session, alice.storage.sessions.load(BOB)!!.state)

        alice.failing.failSessionStore = false
        assertEquals(listOf(sent.id), alice.client.retryPendingMessages(BOB))
        assertEquals("hello", bob.receiveOne().text())
    }

    /** A failed acknowledgement never undoes the accepted message. */
    @Test
    fun failedAcknowledgementEncryptionKeepsTheMessageProcessed() = runTest {
        val (alice, bob) = devices()
        val sent = alice.send(bob, "hello")

        // The receive stores the session once; the acknowledgement's store fails.
        bob.failing.sessionStoresBeforeFailure = 1
        val received = assertIs<ReceiveResult.Message>(bob.receiveOne())
        bob.failing.sessionStoresBeforeFailure = null
        assertEquals("hello", received.plaintext.decodeToString())
        assertFalse(received.ackSent)
        assertTrue(bob.isProcessed(alice, sent.id))
        assertEquals(emptyList(), alice.inbox())

        alice.client.retryPendingMessages(BOB)
        assertTrue(assertIs<ReceiveResult.Duplicate>(bob.receiveOne()).ackSent)
        assertTrue(assertIs<ReceiveResult.Acknowledgement>(alice.receiveOne()).cleared)
        assertEquals(emptyList(), alice.pending(bob))
    }
}
