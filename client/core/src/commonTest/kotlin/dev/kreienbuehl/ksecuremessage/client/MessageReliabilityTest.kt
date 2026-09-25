package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.LogicalMessageId
import dev.kreienbuehl.ksecuremessage.protocol.ProtocolException
import dev.kreienbuehl.ksecuremessage.protocol.SecurePayload
import dev.kreienbuehl.ksecuremessage.protocol.SecurePayloadCodec
import kotlinx.coroutines.test.runTest
import kotlin.coroutines.cancellation.CancellationException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.days

/**
 * Milestone 8 message reliability (docs/message-reliability.md): logical
 * message IDs, encrypted acknowledgements, pending outbound messages,
 * duplicate suppression and retry.
 */
class MessageReliabilityTest {
    private val network = FlakyNetwork()

    private suspend fun device(address: DeviceAddress) =
        ReliableDevice(address, network).start()

    /** A message and its acknowledgement: both sides end with nothing pending. */
    private suspend fun roundTrip(from: ReliableDevice, to: ReliableDevice, text: String): LogicalMessageId {
        val sent = from.send(to, text)
        assertEquals(text, to.receiveOne().text())
        val ack = assertIs<ReceiveResult.Acknowledgement>(from.receiveOne())
        assertEquals(sent.id, ack.id)
        assertTrue(ack.cleared)
        return sent.id
    }

    // Basic flow

    @Test
    fun messageIsPendingUntilAcknowledged() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)

        val sent = alice.send(bob, "hello")
        // The transport took the envelope; that is not an acknowledgement.
        assertEquals(listOf(sent.id), alice.pending(bob))
        assertEquals("hello", alice.client.pendingMessages(BOB).single().plaintext.decodeToString())

        val received = assertIs<ReceiveResult.Message>(bob.receiveOne())
        assertEquals(ALICE, received.sender)
        assertEquals(sent.id, received.id)
        assertEquals("hello", received.plaintext.decodeToString())
        assertTrue(received.ackSent)
        assertTrue(bob.isProcessed(alice, sent.id))
        assertEquals(listOf(sent.id), alice.pending(bob))

        val ack = assertIs<ReceiveResult.Acknowledgement>(alice.receiveOne())
        assertEquals(BOB, ack.sender)
        assertEquals(sent.id, ack.id)
        assertTrue(ack.cleared)
        assertEquals(emptyList(), alice.pending(bob))

        // An acknowledgement is not acknowledged.
        assertEquals(emptyList(), bob.inbox())

        alice.restart()
        bob.restart()
        assertEquals(emptyList(), alice.pending(bob))
        assertTrue(bob.isProcessed(alice, sent.id))
        roundTrip(bob, alice, "reply")
        roundTrip(alice, bob, "again")
    }

    @Test
    fun pendingStateSurvivesRestartAndIsClearedAfterIt() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val sent = alice.send(bob, "before restart")
        alice.restart()
        bob.restart()
        assertEquals(listOf(sent.id), alice.pending(bob))

        assertEquals("before restart", bob.receiveOne().text())
        bob.restart()
        assertTrue(assertIs<ReceiveResult.Acknowledgement>(alice.receiveOne()).cleared)
        alice.restart()
        assertEquals(emptyList(), alice.pending(bob))
    }

    @Test
    fun logicalIdsAreDistinctAndIndependentOfEnvelopeIds() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val first = alice.send(bob, "one")
        val second = alice.send(bob, "one")
        assertNotEquals(first.id, second.id)
        assertNotEquals(first.id.toString(), first.envelope.id.value)
    }

    // Duplicates

    @Test
    fun retryOfAnAcceptedMessageIsNotDeliveredAgainButAcknowledgedAgain() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val sent = alice.send(bob, "once")
        assertEquals("once", bob.receiveOne().text())

        assertEquals(listOf(sent.id), alice.client.retryPendingMessages(BOB))
        val retried = network.sent.last()
        assertNotEquals(sent.envelope.id, retried.id, "a retry is a new envelope")
        assertFalse(sent.envelope.payload.contentEquals(retried.payload), "a retry is fresh ciphertext")

        val duplicate = assertIs<ReceiveResult.Duplicate>(bob.receive(bob.inbox().single()))
        assertEquals(sent.id, duplicate.id)
        assertTrue(duplicate.ackSent)

        val acks = alice.inbox().map { assertIs<ReceiveResult.Acknowledgement>(alice.receive(it)) }
        assertEquals(listOf(true, false), acks.map { it.cleared }, "the second acknowledgement is harmless")
        assertEquals(emptyList(), alice.pending(bob))
        assertEquals(emptyList(), bob.inbox())
    }

    /**
     * The same envelope twice: the ratchet has used the message key, so the
     * second decryption fails before the reliability layer sees it.
     */
    @Test
    fun replayedEnvelopeIsRejectedByTheRatchet() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        alice.send(bob, "first contact")
        val first = bob.inbox().single()
        bob.receive(first).text()
        alice.receiveOne()
        roundTrip(bob, alice, "established")
        alice.send(bob, "ratchet message")
        val second = bob.inbox().single()
        bob.receive(second).text()
        alice.receiveOne()

        for (replay in listOf(first, second)) {
            assertFailsWith<ProtocolException> { bob.receive(replay) }
        }
        assertEquals(emptyList(), alice.inbox(), "nothing acknowledged")
    }

    // Lost acknowledgements

    @Test
    fun lostAcknowledgementIsRecoveredByRetry() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val sent = alice.send(bob, "important")

        network.failingSenders += BOB
        val received = assertIs<ReceiveResult.Message>(bob.receiveOne())
        assertFalse(received.ackSent)
        assertTrue(bob.isProcessed(alice, sent.id), "processed although the acknowledgement failed")
        assertEquals(emptyList(), alice.inbox())
        assertEquals(listOf(sent.id), alice.pending(bob))

        network.failingSenders -= BOB
        bob.restart()
        alice.client.retryPendingMessages(BOB)
        val duplicate = assertIs<ReceiveResult.Duplicate>(bob.receiveOne())
        assertTrue(duplicate.ackSent)
        assertTrue(assertIs<ReceiveResult.Acknowledgement>(alice.receiveOne()).cleared)
        assertEquals(emptyList(), alice.pending(bob))
    }

    @Test
    fun cancellationOfTheAcknowledgementIsNotSwallowed() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val sent = alice.send(bob, "hi")
        network.cancellingSenders += BOB
        assertFailsWith<CancellationException> { bob.receiveOne() }
        assertTrue(bob.isProcessed(alice, sent.id))
    }

    // Acknowledgements

    @Test
    fun unknownAndRepeatedAcknowledgementsAreHarmlessAndNeverAnswered() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val id = roundTrip(alice, bob, "hello")

        for (ackId in listOf(LogicalMessageId.random(), id)) {
            bob.sendFrame(alice, SecurePayload.Acknowledgement(ackId))
            val ack = assertIs<ReceiveResult.Acknowledgement>(alice.receiveOne())
            assertFalse(ack.cleared)
            assertEquals(emptyList(), bob.inbox(), "no acknowledgement of an acknowledgement")
        }
    }

    @Test
    fun acknowledgementFromAnotherPeerDoesNotClearAPendingMessage() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val carol = device(CAROL)
        roundTrip(alice, bob, "hello Bob")
        val toCarol = alice.send(carol, "for Carol only")

        bob.sendFrame(alice, SecurePayload.Acknowledgement(toCarol.id))
        val ack = assertIs<ReceiveResult.Acknowledgement>(alice.receiveOne())
        assertEquals(BOB, ack.sender)
        assertFalse(ack.cleared)
        assertEquals(listOf(toCarol.id), alice.pending(carol))

        assertEquals("for Carol only", carol.receiveOne().text())
        assertTrue(assertIs<ReceiveResult.Acknowledgement>(alice.receiveOne()).cleared)
        assertEquals(emptyList(), alice.pending(carol))
    }

    @Test
    fun sameRawIdFromTwoSendersIsTwoMessages() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val carol = device(CAROL)
        val id = LogicalMessageId.random()
        alice.sendFrame(bob, SecurePayload.ApplicationMessage(id, "from Alice".encodeToByteArray()))
        assertEquals("from Alice", bob.receiveOne().text())
        // The fake relay hands out the lowest one-time prekey; Alice used it.
        network.fake.publish(bob.client)
        carol.sendFrame(bob, SecurePayload.ApplicationMessage(id, "from Carol".encodeToByteArray()))
        assertEquals("from Carol", bob.receiveOne().text())
        assertTrue(bob.isProcessed(alice, id))
        assertTrue(bob.isProcessed(carol, id))
    }

    // Several pending messages

    @Test
    fun pendingMessagesKeepTheirOrderAcrossRestartsAndRetries() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val ids = listOf("m1", "m2", "m3").map { alice.send(bob, it).id }
        bob.inbox() // lost in transit
        alice.restart()
        assertEquals(ids, alice.pending(bob))
        assertEquals(listOf("m1", "m2", "m3"), alice.client.pendingMessages(BOB).map { it.plaintext.decodeToString() })

        assertEquals(ids, alice.client.retryPendingMessages(BOB))
        val retried = bob.inbox()
        assertEquals(3, retried.size)

        // Only the acknowledgement of m2 gets through.
        network.failingSenders += BOB
        assertEquals("m1", bob.receive(retried[0]).text())
        network.failingSenders -= BOB
        assertEquals("m2", bob.receive(retried[1]).text())
        network.failingSenders += BOB
        assertEquals("m3", bob.receive(retried[2]).text())
        network.failingSenders -= BOB

        assertEquals(ids[1], assertIs<ReceiveResult.Acknowledgement>(alice.receiveOne()).id)
        assertEquals(listOf(ids[0], ids[2]), alice.pending(bob))

        alice.restart()
        assertEquals(listOf(ids[0], ids[2]), alice.client.retryPendingMessages(BOB))
        val duplicates = bob.inbox().map { assertIs<ReceiveResult.Duplicate>(bob.receive(it)) }
        assertEquals(listOf(ids[0], ids[2]), duplicates.map { it.id })
        alice.inbox().forEach { assertTrue(assertIs<ReceiveResult.Acknowledgement>(alice.receive(it)).cleared) }
        assertEquals(emptyList(), alice.pending(bob))
        assertEquals(emptyList(), alice.client.retryPendingMessages(BOB))
    }

    // Send failures

    @Test
    fun failedHandOffKeepsTheMessagePending() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        network.failingSenders += ALICE
        val error = assertFailsWith<SecureMessageClientException.MessageNotSent> { alice.send(bob, "offline") }
        assertIs<SecureMessageTransportException>(error.cause)
        assertEquals(listOf(error.messageId), alice.pending(bob))
        assertEquals(emptyList(), bob.inbox())

        // Retry also fails and stops at the first message.
        assertFailsWith<SecureMessageClientException.MessageNotSent> { alice.client.retryPendingMessages(BOB) }
        assertEquals(listOf(error.messageId), alice.pending(bob))

        network.failingSenders -= ALICE
        alice.restart()
        assertEquals(listOf(error.messageId), alice.client.retryPendingMessages(BOB))
        val received = assertIs<ReceiveResult.Message>(bob.receiveOne())
        assertEquals(error.messageId, received.id)
        assertEquals("offline", received.plaintext.decodeToString())
        assertTrue(assertIs<ReceiveResult.Acknowledgement>(alice.receiveOne()).cleared)
    }

    @Test
    fun oversizedMessageIsRejectedBeforeAnythingIsStored() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        assertFailsWith<ProtocolException.MessageTooLarge> {
            alice.client.send(BOB, ByteArray(SecurePayloadCodec.MAX_BODY_SIZE + 1))
        }
        assertEquals(emptyList(), alice.pending(bob))
        assertNull(alice.storage.sessions.load(BOB))
        assertEquals(emptyList(), bob.inbox())

        val largest = alice.client.send(BOB, ByteArray(SecurePayloadCodec.MAX_BODY_SIZE) { 7 })
        val received = assertIs<ReceiveResult.Message>(bob.receiveOne())
        assertEquals(largest.id, received.id)
        assertContentEquals(ByteArray(SecurePayloadCodec.MAX_BODY_SIZE) { 7 }, received.plaintext)
    }

    // Rejected messages are never acknowledged

    @Test
    fun plaintextWithoutAReliabilityFrameIsRejectedAndChangesNothing() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val oneTimePreKeys = bob.storage.preKeys.oneTimePreKeyCount()

        // A peer before milestone 8 encrypts raw application bytes.
        alice.client.sendRaw(BOB, "legacy plaintext".encodeToByteArray())
        assertFailsWith<ProtocolException.UnsupportedSecurePayloadVersion> { bob.receiveOne() }
        assertNull(bob.storage.sessions.load(ALICE))
        assertNull(bob.storage.remoteIdentities.identityKey(ALICE))
        assertEquals(oneTimePreKeys, bob.storage.preKeys.oneTimePreKeyCount())
        assertEquals(emptyList(), alice.inbox())

        roundTrip(alice, bob, "framed")
        roundTrip(bob, alice, "reply")
        val session = bob.storage.sessions.load(ALICE)!!.state
        alice.client.sendRaw(BOB, byteArrayOf(SecurePayloadCodec.VERSION.toByte(), 0x01, 0x02))
        assertFailsWith<ProtocolException.MalformedSecurePayload> { bob.receiveOne() }
        assertContentEquals(session, bob.storage.sessions.load(ALICE)!!.state, "ratchet step rolled back")
        assertEquals(emptyList(), alice.inbox())
        roundTrip(alice, bob, "still works")
    }

    @Test
    fun changedIdentityIsNotAcknowledged() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        roundTrip(alice, bob, "hello")

        val impostor = ReliableDevice(ALICE, network).also { it.client.initialize() }
        val forged = impostor.send(bob, "forged")
        assertFailsWith<SecureMessageClientException.IdentityChanged> { bob.receiveOne() }
        assertFalse(bob.isProcessed(alice, forged.id))
        assertEquals(emptyList(), impostor.inbox())
        assertEquals(listOf(forged.id), impostor.pending(bob))
    }

    @Test
    fun initiationWithAnExpiredSignedPreKeyIsNotAcknowledged() = runTest {
        val clock = ManualClock()
        val configuration = PreKeyConfiguration(4, signedPreKeyRotationAge = 7.days, signedPreKeyGracePeriod = 30.days)
        val alice = ReliableDevice(ALICE, network, configuration = configuration, clock = clock).start()
        val bob = ReliableDevice(BOB, network, configuration = configuration, clock = clock).start()

        val delayed = alice.send(bob, "delayed")
        clock.advanceBy(8.days)
        bob.client.initialize()
        clock.advanceBy(31.days)
        bob.client.initialize()

        assertFailsWith<SecureMessageClientException.ExpiredSignedPreKey> { bob.receiveOne() }
        assertFalse(bob.isProcessed(alice, delayed.id))
        assertEquals(emptyList(), alice.inbox())
        assertEquals(listOf(delayed.id), alice.pending(bob))
    }
}
