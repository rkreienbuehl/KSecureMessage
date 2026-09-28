package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.InboundFinalization
import dev.kreienbuehl.ksecuremessage.model.LogicalMessageId
import dev.kreienbuehl.ksecuremessage.model.MessageDiscardReason
import dev.kreienbuehl.ksecuremessage.protocol.ApplicationMessageDigest
import dev.kreienbuehl.ksecuremessage.protocol.SecurePayload
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.milliseconds

/**
 * Milestone 21 explicit discard and pending pagination
 * (docs/message-discard.md): a pending message ends as committed or
 * discarded, once, by an explicit application call; both are acknowledged
 * alike; pending messages are enumerated by a sequence cursor.
 */
class MessageDiscardTest {
    private val network = FlakyNetwork()
    private val clock = ManualClock()

    private suspend fun device(address: DeviceAddress) = ReliableDevice(address, network, clock = clock).start()

    private suspend fun ReliableDevice.discard(
        message: ReceivedMessage,
        reason: MessageDiscardReason = MessageDiscardReason.UNSUPPORTED_CONTENT,
    ): DiscardResult = client.discardReceivedMessage(message, reason)

    private suspend fun ReliableDevice.finalization(from: ReliableDevice, id: LogicalMessageId): InboundFinalization? =
        storage.processedInbound.get(from.address, id)?.finalization

    // Discard

    @Test
    fun discardRemovesThePlaintextRecordsATombstoneAndThenAcknowledges() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val sent = alice.send(bob, "unprocessable")
        val delivered = bob.receiveOne().delivery()

        clock.advanceBy(5.milliseconds)
        val result = bob.discard(delivered, MessageDiscardReason.POLICY_REJECTED)
        assertEquals(DiscardStatus.DISCARDED, result.status)
        assertEquals(ALICE, result.sender)
        assertEquals(sent.id, result.id)
        assertTrue(result.ackSent)

        assertFalse(bob.isPendingInbound(alice, sent.id), "the plaintext is not kept")
        assertEquals(emptyList(), bob.client.allPendingReceivedMessages())
        assertEquals(0L, bob.client.pendingReceivedMessageCount())
        val tombstone = assertNotNull(bob.storage.processedInbound.get(ALICE, sent.id))
        assertEquals(InboundFinalization.DISCARDED, tombstone.finalization)
        assertEquals(MessageDiscardReason.POLICY_REJECTED, tombstone.discardReason)
        assertEquals(clock.now, tombstone.finalizedAt)
        assertContentEquals(ApplicationMessageDigest.of("unprocessable".encodeToByteArray()), tombstone.digest)

        // The sender sees an ordinary acknowledgement: it cannot tell a discard from a commit.
        assertTrue(assertIs<ReceiveResult.Acknowledgement>(alice.receiveOne()).cleared)
        assertEquals(emptyList(), alice.pending(bob))
    }

    @Test
    fun failedAcknowledgementKeepsTheDiscardAndTheRetryIsAcknowledged() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val sent = alice.send(bob, "dropped")
        val delivered = bob.receiveOne().delivery()

        network.failingSenders += BOB
        val result = bob.discard(delivered)
        network.failingSenders -= BOB
        assertEquals(DiscardStatus.DISCARDED, result.status)
        assertFalse(result.ackSent)
        assertFalse(bob.isPendingInbound(alice, sent.id))
        assertEquals(InboundFinalization.DISCARDED, bob.finalization(alice, sent.id))
        assertEquals(listOf(sent.id), alice.pending(bob), "the sender keeps it pending")

        alice.client.retryPendingMessages(BOB)
        val duplicate = assertIs<ReceiveResult.AlreadyDiscarded>(bob.receiveOne())
        assertEquals(ALICE, duplicate.sender)
        assertEquals(sent.id, duplicate.id)
        assertTrue(duplicate.ackSent)
        assertEquals(emptyList(), bob.client.allPendingReceivedMessages(), "not delivered again")
        assertTrue(assertIs<ReceiveResult.Acknowledgement>(alice.receiveOne()).cleared)
    }

    @Test
    fun discardSurvivesARestart() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val sent = alice.send(bob, "restart")
        network.failingSenders += BOB
        bob.discard(bob.receiveOne().delivery(), MessageDiscardReason.USER_REJECTED)
        network.failingSenders -= BOB

        bob.restart()
        alice.client.retryPendingMessages(BOB)
        assertTrue(assertIs<ReceiveResult.AlreadyDiscarded>(bob.receiveOne()).ackSent)
        assertEquals(MessageDiscardReason.USER_REJECTED, bob.storage.processedInbound.get(ALICE, sent.id)?.discardReason)
    }

    @Test
    fun discardIsIdempotentAndKeepsTheFirstReason() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val sent = alice.send(bob, "twice")
        val delivered = bob.receiveOne().delivery()

        assertEquals(DiscardStatus.DISCARDED, bob.discard(delivered, MessageDiscardReason.USER_REJECTED).status)
        clock.advanceBy(1.days)
        val again = bob.client.discardReceivedMessage(ALICE, sent.id, MessageDiscardReason.OTHER)
        assertEquals(DiscardStatus.ALREADY_DISCARDED, again.status)
        assertTrue(again.ackSent, "acknowledged again")
        val tombstone = assertNotNull(bob.storage.processedInbound.get(ALICE, sent.id))
        assertEquals(MessageDiscardReason.USER_REJECTED, tombstone.discardReason)
        assertEquals(clock.now - 1.days, tombstone.finalizedAt, "not written again")

        val acks = alice.inbox().map { assertIs<ReceiveResult.Acknowledgement>(alice.receive(it)) }
        assertEquals(listOf(true, false), acks.map { it.cleared })
    }

    @Test
    fun aCommittedMessageCannotBeDiscarded() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val sent = alice.send(bob, "committed")
        val delivered = bob.receiveOne().delivery()
        bob.client.commitReceivedMessage(delivered)

        val result = bob.discard(delivered)
        assertEquals(DiscardStatus.ALREADY_COMMITTED, result.status)
        assertTrue(result.ackSent)
        val tombstone = assertNotNull(bob.storage.processedInbound.get(ALICE, sent.id))
        assertEquals(InboundFinalization.COMMITTED, tombstone.finalization)
        assertNull(tombstone.discardReason)
        assertEquals(CommitStatus.ALREADY_COMMITTED, bob.client.commitReceivedMessage(delivered).status)
    }

    @Test
    fun aDiscardedMessageCannotBeCommitted() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val sent = alice.send(bob, "discarded")
        val delivered = bob.receiveOne().delivery()
        bob.discard(delivered)

        val result = bob.client.commitReceivedMessage(delivered)
        assertEquals(CommitStatus.ALREADY_DISCARDED, result.status)
        assertTrue(result.ackSent)
        assertEquals(InboundFinalization.DISCARDED, bob.finalization(alice, sent.id))
        assertEquals(CommitStatus.ALREADY_DISCARDED, bob.client.commitReceivedMessage(ALICE, sent.id).status)
    }

    @Test
    fun discardOfAnUnknownMessageFailsAndRecordsNothing() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val id = LogicalMessageId.random()
        val error = assertFailsWith<SecureMessageClientException.ReceivedMessageNotPending> {
            bob.client.discardReceivedMessage(ALICE, id, MessageDiscardReason.OTHER)
        }
        assertEquals(ALICE, error.sender)
        assertEquals(id, error.messageId)
        assertFalse(bob.isProcessed(alice, id))
        assertEquals(emptyList(), alice.inbox(), "nothing acknowledged")
    }

    @Test
    fun discardIsScopedToTheSender() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val carol = device(CAROL)
        val sent = alice.send(bob, "alice's")
        bob.receiveOne()
        assertFailsWith<SecureMessageClientException.ReceivedMessageNotPending> {
            bob.client.discardReceivedMessage(CAROL, sent.id, MessageDiscardReason.OTHER)
        }
        assertTrue(bob.isPendingInbound(alice, sent.id))
        assertFalse(bob.isProcessed(carol, sent.id))
    }

    @Test
    fun differentBodyForADiscardedIdIsRejectedAndNotAcknowledged() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val id = LogicalMessageId.random()
        alice.sendFrame(bob, SecurePayload.ApplicationMessage(id, "original".encodeToByteArray()))
        bob.discard(bob.receiveOne().delivery())
        alice.receiveOne()
        val session = assertNotNull(bob.storage.sessions.load(ALICE)).state

        alice.sendFrame(bob, SecurePayload.ApplicationMessage(id, "substitute".encodeToByteArray()))
        val error = assertFailsWith<SecureMessageClientException.LogicalMessageConflict> { bob.receiveOne() }
        assertEquals(id, error.messageId)
        assertEquals(emptyList(), alice.inbox(), "no acknowledgement")
        assertContentEquals(session, bob.storage.sessions.load(ALICE)?.state, "the ratchet step is rolled back")
        assertEquals(InboundFinalization.DISCARDED, bob.finalization(alice, id))
        assertFalse(bob.isPendingInbound(alice, id))
    }

    @Test
    fun failedTombstoneRollsBackTheDiscard() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val sent = alice.send(bob, "hello")
        val delivered = bob.receiveOne().delivery()

        bob.failing.failMarkProcessed = true
        assertFailsWith<StorageFailure> { bob.discard(delivered) }
        assertTrue(bob.isPendingInbound(alice, sent.id), "still pending")
        assertFalse(bob.isProcessed(alice, sent.id))
        assertEquals(emptyList(), alice.inbox(), "nothing acknowledged")

        bob.failing.failMarkProcessed = false
        bob.failing.failPendingInboundRemoval = true
        assertFailsWith<StorageFailure> { bob.discard(delivered) }
        assertTrue(bob.isPendingInbound(alice, sent.id))
        assertFalse(bob.isProcessed(alice, sent.id))
        assertEquals(emptyList(), alice.inbox())

        bob.failing.failPendingInboundRemoval = false
        assertEquals(DiscardStatus.DISCARDED, bob.discard(delivered).status)
        assertTrue(assertIs<ReceiveResult.Acknowledgement>(alice.receiveOne()).cleared)
    }

    // Races

    @Test
    fun commitRacingADiscardHasOneImmutableWinner() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val sent = alice.send(bob, "race")
        val delivered = bob.receiveOne().delivery()

        val commit = async { bob.client.commitReceivedMessage(delivered) }
        val discard = async { bob.discard(delivered) }
        val committed = commit.await().status
        val discarded = discard.await().status
        val winner = assertNotNull(bob.finalization(alice, sent.id))
        when (winner) {
            InboundFinalization.COMMITTED -> {
                assertEquals(CommitStatus.COMMITTED, committed)
                assertEquals(DiscardStatus.ALREADY_COMMITTED, discarded)
            }
            InboundFinalization.DISCARDED -> {
                assertEquals(DiscardStatus.DISCARDED, discarded)
                assertEquals(CommitStatus.ALREADY_DISCARDED, committed)
            }
        }
        assertFalse(bob.isPendingInbound(alice, sent.id))
        val acks = alice.inbox().map { assertIs<ReceiveResult.Acknowledgement>(alice.receive(it)) }
        assertEquals(1, acks.count { it.cleared })
    }

    @Test
    fun concurrentDiscardsDiscardOnce() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        alice.send(bob, "discard race")
        val delivered = bob.receiveOne().delivery()

        val results = List(3) { async { bob.discard(delivered) } }.awaitAll()
        assertEquals(listOf(DiscardStatus.DISCARDED, DiscardStatus.ALREADY_DISCARDED, DiscardStatus.ALREADY_DISCARDED), results.map { it.status }.sorted())
        val acks = alice.inbox().map { assertIs<ReceiveResult.Acknowledgement>(alice.receive(it)) }
        assertEquals(1, acks.count { it.cleared })
    }

    @Test
    fun discardRacingARetryNeverRedeliversAfterTheDiscard() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val sent = alice.send(bob, "retry race")
        val delivered = bob.receiveOne().delivery()
        alice.client.retryPendingMessages(BOB)
        val retry = bob.inbox().single()

        val discard = async { bob.discard(delivered) }
        val received = async { bob.receive(retry) }
        assertEquals(DiscardStatus.DISCARDED, discard.await().status)
        when (val result = received.await()) {
            is ReceiveResult.Delivery -> assertEquals("retry race", result.message.plaintext.decodeToString())
            is ReceiveResult.AlreadyDiscarded -> assertTrue(result.ackSent)
            is ReceiveResult.AlreadyCommitted -> error("never committed")
            is ReceiveResult.Acknowledgement -> error("not an acknowledgement")
        }
        assertEquals(emptyList(), bob.client.allPendingReceivedMessages())
        assertEquals(InboundFinalization.DISCARDED, bob.finalization(alice, sent.id))

        // Once the discard is recorded, a further copy is never delivered.
        alice.client.retryPendingMessages(BOB)
        bob.inbox().forEach { assertIs<ReceiveResult.AlreadyDiscarded>(bob.receive(it)) }
    }

    @Test
    fun retryObservedBeforeTheDiscardIsDeliveredThenTheDiscardWins() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val sent = alice.send(bob, "sequential")
        bob.receiveOne()
        alice.client.retryPendingMessages(BOB)
        val redelivered = bob.receiveOne().delivery()
        assertEquals(emptyList(), alice.inbox(), "a pending retry is not acknowledged")

        assertEquals(DiscardStatus.DISCARDED, bob.discard(redelivered).status)
        alice.client.retryPendingMessages(BOB)
        val acks = alice.inbox()
        assertEquals(1, acks.size)
        assertTrue(assertIs<ReceiveResult.Acknowledgement>(alice.receive(acks.single())).cleared)
        assertEquals(InboundFinalization.DISCARDED, bob.finalization(alice, sent.id))
    }

    // Retention

    @Test
    fun discardedTombstonesPruneLikeCommittedOnes() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val discarded = alice.send(bob, "discarded").id
        bob.discard(bob.receiveOne().delivery())
        val committed = alice.send(bob, "committed").id
        bob.acceptOne()
        val uncommitted = alice.send(bob, "uncommitted").id
        bob.receiveOne()
        val policy = ProcessedInboundRetentionPolicy(30.days)

        clock.advanceBy(30.days - 1.milliseconds)
        assertEquals(0, bob.client.pruneProcessedMessages(policy), "age just below the maximum")
        clock.advanceBy(1.milliseconds)
        assertEquals(2, bob.client.pruneProcessedMessages(policy), "age equal to the maximum, both outcomes")
        assertFalse(bob.isProcessed(alice, discarded))
        assertFalse(bob.isProcessed(alice, committed))
        assertEquals(listOf(uncommitted), bob.client.allPendingReceivedMessages().map { it.id }, "pending messages are never pruned")
    }

    @Test
    fun aPrunedDiscardedIdIsAcceptedAsNewAgain() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val id = LogicalMessageId.random()
        alice.sendFrame(bob, SecurePayload.ApplicationMessage(id, "first".encodeToByteArray()))
        bob.discard(bob.receiveOne().delivery())
        clock.advanceBy(31.days)
        assertEquals(1, bob.client.pruneProcessedMessages(ProcessedInboundRetentionPolicy(30.days)))

        alice.sendFrame(bob, SecurePayload.ApplicationMessage(id, "second".encodeToByteArray()))
        assertEquals("second", bob.receiveOne().text())
    }

    // Pagination

    @Test
    fun pagesFollowTheSequenceCursor() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val texts = (1..7).map { "m$it" }
        texts.forEach { alice.send(bob, it) }
        bob.inbox().forEach { bob.receive(it) }

        val first = bob.client.pendingReceivedMessages(limit = 3)
        assertEquals(listOf("m1", "m2", "m3"), first.messages.map { it.plaintext.decodeToString() })
        assertEquals(first.messages.last().sequence, first.nextAfterSequence)
        val second = bob.client.pendingReceivedMessages(first.nextAfterSequence, 3)
        assertEquals(listOf("m4", "m5", "m6"), second.messages.map { it.plaintext.decodeToString() })
        val last = bob.client.pendingReceivedMessages(second.nextAfterSequence, 3)
        assertEquals(listOf("m7"), last.messages.map { it.plaintext.decodeToString() })
        assertNull(last.nextAfterSequence, "the end")
        val exact = bob.client.pendingReceivedMessages(second.messages.first().sequence - 1, 3)
        assertEquals(second.messages.map { it.sequence }, exact.messages.map { it.sequence })

        val all = bob.client.pendingReceivedMessages(limit = PendingReceivedMessagePage.MAX_SIZE)
        assertEquals(texts, all.messages.map { it.plaintext.decodeToString() })
        assertNull(all.nextAfterSequence)
        val sequences = all.messages.map { it.sequence }
        assertEquals(sequences.sorted(), sequences)
        assertEquals(7L, bob.client.pendingReceivedMessageCount())
        assertEquals(7L, bob.client.pendingReceivedMessageCount(ALICE))
        assertEquals(0L, bob.client.pendingReceivedMessageCount(CAROL))
    }

    @Test
    fun aFullPageAtTheEndReportsNoFurtherPage() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        repeat(3) { alice.send(bob, "m$it") }
        bob.inbox().forEach { bob.receive(it) }
        assertNull(bob.client.pendingReceivedMessages(limit = 3).nextAfterSequence)
        assertEquals(emptyList(), bob.client.pendingReceivedMessages(Long.MAX_VALUE, 3).messages)
    }

    @Test
    fun pageBoundsAreValidated() = runTest {
        val bob = device(BOB)
        assertFailsWith<IllegalArgumentException> { bob.client.pendingReceivedMessages(limit = 0) }
        assertFailsWith<IllegalArgumentException> { bob.client.pendingReceivedMessages(limit = -1) }
        assertFailsWith<IllegalArgumentException> { bob.client.pendingReceivedMessages(limit = PendingReceivedMessagePage.MAX_SIZE + 1) }
        assertFailsWith<IllegalArgumentException> { bob.client.pendingReceivedMessages(-1, 1) }
        assertEquals(emptyList(), bob.client.pendingReceivedMessages(0, PendingReceivedMessagePage.MAX_SIZE).messages)
    }

    @Test
    fun pagesAreBoundedByTheMaximumSize() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        repeat(PendingReceivedMessagePage.MAX_SIZE + 5) { alice.send(bob, "m$it") }
        bob.inbox().forEach { bob.receive(it) }
        val first = bob.client.pendingReceivedMessages(limit = PendingReceivedMessagePage.MAX_SIZE)
        assertEquals(PendingReceivedMessagePage.MAX_SIZE, first.messages.size)
        val rest = bob.client.pendingReceivedMessages(first.nextAfterSequence, PendingReceivedMessagePage.MAX_SIZE)
        assertEquals(5, rest.messages.size)
        assertNull(rest.nextAfterSequence)
    }

    @Test
    fun finalizingBetweenPagesNeitherSkipsNorRepeats() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        (1..10).forEach { alice.send(bob, "m$it") }
        bob.inbox().forEach { bob.receive(it) }

        val first = bob.client.pendingReceivedMessages(limit = 4)
        assertEquals(listOf("m1", "m2", "m3", "m4"), first.messages.map { it.plaintext.decodeToString() })
        // Finalize returned and not yet returned messages between the pages.
        val later = bob.client.pendingReceivedMessages(first.nextAfterSequence, 4).messages
        bob.client.commitReceivedMessage(first.messages[1])
        bob.discard(first.messages[2])
        bob.client.commitReceivedMessage(later[0])
        bob.discard(later[1])
        alice.send(bob, "m11")
        bob.receiveOne()

        val seen = first.messages.map { it.plaintext.decodeToString() }.toMutableList()
        var after = first.nextAfterSequence
        while (after != null) {
            val page = bob.client.pendingReceivedMessages(after, 4)
            seen += page.messages.map { it.plaintext.decodeToString() }
            after = page.nextAfterSequence
        }
        assertEquals(listOf("m1", "m2", "m3", "m4", "m7", "m8", "m9", "m10", "m11"), seen, "new arrivals may appear later")
        assertEquals(listOf("m1", "m4", "m7", "m8", "m9", "m10", "m11"), bob.client.allPendingReceivedMessages().map { it.plaintext.decodeToString() })
        alice.inbox().forEach { alice.receive(it) }
    }

    @Test
    fun senderFilterUsesTheGlobalCursor() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val carol = device(CAROL)
        alice.send(bob, "a1")
        bob.receiveOne()
        // The fake relay hands out the lowest one-time prekey; Alice used it.
        network.fake.publish(bob.client)
        carol.send(bob, "c1")
        bob.receiveOne()
        alice.send(bob, "a2")
        bob.receiveOne()
        carol.send(bob, "c2")
        bob.receiveOne()
        alice.send(bob, "a3")
        bob.receiveOne()

        val first = bob.client.pendingReceivedMessages(limit = 2, sender = ALICE)
        assertEquals(listOf("a1", "a2"), first.messages.map { it.plaintext.decodeToString() })
        assertTrue(first.messages.all { it.sender == ALICE })
        val second = bob.client.pendingReceivedMessages(first.nextAfterSequence, 2, ALICE)
        assertEquals(listOf("a3"), second.messages.map { it.plaintext.decodeToString() })
        assertNull(second.nextAfterSequence)
        // The cursor is a global sequence: it also works with another filter.
        val fromCarol = bob.client.pendingReceivedMessages(first.nextAfterSequence, 2, CAROL)
        assertEquals(listOf("c2"), fromCarol.messages.map { it.plaintext.decodeToString() })
        assertEquals(3L, bob.client.pendingReceivedMessageCount(ALICE))
        assertEquals(2L, bob.client.pendingReceivedMessageCount(CAROL))
    }

    @Test
    fun pagingAndDiscardNeedAnInitializedClient() = runTest {
        val client = ReliableDevice(BOB, network, clock = clock).client
        assertFailsWith<SecureMessageClientException.NotInitialized> { client.pendingReceivedMessages(limit = 1) }
        assertFailsWith<SecureMessageClientException.NotInitialized> { client.pendingReceivedMessageCount() }
        assertFailsWith<SecureMessageClientException.NotInitialized> {
            client.discardReceivedMessage(ALICE, LogicalMessageId.random(), MessageDiscardReason.OTHER)
        }
    }
}
