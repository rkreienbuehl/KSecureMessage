package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.LogicalMessageId
import kotlinx.coroutines.async
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
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Milestone 22 pending outbound pagination and explicit abandon
 * (docs/outbound-message-lifecycle.md): a pending sent message ends either by
 * the recipient's acknowledgement or by the application abandoning it
 * locally; pending messages are enumerated by a sequence cursor.
 */
class MessageAbandonTest {
    private val network = FlakyNetwork()

    private suspend fun device(address: DeviceAddress) = ReliableDevice(address, network).start()

    private suspend fun ReliableDevice.abandon(to: ReliableDevice, id: LogicalMessageId): AbandonStatus =
        client.abandonPendingMessage(to.address, id)

    private suspend fun ReliableDevice.sessionState(with: ReliableDevice): ByteArray? = storage.sessions.load(with.address)?.state

    // Abandon

    @Test
    fun abandonedMessageIsNeverResentAndItsLateAcknowledgementIsHarmless() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val sent = alice.send(bob, "never finalized")
        val delivered = bob.receiveOne().delivery()

        val listed = alice.client.pendingMessages(limit = 10).messages.single()
        assertEquals(BOB, listed.recipient)
        assertEquals(sent.id, listed.id)
        assertEquals("never finalized", listed.plaintext.decodeToString())

        assertEquals(AbandonStatus.ABANDONED, alice.client.abandonPendingMessage(listed))
        assertEquals(emptyList(), alice.client.pendingMessages(limit = 10).messages)
        assertEquals(0L, alice.client.pendingMessageCount())
        assertNull(alice.storage.pendingOutbound.get(BOB, sent.id))
        assertEquals(emptyList(), alice.client.retryPendingMessages(BOB))
        assertEquals(emptyList(), bob.inbox(), "the abandoned message is not resent")

        // Not a recall: Bob still has the delivered copy and can commit it.
        val commit = bob.commit(ReceiveResult.Delivery(delivered))
        assertEquals(CommitStatus.COMMITTED, commit.status)
        assertTrue(commit.ackSent)
        val ack = assertIs<ReceiveResult.Acknowledgement>(alice.receiveOne())
        assertEquals(sent.id, ack.id)
        assertFalse(ack.cleared, "nothing was pending any more")
        assertNull(alice.storage.pendingOutbound.get(BOB, sent.id), "the acknowledgement recreates nothing")
        assertFalse(alice.isProcessed(bob, sent.id), "an acknowledgement is not a received message")
        assertEquals(0L, alice.client.pendingMessageCount())

        // The session keeps working in both directions.
        alice.send(bob, "after the abandon")
        assertEquals("after the abandon", bob.acceptOne())
        assertTrue(assertIs<ReceiveResult.Acknowledgement>(alice.receiveOne()).cleared)
    }

    @Test
    fun abandonSendsNothingAndChangesOnlyThatMessage() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val carol = device(CAROL)
        val first = alice.send(bob, "first")
        val second = alice.send(bob, "second")
        val toCarol = alice.send(carol, "to Carol")
        bob.inbox().forEach { bob.receive(it) }
        carol.inbox().forEach { carol.receive(it) }
        // Alice also has a received message waiting for her commit and a committed one.
        bob.send(alice, "to Alice")
        val committed = bob.send(alice, "to Alice, committed").id
        val inbox = alice.inbox()
        val pendingFromBob = alice.receive(inbox[0]).delivery()
        alice.client.accept(inbox[1])
        assertTrue(assertIs<ReceiveResult.Acknowledgement>(bob.receiveOne()).cleared)
        val sessionBefore = alice.sessionState(bob)
        val handedOff = network.sent.size
        val fetches = network.bundleFetches

        assertEquals(AbandonStatus.ABANDONED, alice.abandon(bob, first.id))

        assertEquals(handedOff, network.sent.size, "no envelope")
        assertEquals(fetches, network.bundleFetches, "no bundle fetch")
        assertEquals(emptyList(), bob.inbox())
        assertEquals(emptyList(), carol.inbox())
        assertContentEquals(sessionBefore, alice.sessionState(bob), "the session is not touched")
        assertEquals(listOf(second.id), alice.pending(bob))
        assertEquals(listOf(toCarol.id), alice.pending(carol))
        assertTrue(alice.isPendingInbound(bob, pendingFromBob.id))
        assertTrue(alice.isProcessed(bob, committed))
        assertEquals(AbandonStatus.NOT_PENDING, alice.abandon(carol, first.id), "scoped to the recipient")
        assertEquals(listOf(toCarol.id), alice.pending(carol))
    }

    @Test
    fun abandonIsIdempotentAndUnknownMessagesAreNotPending() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val sent = alice.send(bob, "once")

        assertEquals(AbandonStatus.NOT_PENDING, alice.abandon(bob, LogicalMessageId.random()))
        assertEquals(listOf(sent.id), alice.pending(bob))
        assertEquals(AbandonStatus.ABANDONED, alice.abandon(bob, sent.id))
        assertEquals(AbandonStatus.NOT_PENDING, alice.abandon(bob, sent.id))
        assertEquals(emptyList(), alice.pending(bob))
    }

    @Test
    fun abandonedIdIsNotReusedAndSequencesKeepGrowing() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val abandoned = alice.send(bob, "abandoned")
        val abandonedSequence = alice.client.pendingMessages(limit = 1).messages.single().sequence
        alice.abandon(bob, abandoned.id)

        val next = alice.send(bob, "next")
        assertNotEquals(abandoned.id, next.id)
        val listed = alice.client.pendingMessages(limit = 10).messages.single()
        assertEquals(next.id, listed.id)
        assertTrue(listed.sequence > abandonedSequence, "never rewound")
    }

    @Test
    fun rolledBackAbandonKeepsTheMessagePending() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val sent = alice.send(bob, "kept")

        alice.failing.failPendingRemoval = true
        assertFailsWith<StorageFailure> { alice.abandon(bob, sent.id) }
        alice.failing.failPendingRemoval = false

        assertEquals(listOf(sent.id), alice.pending(bob))
        assertEquals(AbandonStatus.ABANDONED, alice.abandon(bob, sent.id))
    }

    @Test
    fun messageWhoseHandOffFailedCanBeAbandoned() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)

        network.failingSenders += ALICE
        val failure = assertFailsWith<SecureMessageClientException.MessageNotSent> { alice.send(bob, "never handed off") }
        network.failingSenders -= ALICE
        assertEquals(listOf(failure.messageId), alice.pending(bob))

        assertEquals(AbandonStatus.ABANDONED, alice.abandon(bob, failure.messageId))
        assertEquals(emptyList(), alice.client.retryPendingMessages(BOB))
        assertEquals(emptyList(), bob.inbox())
    }

    @Test
    fun messageWhoseRetryFailedToEncryptCanBeAbandoned() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val sent = alice.send(bob, "retry fails")
        bob.inbox()

        alice.failing.failSessionStore = true
        assertFailsWith<StorageFailure> { alice.client.retryPendingMessages(BOB) }
        alice.failing.failSessionStore = false
        assertEquals(listOf(sent.id), alice.pending(bob))

        assertEquals(AbandonStatus.ABANDONED, alice.abandon(bob, sent.id))
        assertEquals(emptyList(), alice.client.retryPendingMessages(BOB))
        assertEquals(emptyList(), bob.inbox())
    }

    @Test
    fun retryWithNothingPendingFetchesNoBundle() = runTest {
        val alice = device(ALICE)
        val sent = alice.send(device(BOB), "abandoned")
        // No session any more (for example after an identity change) and nothing pending.
        alice.storage.sessions.remove(BOB)
        alice.client.abandonPendingMessage(BOB, sent.id)
        val fetches = network.bundleFetches

        assertEquals(emptyList(), alice.client.retryPendingMessages(BOB))
        assertEquals(fetches, network.bundleFetches, "a bundle is fetched only for a message that needs a session")
    }

    @Test
    fun abandonNeedsAnInitializedClient() = runTest {
        val client = ReliableDevice(BOB, network).client
        assertFailsWith<SecureMessageClientException.NotInitialized> { client.pendingMessages(limit = 1) }
        assertFailsWith<SecureMessageClientException.NotInitialized> { client.pendingMessageCount() }
        assertFailsWith<SecureMessageClientException.NotInitialized> { client.abandonPendingMessage(ALICE, LogicalMessageId.random()) }
        assertFailsWith<SecureMessageClientException.NotInitialized> { client.retryPendingMessages(ALICE) }
    }

    // Acknowledgement versus abandon

    @Test
    fun acknowledgementBeforeTheAbandonLeavesNothingToAbandon() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val sent = alice.send(bob, "acknowledged first")
        bob.acceptOne()

        assertTrue(assertIs<ReceiveResult.Acknowledgement>(alice.receiveOne()).cleared)
        assertEquals(AbandonStatus.NOT_PENDING, alice.abandon(bob, sent.id))
        assertEquals(emptyList(), alice.pending(bob))
    }

    @Test
    fun abandonBeforeTheAcknowledgementLeavesNothingToClear() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val sent = alice.send(bob, "abandoned first")
        bob.acceptOne()

        assertEquals(AbandonStatus.ABANDONED, alice.abandon(bob, sent.id))
        val ack = assertIs<ReceiveResult.Acknowledgement>(alice.receiveOne())
        assertFalse(ack.cleared)
        assertEquals(emptyList(), alice.pending(bob))
    }

    @Test
    fun concurrentAcknowledgementAndAbandonRemoveTheMessageOnce() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val sent = alice.send(bob, "race")
        bob.acceptOne()
        val ackEnvelope = alice.inbox().single()

        val ack = async { assertIs<ReceiveResult.Acknowledgement>(alice.receive(ackEnvelope)) }
        val abandon = async { alice.abandon(bob, sent.id) }
        val cleared = ack.await().cleared
        val abandoned = abandon.await() == AbandonStatus.ABANDONED
        assertTrue(cleared != abandoned, "exactly one removal wins")
        assertEquals(emptyList(), alice.pending(bob))
    }

    @Test
    fun concurrentAbandonsAbandonOnce() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val sent = alice.send(bob, "twice")

        val results = (1..3).map { async { alice.abandon(bob, sent.id) } }.map { it.await() }
        assertEquals(listOf(AbandonStatus.ABANDONED, AbandonStatus.NOT_PENDING, AbandonStatus.NOT_PENDING), results.sorted())
        assertEquals(emptyList(), alice.pending(bob))
    }

    // Retry versus abandon

    @Test
    fun abandonWaitsForARetryInProgressWhichStillSendsTheMessage() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val m1 = alice.send(bob, "m1")
        val m2 = alice.send(bob, "m2")
        val originals = bob.inbox()

        val held = network.fake.holdNextSend(ALICE)
        val retry = async { alice.client.retryPendingMessages(BOB) }
        held.reached.await()
        val abandon = async { alice.abandon(bob, m2.id) }
        runCurrent()
        assertFalse(abandon.isCompleted, "serialized with the retry: never between its steps")

        held.release.complete(Unit)
        assertEquals(listOf(m1.id, m2.id), retry.await(), "the retry had already started, so it sends m2 too")
        assertEquals(AbandonStatus.ABANDONED, abandon.await())
        assertEquals(listOf(m1.id), alice.pending(bob))

        // The copy handed off before the abandon may still arrive; the session is consistent.
        val copies = originals + bob.inbox()
        assertEquals(listOf("m1", "m2", "m1", "m2"), copies.map { bob.receive(it).delivery().plaintext.decodeToString() })
        assertEquals(listOf(m1.id), alice.client.retryPendingMessages(BOB), "later retries skip m2")
        assertEquals(m1.id, bob.receiveOne().delivery().id)
    }

    @Test
    fun retryAfterTheAbandonNeverEncryptsTheMessage() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val m1 = alice.send(bob, "m1")
        val m2 = alice.send(bob, "m2")
        val m3 = alice.send(bob, "m3")
        bob.inbox()
        val sessionBefore = alice.sessionState(bob)

        assertEquals(AbandonStatus.ABANDONED, alice.abandon(bob, m2.id))
        assertContentEquals(sessionBefore, alice.sessionState(bob))
        assertEquals(listOf(m1.id, m3.id), alice.client.retryPendingMessages(BOB))
        assertEquals(listOf("m1", "m3"), bob.inbox().map { bob.receive(it).delivery().plaintext.decodeToString() })
    }

    @Test
    fun abandonDuringAnAcknowledgementOfAnotherMessageKeepsTheSessionConsistent() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val kept = alice.send(bob, "kept")
        val dropped = alice.send(bob, "dropped")
        val delivered = bob.inbox().map { bob.receive(it).delivery() }

        assertEquals(AbandonStatus.ABANDONED, alice.abandon(bob, dropped.id))
        delivered.forEach { bob.client.commitReceivedMessage(it) }
        val acks = alice.inbox().map { assertIs<ReceiveResult.Acknowledgement>(alice.receive(it)) }
        assertEquals(listOf(kept.id to true, dropped.id to false), acks.map { it.id to it.cleared })
        assertEquals(emptyList(), alice.pending(bob))
    }

    // Pagination

    @Test
    fun pagesFollowTheGlobalSequenceCursor() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val carol = device(CAROL)
        val sent = listOf(bob, carol, bob, bob, carol).mapIndexed { i, to -> alice.send(to, "m$i") }

        val first = alice.client.pendingMessages(limit = 2)
        assertEquals(sent.take(2).map { it.id }, first.messages.map { it.id })
        assertEquals(listOf(BOB, CAROL), first.messages.map { it.recipient })
        assertEquals(listOf("m0", "m1"), first.messages.map { it.plaintext.decodeToString() })
        assertEquals(first.messages.last().sequence, first.nextAfterSequence)
        val second = alice.client.pendingMessages(first.nextAfterSequence, 2)
        assertEquals(sent.subList(2, 4).map { it.id }, second.messages.map { it.id })
        val last = alice.client.pendingMessages(second.nextAfterSequence, 2)
        assertEquals(listOf(sent[4].id), last.messages.map { it.id })
        assertNull(last.nextAfterSequence)
        val sequences = (first.messages + second.messages + last.messages).map { it.sequence }
        assertEquals(sequences.sorted(), sequences)

        val toBob = alice.client.pendingMessages(first.nextAfterSequence, 2, BOB)
        assertEquals(listOf(sent[2].id, sent[3].id), toBob.messages.map { it.id }, "the recipient filter uses the global cursor")
        assertNull(toBob.nextAfterSequence, "no further message to Bob")
        assertEquals(5L, alice.client.pendingMessageCount())
        assertEquals(3L, alice.client.pendingMessageCount(BOB))
        assertEquals(2L, alice.client.pendingMessageCount(CAROL))
    }

    @Test
    fun aFullPageAtTheEndReportsNoFurtherPage() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        repeat(2) { alice.send(bob, "m$it") }
        assertNull(alice.client.pendingMessages(limit = 2).nextAfterSequence)
    }

    @Test
    fun pageBoundsAreValidated() = runTest {
        val alice = device(ALICE)
        assertFailsWith<IllegalArgumentException> { alice.client.pendingMessages(limit = 0) }
        assertFailsWith<IllegalArgumentException> { alice.client.pendingMessages(limit = -1) }
        assertFailsWith<IllegalArgumentException> { alice.client.pendingMessages(limit = PendingMessagePage.MAX_SIZE + 1) }
        assertFailsWith<IllegalArgumentException> { alice.client.pendingMessages(afterSequence = -1, limit = 1) }
        assertEquals(emptyList(), alice.client.pendingMessages(limit = PendingMessagePage.MAX_SIZE).messages)
    }

    @Test
    fun pagesAreBoundedByTheMaximumSize() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        repeat(PendingMessagePage.MAX_SIZE + 3) { alice.send(bob, "m$it") }

        val first = alice.client.pendingMessages(limit = PendingMessagePage.MAX_SIZE)
        assertEquals(PendingMessagePage.MAX_SIZE, first.messages.size)
        assertNotNull(first.nextAfterSequence)
        assertEquals(3, alice.client.pendingMessages(first.nextAfterSequence, PendingMessagePage.MAX_SIZE).messages.size)
        assertEquals(PendingMessagePage.MAX_SIZE + 3, alice.client.allPendingMessages().size)
    }

    @Test
    fun acknowledgingOrAbandoningBetweenPagesNeitherSkipsNorRepeats() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val sent = (1..8).map { alice.send(bob, "m$it") }
        val delivered = bob.inbox().map { bob.receive(it).delivery() }

        val first = alice.client.pendingMessages(limit = 3)
        assertEquals(sent.take(3).map { it.id }, first.messages.map { it.id })
        // Between pages: one returned message acknowledged, two later ones abandoned and acknowledged, one new send.
        bob.client.commitReceivedMessage(delivered[1])
        bob.client.commitReceivedMessage(delivered[4])
        alice.inbox().forEach { alice.receive(it) }
        alice.abandon(bob, sent[5].id)
        alice.abandon(bob, sent[6].id)
        val later = alice.send(bob, "later")

        val rest = alice.client.allPendingMessagesAfter(first.nextAfterSequence!!)
        assertEquals(listOf(sent[3].id, sent[7].id, later.id), rest.map { it.id })
        val seen = (first.messages + rest).map { it.id }
        assertEquals(seen.distinct(), seen, "no message twice")
    }

    private suspend fun SecureMessageClient.allPendingMessagesAfter(afterSequence: Long): List<PendingMessage> {
        val all = mutableListOf<PendingMessage>()
        var after: Long? = afterSequence
        while (after != null) {
            val page = pendingMessages(after, 2)
            all += page.messages
            after = page.nextAfterSequence
        }
        return all
    }
}
