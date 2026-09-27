package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.LogicalMessageId
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
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.nanoseconds

/**
 * Milestone 20 application commit boundary (docs/application-delivery.md):
 * received messages stay pending until the application commits them, are
 * delivered again until then, and are acknowledged only after the commit.
 */
class ApplicationDeliveryTest {
    private val network = FlakyNetwork()
    private val clock = ManualClock()

    private suspend fun device(address: DeviceAddress) = ReliableDevice(address, network, clock = clock).start()

    private suspend fun ReliableDevice.pendingReceived() = client.allPendingReceivedMessages()

    // Delivery and commit

    @Test
    fun deliveryIsPendingAndUnacknowledgedUntilTheCommit() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val sent = alice.send(bob, "hello")

        val delivered = bob.receiveOne().delivery()
        assertEquals(sent.id, delivered.id)
        assertEquals(clock.now, delivered.receivedAt)
        assertEquals(emptyList(), alice.inbox(), "no acknowledgement before the commit")
        assertEquals(listOf(sent.id), alice.pending(bob), "the sender keeps it pending")
        assertTrue(bob.isPendingInbound(alice, sent.id))
        assertFalse(bob.isProcessed(alice, sent.id))

        val pending = bob.pendingReceived().single()
        assertEquals(sent.id, pending.id)
        assertEquals(delivered.sequence, pending.sequence)
        assertEquals("hello", pending.plaintext.decodeToString())

        clock.advanceBy(5.milliseconds)
        val commit = bob.client.commitReceivedMessage(pending)
        assertEquals(CommitStatus.COMMITTED, commit.status)
        assertTrue(commit.ackSent)
        assertEquals(emptyList(), bob.pendingReceived())
        val processed = assertNotNull(bob.storage.processedInbound.get(ALICE, sent.id))
        assertEquals(clock.now, processed.finalizedAt)
        assertContentEquals(ApplicationMessageDigest.of("hello".encodeToByteArray()), processed.digest)

        assertTrue(assertIs<ReceiveResult.Acknowledgement>(alice.receiveOne()).cleared)
        assertEquals(emptyList(), alice.pending(bob))
    }

    @Test
    fun retryBeforeTheCommitDeliversTheSameMessageAgainWithoutAcknowledgement() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val sent = alice.send(bob, "again")
        val first = bob.receiveOne().delivery()

        clock.advanceBy(1.days)
        alice.client.retryPendingMessages(BOB)
        val second = bob.receiveOne().delivery()
        assertEquals(first.id, second.id)
        assertEquals(first.sequence, second.sequence)
        assertEquals(first.receivedAt, second.receivedAt, "the first acceptance stays authoritative")
        assertEquals("again", second.plaintext.decodeToString())
        assertEquals(1, bob.pendingReceived().size, "stored once")
        assertEquals(emptyList(), alice.inbox(), "not acknowledged")
        assertEquals(listOf(sent.id), alice.pending(bob))

        assertTrue(bob.client.commitReceivedMessage(second).ackSent)
        assertTrue(assertIs<ReceiveResult.Acknowledgement>(alice.receiveOne()).cleared)
    }

    @Test
    fun retryAfterTheCommitIsAcknowledgedAndNotDeliveredAgain() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val sent = alice.send(bob, "once")
        network.failingSenders += BOB
        assertFalse(bob.commit(bob.receiveOne()).ackSent)
        network.failingSenders -= BOB

        alice.client.retryPendingMessages(BOB)
        val duplicate = assertIs<ReceiveResult.AlreadyCommitted>(bob.receiveOne())
        assertEquals(sent.id, duplicate.id)
        assertTrue(duplicate.ackSent)
        assertEquals(emptyList(), bob.pendingReceived())
        assertTrue(assertIs<ReceiveResult.Acknowledgement>(alice.receiveOne()).cleared)
    }

    @Test
    fun commitIsIdempotentAndAcknowledgesAgain() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val sent = alice.send(bob, "twice")
        val delivered = bob.receiveOne().delivery()

        assertEquals(CommitStatus.COMMITTED, bob.client.commitReceivedMessage(delivered).status)
        clock.advanceBy(1.days)
        val again = bob.client.commitReceivedMessage(ALICE, sent.id)
        assertEquals(CommitStatus.ALREADY_COMMITTED, again.status)
        assertTrue(again.ackSent)
        assertEquals(clock.now - 1.days, bob.storage.processedInbound.get(ALICE, sent.id)?.finalizedAt, "not written again")

        val acks = alice.inbox().map { assertIs<ReceiveResult.Acknowledgement>(alice.receive(it)) }
        assertEquals(listOf(true, false), acks.map { it.cleared })
    }

    @Test
    fun commitOfAnUnknownMessageFailsAndChangesNothing() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        alice.send(bob, "hello")
        bob.receiveOne()
        val unknown = LogicalMessageId.random()

        val error = assertFailsWith<SecureMessageClientException.ReceivedMessageNotPending> { bob.client.commitReceivedMessage(ALICE, unknown) }
        assertEquals(unknown, error.messageId)
        assertFalse(bob.isProcessed(alice, unknown))
        assertFailsWith<SecureMessageClientException.ReceivedMessageNotPending> { bob.client.commitReceivedMessage(CAROL, unknown) }
        assertEquals(1, bob.pendingReceived().size)
        assertEquals(emptyList(), alice.inbox())
    }

    @Test
    fun commitIsScopedToTheSender() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val sent = alice.send(bob, "hello")
        bob.receiveOne()
        assertFailsWith<SecureMessageClientException.ReceivedMessageNotPending> { bob.client.commitReceivedMessage(CAROL, sent.id) }
        assertTrue(bob.isPendingInbound(alice, sent.id))
    }

    // Enumeration

    @Test
    fun pendingMessagesAreListedInAcceptanceOrderPerSenderAndAsCopies() = runTest {
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

        val all = bob.pendingReceived()
        assertEquals(listOf("a1", "c1", "a2"), all.map { it.plaintext.decodeToString() })
        assertEquals(all.map { it.sequence }.sorted(), all.map { it.sequence })
        assertEquals(listOf("a1", "a2"), bob.client.allPendingReceivedMessages(ALICE).map { it.plaintext.decodeToString() })
        assertEquals(listOf("c1"), bob.client.allPendingReceivedMessages(CAROL).map { it.plaintext.decodeToString() })

        all[0].plaintext.fill(0)
        assertEquals("a1", bob.pendingReceived()[0].plaintext.decodeToString(), "returned plaintext is a copy")

        bob.client.commitReceivedMessage(all[1])
        assertEquals(listOf("a1", "a2"), bob.pendingReceived().map { it.plaintext.decodeToString() })
        alice.send(bob, "a3")
        val a3 = bob.receiveOne().delivery()
        assertTrue(a3.sequence > all.maxOf { it.sequence }, "sequence numbers are not reused")
    }

    @Test
    fun enumerationNeedsAnInitializedClient() = runTest {
        val client = ReliableDevice(ALICE, network).client
        assertFailsWith<SecureMessageClientException.NotInitialized> { client.allPendingReceivedMessages() }
        assertFailsWith<SecureMessageClientException.NotInitialized> { client.commitReceivedMessage(BOB, LogicalMessageId.random()) }
        assertFailsWith<SecureMessageClientException.NotInitialized> {
            client.pruneProcessedMessages(ProcessedInboundRetentionPolicy(1.days))
        }
    }

    // Crash windows

    @Test
    fun uncommittedMessageIsDeliveredAgainAfterRestart() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val ids = listOf("m1", "m2").map { alice.send(bob, it).id }
        bob.inbox().forEach { bob.receive(it) }

        // The application crashed before applying either message.
        bob.restart()
        bob.client.initialize()
        val redelivered = bob.pendingReceived()
        assertEquals(ids, redelivered.map { it.id })
        assertEquals(listOf("m1", "m2"), redelivered.map { it.plaintext.decodeToString() })
        assertEquals(emptyList(), alice.inbox())

        redelivered.forEach { bob.client.commitReceivedMessage(it) }
        alice.inbox().forEach { assertTrue(assertIs<ReceiveResult.Acknowledgement>(alice.receive(it)).cleared) }
        assertEquals(emptyList(), alice.pending(bob))
    }

    /**
     * The full recovery path, with an application that applies messages
     * idempotently by (sender, logical ID): nothing is lost and nothing is
     * applied twice.
     */
    @Test
    fun endToEndRecoveryWithAnIdempotentApplication() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val applied = mutableListOf<String>()
        val appliedKeys = mutableSetOf<Pair<DeviceAddress, LogicalMessageId>>()
        fun apply(message: ReceivedMessage) {
            if (appliedKeys.add(message.sender to message.id)) applied += message.plaintext.decodeToString()
        }

        val m1 = alice.send(bob, "M1").id
        val delivery = bob.receiveOne().delivery()
        assertEquals(m1, delivery.id)
        // Bob crashes before applying M1.
        bob.restart()
        bob.client.initialize()
        val pending = bob.pendingReceived().single()
        apply(pending)
        // The application committed its own transaction; the acknowledgement is lost.
        network.failingSenders += BOB
        assertFalse(bob.client.commitReceivedMessage(pending).ackSent)
        network.failingSenders -= BOB
        bob.restart()

        assertEquals(listOf(m1), alice.pending(bob))
        alice.client.retryPendingMessages(BOB)
        val retried = bob.receiveOne()
        assertIs<ReceiveResult.AlreadyCommitted>(retried)
        assertTrue(assertIs<ReceiveResult.Acknowledgement>(alice.receiveOne()).cleared)
        assertEquals(emptyList(), alice.pending(bob))
        bob.pendingReceived().forEach { apply(it) }
        assertEquals(listOf("M1"), applied)
    }

    /**
     * The gap the library cannot close: the application applied the message
     * but crashed before the library commit. The message comes again, so the
     * application must deduplicate by (sender, logical ID).
     */
    @Test
    fun crashBetweenApplicationCommitAndLibraryCommitDeliversAgain() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val sent = alice.send(bob, "side effect")
        val first = bob.receiveOne().delivery()
        // The application applied it here, then crashed.
        bob.restart()
        alice.client.retryPendingMessages(BOB)
        val again = bob.receiveOne().delivery()
        assertEquals(first.sender to first.id, again.sender to again.id, "same idempotency key")
        assertEquals(sent.id, bob.pendingReceived().single().id)
    }

    // Same logical ID, different body

    @Test
    fun differentBodyForAPendingIdIsRejectedAndChangesNothing() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val id = LogicalMessageId.random()
        alice.sendFrame(bob, SecurePayload.ApplicationMessage(id, "original".encodeToByteArray()))
        bob.receiveOne()
        val session = assertNotNull(bob.storage.sessions.load(ALICE)).state

        alice.sendFrame(bob, SecurePayload.ApplicationMessage(id, "substitute".encodeToByteArray()))
        val error = assertFailsWith<SecureMessageClientException.LogicalMessageConflict> { bob.receiveOne() }
        assertEquals(ALICE, error.sender)
        assertEquals(id, error.messageId)
        assertContentEquals(session, bob.storage.sessions.load(ALICE)?.state, "ratchet step rolled back")
        assertEquals("original", bob.pendingReceived().single().plaintext.decodeToString())
        assertFalse(bob.isProcessed(alice, id))
        assertEquals(emptyList(), alice.inbox(), "not acknowledged")

        // The same body is still a redelivery, and the session keeps working.
        alice.sendFrame(bob, SecurePayload.ApplicationMessage(id, "original".encodeToByteArray()))
        assertEquals("original", bob.receiveOne().text())
        assertEquals(1, bob.pendingReceived().size)
    }

    @Test
    fun differentBodyForACommittedIdIsRejectedAndNotAcknowledged() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val id = LogicalMessageId.random()
        alice.sendFrame(bob, SecurePayload.ApplicationMessage(id, "original".encodeToByteArray()))
        bob.commit(bob.receiveOne())
        alice.receiveOne()
        val processed = assertNotNull(bob.storage.processedInbound.get(ALICE, id))

        alice.sendFrame(bob, SecurePayload.ApplicationMessage(id, "substitute".encodeToByteArray()))
        assertFailsWith<SecureMessageClientException.LogicalMessageConflict> { bob.receiveOne() }
        assertEquals(emptyList(), alice.inbox(), "not acknowledged")
        assertEquals(emptyList(), bob.pendingReceived())
        assertContentEquals(processed.digest, bob.storage.processedInbound.get(ALICE, id)?.digest)

        alice.sendFrame(bob, SecurePayload.ApplicationMessage(id, "original".encodeToByteArray()))
        assertTrue(assertIs<ReceiveResult.AlreadyCommitted>(bob.receiveOne()).ackSent)
    }

    // Concurrency

    @Test
    fun concurrentCopiesOfOneMessageAreStoredOnce() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val sent = alice.send(bob, "race")
        alice.client.retryPendingMessages(BOB)
        val envelopes = bob.inbox()
        assertEquals(2, envelopes.size)

        val results = envelopes.map { async { bob.receive(it) } }.awaitAll()
        assertEquals(listOf(sent.id, sent.id), results.map { it.delivery().id })
        assertEquals(1, results.map { it.delivery().sequence }.toSet().size)
        assertEquals(1, bob.pendingReceived().size)
        assertEquals(emptyList(), alice.inbox())
    }

    @Test
    fun concurrentCommitsCommitOnce() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        alice.send(bob, "commit race")
        val delivered = bob.receiveOne().delivery()

        val results = List(2) { async { bob.client.commitReceivedMessage(delivered) } }.awaitAll()
        assertEquals(setOf(CommitStatus.COMMITTED, CommitStatus.ALREADY_COMMITTED), results.map { it.status }.toSet())
        assertEquals(emptyList(), bob.pendingReceived())
        val acks = alice.inbox().map { assertIs<ReceiveResult.Acknowledgement>(alice.receive(it)) }
        assertEquals(1, acks.count { it.cleared })
    }

    @Test
    fun commitRacingARetryNeverLosesOrDuplicatesTheMessage() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val sent = alice.send(bob, "retry race")
        val delivered = bob.receiveOne().delivery()
        alice.client.retryPendingMessages(BOB)
        val retry = bob.inbox().single()

        val commit = async { bob.client.commitReceivedMessage(delivered) }
        val received = async { bob.receive(retry) }
        assertEquals(CommitStatus.COMMITTED, commit.await().status)
        when (val result = received.await()) {
            is ReceiveResult.Delivery -> assertEquals("retry race", result.message.plaintext.decodeToString())
            is ReceiveResult.AlreadyCommitted -> assertEquals(sent.id, result.id)
            is ReceiveResult.AlreadyDiscarded -> error("never discarded")
            is ReceiveResult.Acknowledgement -> error("not an acknowledgement")
        }
        assertEquals(emptyList(), bob.pendingReceived())
        assertTrue(bob.isProcessed(alice, sent.id))
        alice.inbox().forEach { alice.receive(it) }
        assertEquals(emptyList(), alice.pending(bob))
    }

    // Retention of processed IDs

    @Test
    fun pruningRemovesEntriesExactlyAtTheirMaximumAge() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val old = alice.send(bob, "old").id
        bob.acceptOne()
        clock.advanceBy(10.days)
        val young = alice.send(bob, "young").id
        bob.acceptOne()
        val uncommitted = alice.send(bob, "uncommitted").id
        bob.receiveOne()
        val policy = ProcessedInboundRetentionPolicy(30.days)

        clock.advanceBy(20.days - 1.milliseconds)
        assertEquals(0, bob.client.pruneProcessedMessages(policy), "age just below the maximum")
        assertTrue(bob.isProcessed(alice, old))
        clock.advanceBy(1.milliseconds)
        assertEquals(1, bob.client.pruneProcessedMessages(policy), "age equal to the maximum")
        assertFalse(bob.isProcessed(alice, old))
        assertTrue(bob.isProcessed(alice, young))
        assertEquals(0, bob.client.pruneProcessedMessages(policy))

        clock.advanceBy(365.days)
        assertEquals(1, bob.client.pruneProcessedMessages(policy))
        assertEquals(listOf(uncommitted), bob.pendingReceived().map { it.id }, "pending messages are never pruned")
    }

    @Test
    fun infiniteRetentionAndABackwardsClockPruneNothing() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val id = alice.send(bob, "kept").id
        bob.acceptOne()
        clock.advanceBy(10_000.days)
        assertEquals(0, bob.client.pruneProcessedMessages(ProcessedInboundRetentionPolicy(Duration.INFINITE)))
        clock.now -= 20_000.days
        assertEquals(0, bob.client.pruneProcessedMessages(ProcessedInboundRetentionPolicy(1.milliseconds)))
        assertTrue(bob.isProcessed(alice, id))
    }

    @Test
    fun subMillisecondMaxAgeRoundsUp() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        alice.send(bob, "now")
        bob.acceptOne()
        val policy = ProcessedInboundRetentionPolicy(1.milliseconds + 1.nanoseconds)
        clock.advanceBy(1.milliseconds)
        assertEquals(0, bob.client.pruneProcessedMessages(policy))
        clock.advanceBy(1.milliseconds)
        assertEquals(1, bob.client.pruneProcessedMessages(policy))
    }

    @Test
    fun retentionPolicyNeedsAPositiveAge() {
        assertFailsWith<IllegalArgumentException> { ProcessedInboundRetentionPolicy(Duration.ZERO) }
        assertFailsWith<IllegalArgumentException> { ProcessedInboundRetentionPolicy((-1).days) }
    }

    /**
     * Once pruned, an old logical ID is no longer recognized: the retention
     * bounds reliability deduplication, not cryptographic replay protection.
     */
    @Test
    fun aPrunedIdIsAcceptedAsNewAgain() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val id = LogicalMessageId.random()
        alice.sendFrame(bob, SecurePayload.ApplicationMessage(id, "first".encodeToByteArray()))
        bob.commit(bob.receiveOne())
        clock.advanceBy(31.days)
        assertEquals(1, bob.client.pruneProcessedMessages(ProcessedInboundRetentionPolicy(30.days)))

        alice.sendFrame(bob, SecurePayload.ApplicationMessage(id, "second".encodeToByteArray()))
        assertEquals("second", bob.receiveOne().text())
    }
}
