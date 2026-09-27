package dev.kreienbuehl.ksecuremessage.storage.client.sqldelight

import app.cash.sqldelight.db.SqlDriver
import dev.kreienbuehl.ksecuremessage.client.CommitStatus
import dev.kreienbuehl.ksecuremessage.client.PreKeyConfiguration
import dev.kreienbuehl.ksecuremessage.client.ProcessedInboundRetentionPolicy
import dev.kreienbuehl.ksecuremessage.client.ReceiveResult
import dev.kreienbuehl.ksecuremessage.client.SecureMessageClient
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.LogicalMessageId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.ApplicationMessageDigest
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.storage.client.inmemory.InMemoryClientStorage
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageEncryptionException
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyProvider
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
import kotlin.time.Duration.Companion.days
import kotlin.time.Instant

private val ALICE = DeviceAddress(UserId("alice"), DeviceId("phone"))
private val BOB = DeviceAddress(UserId("bob"), DeviceId("laptop"))
private val SECRET = "received-and-not-yet-committed".encodeToByteArray()

/**
 * Milestone 20 application delivery on SQLDelight storage
 * (docs/application-delivery.md): pending received messages and processed
 * entries survive restarts, are sealed at rest (record types 11 and 12), fail
 * closed when damaged, survive storage key rotation, and schema version 12
 * databases migrate with their processed IDs kept.
 */
class ApplicationDeliveryStorageTest {
    private val database = TestDatabase()
    private val engine = KodiumProtocolEngine()
    private val network = TestRelay()
    private val clock = TestClock(Instant.fromEpochMilliseconds(1_767_225_600_000))
    private val config = PreKeyConfiguration(oneTimePreKeyTarget = 3)
    private val keys = MemoryKeyStore()
    private val provider: StorageKeyProvider = keys.provider("application-delivery")
    private lateinit var driver: SqlDriver
    private val alice = SecureMessageClient(ALICE, InMemoryClientStorage(), engine, network, config, clock)

    @AfterTest
    fun close() = database.close()

    private suspend fun reopen(): SqlDelightClientStorage {
        database.closeOpenDrivers()
        driver = database.open()
        return SqlDelightClientStorage.open(driver, provider)
    }

    /** Bob on a freshly reopened database, like an application restart. */
    private suspend fun bob(): SecureMessageClient = SecureMessageClient(BOB, reopen(), engine, network, config, clock)

    private suspend fun start(): SecureMessageClient {
        alice.initialize()
        network.publish(alice)
        val bob = bob()
        bob.initialize()
        network.publish(bob)
        return bob
    }

    private fun pendingRows(): Long = driver.longs("SELECT count(*) FROM pending_inbound_message").single()!!

    @Test
    fun uncommittedMessageIsDeliveredAgainAfterReopen() = runTest {
        start()
        val ids = listOf("m1", "m2").map { alice.send(BOB, it.encodeToByteArray()).id }
        val first = bob()
        val delivered = network.receive(BOB).map { first.decrypt(it) }.map { assertIs<ReceiveResult.Delivery>(it).message }
        assertEquals(0, network.waiting(ALICE), "no acknowledgement before the commit")

        // Crash before the application applied anything.
        val restarted = bob()
        restarted.initialize()
        val pending = restarted.allPendingReceivedMessages()
        assertEquals(ids, pending.map { it.id })
        assertEquals(delivered.map { it.sequence }, pending.map { it.sequence }, "order survives the restart")
        assertEquals(delivered.map { it.receivedAt }, pending.map { it.receivedAt })
        assertEquals(listOf("m1", "m2"), pending.map { it.text() })

        clock.now += 1.days
        assertEquals(CommitStatus.COMMITTED, restarted.commitReceivedMessage(pending[0]).status)
        val afterCommit = bob()
        assertEquals(listOf(ids[1]), afterCommit.allPendingReceivedMessages().map { it.id })
        assertEquals(listOf(1L), driver.longs("SELECT count(*) FROM processed_inbound_message"))
        assertEquals(listOf(clock.now.toEpochMilliseconds()), driver.longs("SELECT committed_at FROM processed_inbound_message"))
        assertTrue(assertIs<ReceiveResult.Acknowledgement>(alice.decrypt(network.receive(ALICE).single())).cleared)
        assertEquals(listOf(ids[1]), alice.pendingMessages(BOB).map { it.id })
    }

    @Test
    fun committedMessageIsAcknowledgedAgainButNotDeliveredAgainAfterReopen() = runTest {
        start()
        val sent = alice.send(BOB, "lost ack".encodeToByteArray())
        bob().accept(network.receive(BOB).single())
        network.receive(ALICE) // the acknowledgement is lost

        val processed = assertNotNull(reopen().processedInbound.get(ALICE, sent.id))
        assertContentEquals(ApplicationMessageDigest.of("lost ack".encodeToByteArray()), processed.digest)
        assertEquals(listOf(sent.id), alice.retryPendingMessages(BOB))
        val again = assertIs<ReceiveResult.AlreadyCommitted>(bob().decrypt(network.receive(BOB).single()))
        assertTrue(again.ackSent)
        assertEquals(emptyList(), bob().allPendingReceivedMessages())
        assertTrue(assertIs<ReceiveResult.Acknowledgement>(alice.decrypt(network.receive(ALICE).single())).cleared)
        assertEquals(emptyList(), alice.pendingMessages(BOB))
    }

    @Test
    fun pendingPlaintextAndDigestAreSealedAtRest() = runTest {
        start()
        val sent = alice.send(BOB, SECRET)
        bob().decrypt(network.receive(BOB).single())
        val sealed = driver.blob("SELECT sealed_frame FROM pending_inbound_message")
        assertContentEquals(SEALED_MAGIC, sealed.copyOf(4))
        assertFalse(sealed.toHex().contains(SECRET.toHex()), "no plaintext at rest")

        bob().commitReceivedMessage(ALICE, sent.id)
        val digest = driver.blob("SELECT sealed_digest FROM processed_inbound_message")
        assertContentEquals(SEALED_MAGIC, digest.copyOf(4))
        assertFalse(digest.toHex().contains(ApplicationMessageDigest.of(SECRET).toHex()), "no digest at rest")
        assertEquals(0L, pendingRows())
    }

    @Test
    fun corruptedPendingRecordFailsClosedAndStaysPending() = runTest {
        start()
        val sent = alice.send(BOB, SECRET)
        bob().decrypt(network.receive(BOB).single())
        driver.exec("UPDATE pending_inbound_message SET sealed_frame = ?", driver.blob("SELECT sealed_frame FROM pending_inbound_message").flipped(30))
        val before = driver.dump()

        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { bob().allPendingReceivedMessages() }
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { bob().commitReceivedMessage(ALICE, sent.id) }
        // A retry of the message must compare against the damaged record: it fails instead of storing a new one.
        alice.retryPendingMessages(BOB)
        val retry = network.receive(BOB).single()
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { bob().decrypt(retry) }
        assertEquals(before, driver.dump(), "nothing deleted, nothing processed")
        assertEquals(0, network.waiting(ALICE), "nothing acknowledged")
    }

    @Test
    fun pendingRecordMovedToAnotherRowFailsAuthentication() = runTest {
        start()
        alice.send(BOB, "one".encodeToByteArray())
        alice.send(BOB, "two".encodeToByteArray())
        network.receive(BOB).forEach { bob().decrypt(it) }
        val records = driver.blobs("SELECT sealed_frame FROM pending_inbound_message ORDER BY sequence")
        driver.exec("UPDATE pending_inbound_message SET sealed_frame = ? WHERE sequence = (SELECT min(sequence) FROM pending_inbound_message)", records[1])
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { bob().allPendingReceivedMessages() }
    }

    @Test
    fun corruptedProcessedDigestFailsClosed() = runTest {
        start()
        val sent = alice.send(BOB, "committed".encodeToByteArray())
        bob().accept(network.receive(BOB).single())
        network.receive(ALICE)
        driver.exec("UPDATE processed_inbound_message SET sealed_digest = ?", driver.blob("SELECT sealed_digest FROM processed_inbound_message").flipped(30))

        alice.retryPendingMessages(BOB)
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { bob().decrypt(network.receive(BOB).single()) }
        assertEquals(0, network.waiting(ALICE), "not acknowledged blindly")
        assertTrue(reopen().processedInbound.isProcessed(ALICE, sent.id))
    }

    @Test
    fun pendingAndProcessedRecordsSurviveStorageKeyRotation() = runTest {
        start()
        val committed = alice.send(BOB, "committed".encodeToByteArray()).id
        bob().accept(network.receive(BOB).single())
        alice.decrypt(network.receive(ALICE).single())
        alice.send(BOB, SECRET)
        bob().decrypt(network.receive(BOB).single())
        val committedAt = driver.longs("SELECT committed_at FROM processed_inbound_message")
        val sequence = driver.longs("SELECT sequence FROM pending_inbound_message")

        val storage = reopen()
        storage.rotateStorageKey()
        completeStorageKeyRotation { storage.resumeStorageKeyRotation(1) }
        assertEquals(listOf(2), driver.blobs("SELECT sealed_frame FROM pending_inbound_message").map { dev.kreienbuehl.ksecuremessage.storage.encryption.SealedRecords.keyId(it).value })
        assertEquals(listOf(2), driver.blobs("SELECT sealed_digest FROM processed_inbound_message").map { dev.kreienbuehl.ksecuremessage.storage.encryption.SealedRecords.keyId(it).value })

        val restarted = bob()
        assertContentEquals(SECRET, restarted.allPendingReceivedMessages().single().plaintext)
        assertEquals(sequence, driver.longs("SELECT sequence FROM pending_inbound_message"))
        assertEquals(committedAt, driver.longs("SELECT committed_at FROM processed_inbound_message"), "metadata unchanged")
        assertContentEquals(ApplicationMessageDigest.of("committed".encodeToByteArray()), reopen().processedInbound.get(ALICE, committed)?.digest)
    }

    @Test
    fun pruningPersistsAndNeverTouchesPendingMessages() = runTest {
        start()
        val old = alice.send(BOB, "old".encodeToByteArray()).id
        bob().accept(network.receive(BOB).single())
        alice.decrypt(network.receive(ALICE).single())
        alice.send(BOB, "uncommitted".encodeToByteArray())
        bob().decrypt(network.receive(BOB).single())

        clock.now += 30.days
        assertEquals(1, bob().pruneProcessedMessages(ProcessedInboundRetentionPolicy(30.days)))
        assertFalse(reopen().processedInbound.isProcessed(ALICE, old))
        assertEquals(listOf("uncommitted"), bob().allPendingReceivedMessages().map { it.text() })
    }

    /**
     * Schema version 12 had processed IDs without commit time or digest. They
     * are kept, stamped once by initialize() with its clock, and count as
     * committed; without a digest a different body cannot be detected.
     */
    @Test
    fun version12DatabaseKeepsProcessedIdsAndStampsThemOnce() = runTest {
        start()
        val legacy = alice.send(BOB, "before milestone 20".encodeToByteArray()).id
        bob().accept(network.receive(BOB).single())
        network.receive(ALICE) // the acknowledgement is lost: Alice keeps it pending
        // Turn the database into the schema version 12 database it would have been.
        driver.dropVersion13Additions()
        driver.exec("PRAGMA user_version = 12")
        val fixture = TestDatabase()
        try {
            val fixtureDriver = fixture.open(Version12Schema)
            assertEquals(fixtureDriver.tables().associateWith { fixtureDriver.columns(it) }, driver.tables().associateWith { driver.columns(it) })
        } finally {
            fixture.close()
        }
        val before = driver.dump()

        val migrated = reopen()
        assertEquals(listOf(14L), driver.longs("PRAGMA user_version"))
        assertEquals(before.withLegacyProcessedMessages(), driver.dump(), "no existing row changes")
        val entry = assertNotNull(migrated.processedInbound.get(ALICE, legacy))
        assertNull(entry.digest)
        assertNull(entry.finalizedAt)
        // Unstamped entries are never pruned.
        assertEquals(0, migrated.processedInbound.pruneFinalizedAtOrBefore(Instant.fromEpochMilliseconds(Long.MAX_VALUE)))

        val stampedAt = clock.now
        bob().initialize()
        clock.now += 1.days
        bob().initialize()
        assertEquals(listOf(stampedAt.toEpochMilliseconds()), driver.longs("SELECT committed_at FROM processed_inbound_message"), "stamped once")

        // A legacy ID counts as committed: a retry is acknowledged, not delivered again.
        assertEquals(listOf(legacy), alice.retryPendingMessages(BOB))
        val retried = assertIs<ReceiveResult.AlreadyCommitted>(bob().decrypt(network.receive(BOB).single()))
        assertTrue(retried.ackSent)
        assertEquals(emptyList(), bob().allPendingReceivedMessages())
        assertTrue(assertIs<ReceiveResult.Acknowledgement>(alice.decrypt(network.receive(ALICE).single())).cleared)
        assertEquals(CommitStatus.ALREADY_COMMITTED, bob().commitReceivedMessage(ALICE, legacy).status)
    }

    @Test
    fun unknownCommitChangesNothing() = runTest {
        start()
        val before = driver.dump()
        assertFailsWith<dev.kreienbuehl.ksecuremessage.client.SecureMessageClientException.ReceivedMessageNotPending> {
            bob().commitReceivedMessage(ALICE, LogicalMessageId.random())
        }
        assertEquals(before, driver.dump())
    }
}
