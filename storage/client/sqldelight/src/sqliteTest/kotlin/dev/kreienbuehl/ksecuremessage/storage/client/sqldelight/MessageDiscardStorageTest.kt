package dev.kreienbuehl.ksecuremessage.storage.client.sqldelight

import app.cash.sqldelight.db.SqlDriver
import dev.kreienbuehl.ksecuremessage.client.CommitStatus
import dev.kreienbuehl.ksecuremessage.client.DiscardStatus
import dev.kreienbuehl.ksecuremessage.client.PreKeyConfiguration
import dev.kreienbuehl.ksecuremessage.client.ProcessedInboundRetentionPolicy
import dev.kreienbuehl.ksecuremessage.client.ReceiveResult
import dev.kreienbuehl.ksecuremessage.client.SecureMessageClient
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.InboundFinalization
import dev.kreienbuehl.ksecuremessage.model.MessageDiscardReason
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.ApplicationMessageDigest
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.storage.client.inmemory.InMemoryClientStorage
import dev.kreienbuehl.ksecuremessage.storage.encryption.SealedRecords
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageEncryptionException
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyProvider
import kotlinx.coroutines.async
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
private val SECRET = "received-and-then-discarded".encodeToByteArray()

/**
 * Milestone 21 explicit discard and pending pagination on SQLDelight storage
 * (docs/message-discard.md): discarded tombstones and their reason survive
 * restarts, keep no plaintext, reuse record type 12 for the digest, fail
 * closed when damaged, and schema version 13 databases migrate with every
 * processed row committed.
 */
class MessageDiscardStorageTest {
    private val database = TestDatabase()
    private val engine = KodiumProtocolEngine()
    private val network = TestRelay()
    private val clock = TestClock(Instant.fromEpochMilliseconds(1_767_225_600_000))
    private val config = PreKeyConfiguration(oneTimePreKeyTarget = 3)
    private val keys = MemoryKeyStore()
    private val provider: StorageKeyProvider = keys.provider("message-discard")
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

    private suspend fun receiveAll(bob: SecureMessageClient) = network.receive(BOB).map { assertIs<ReceiveResult.Delivery>(bob.decrypt(it)).message }

    private fun pendingRows(): Long = driver.longs("SELECT count(*) FROM pending_inbound_message").single()!!

    @Test
    fun pendingPaginationIsIdenticalAfterReopen() = runTest {
        start()
        val ids = (1..25).map { alice.send(BOB, "m$it".encodeToByteArray()).id }
        val delivered = receiveAll(bob())

        val pages = mutableListOf<List<Long>>()
        val seen = mutableListOf<String>()
        var after: Long? = null
        do {
            val page = bob().pendingReceivedMessages(after, 10)
            pages += page.messages.map { it.sequence }
            seen += page.messages.map { it.text() }
            after = page.nextAfterSequence
        } while (after != null)
        assertEquals(listOf(10, 10, 5), pages.map { it.size })
        assertEquals(delivered.map { it.sequence }, pages.flatten(), "order and sequences survive the restart")
        assertEquals((1..25).map { "m$it" }, seen)
        assertEquals(ids, bob().allPendingReceivedMessages().map { it.id })
        assertEquals(25L, bob().pendingReceivedMessageCount(ALICE))

        // Finalized between pages, across restarts: the cursor neither skips nor repeats.
        val first = bob().pendingReceivedMessages(limit = 10)
        bob().discardReceivedMessage(delivered[12], MessageDiscardReason.OTHER)
        bob().commitReceivedMessage(delivered[5])
        val second = bob().pendingReceivedMessages(first.nextAfterSequence, 10)
        assertEquals(delivered.subList(10, 21).map { it.sequence } - delivered[12].sequence, second.messages.map { it.sequence })
    }

    @Test
    fun discardSurvivesReopenAndIsAcknowledgedWithoutRedelivery() = runTest {
        start()
        val sent = alice.send(BOB, SECRET)
        val delivered = receiveAll(bob()).single()
        clock.now += 1.days
        val result = bob().discardReceivedMessage(delivered, MessageDiscardReason.UNSUPPORTED_CONTENT)
        assertEquals(DiscardStatus.DISCARDED, result.status)
        network.receive(ALICE) // the acknowledgement is lost

        assertEquals(0L, pendingRows(), "the plaintext row is gone")
        assertEquals(listOf(1L), driver.longs("SELECT finalization FROM processed_inbound_message"))
        assertEquals(listOf(1L), driver.longs("SELECT discard_reason FROM processed_inbound_message"))
        assertEquals(listOf(clock.now.toEpochMilliseconds()), driver.longs("SELECT committed_at FROM processed_inbound_message"))

        val tombstone = assertNotNull(reopen().processedInbound.get(ALICE, sent.id))
        assertEquals(InboundFinalization.DISCARDED, tombstone.finalization)
        assertEquals(MessageDiscardReason.UNSUPPORTED_CONTENT, tombstone.discardReason)
        assertEquals(clock.now, tombstone.finalizedAt)
        assertContentEquals(ApplicationMessageDigest.of(SECRET), tombstone.digest)

        assertEquals(listOf(sent.id), alice.retryPendingMessages(BOB))
        val again = assertIs<ReceiveResult.AlreadyDiscarded>(bob().decrypt(network.receive(BOB).single()))
        assertTrue(again.ackSent)
        assertEquals(emptyList(), bob().allPendingReceivedMessages(), "no plaintext redelivery")
        assertEquals(0L, pendingRows())
        assertTrue(assertIs<ReceiveResult.Acknowledgement>(alice.decrypt(network.receive(ALICE).single())).cleared)
        assertEquals(CommitStatus.ALREADY_DISCARDED, bob().commitReceivedMessage(ALICE, sent.id).status)
        assertEquals(listOf(1L), driver.longs("SELECT finalization FROM processed_inbound_message"), "still discarded")
    }

    @Test
    fun commitRacingADiscardOnOneDatabaseHasOneWinner() = runTest {
        start()
        val sent = alice.send(BOB, "race".encodeToByteArray())
        val delivered = receiveAll(bob()).single()
        val storage = reopen()
        // Two client instances of one application on the same storage.
        val first = SecureMessageClient(BOB, storage, engine, network, config, clock)
        val second = SecureMessageClient(BOB, storage, engine, network, config, clock)

        val commit = async { first.commitReceivedMessage(delivered) }
        val discard = async { second.discardReceivedMessage(delivered, MessageDiscardReason.OTHER) }
        val statuses = commit.await().status to discard.await().status
        assertTrue(
            statuses == (CommitStatus.COMMITTED to DiscardStatus.ALREADY_COMMITTED) ||
                statuses == (CommitStatus.ALREADY_DISCARDED to DiscardStatus.DISCARDED),
            "exactly one outcome wins: $statuses",
        )
        assertEquals(1, driver.longs("SELECT count(*) FROM processed_inbound_message").single()?.toInt())
        assertEquals(0L, pendingRows())
        val winner = assertNotNull(reopen().processedInbound.get(ALICE, sent.id)).finalization
        assertEquals(if (statuses.first == CommitStatus.COMMITTED) InboundFinalization.COMMITTED else InboundFinalization.DISCARDED, winner)
    }

    @Test
    fun everyReasonRoundTripsThroughTheDatabase() = runTest {
        start()
        MessageDiscardReason.entries.forEach { alice.send(BOB, it.name.encodeToByteArray()) }
        val delivered = receiveAll(bob())
        delivered.zip(MessageDiscardReason.entries).forEach { (message, reason) -> bob().discardReceivedMessage(message, reason) }
        val storage = reopen()
        delivered.zip(MessageDiscardReason.entries).forEach { (message, reason) ->
            assertEquals(reason, storage.processedInbound.get(ALICE, message.id)?.discardReason)
        }
        assertEquals(listOf(1L, 2L, 3L, 4L, 5L), driver.longs("SELECT discard_reason FROM processed_inbound_message ORDER BY discard_reason"))
    }

    @Test
    fun discardedDigestIsSealedAndRotatesWithTheStorageKey() = runTest {
        start()
        val sent = alice.send(BOB, SECRET)
        val delivered = receiveAll(bob()).single()
        bob().discardReceivedMessage(delivered, MessageDiscardReason.POLICY_REJECTED)
        val digest = driver.blob("SELECT sealed_digest FROM processed_inbound_message")
        assertContentEquals(SEALED_MAGIC, digest.copyOf(4))
        assertFalse(digest.toHex().contains(ApplicationMessageDigest.of(SECRET).toHex()), "no digest at rest")
        val metadata = driver.strings("SELECT committed_at || '|' || finalization || '|' || discard_reason FROM processed_inbound_message")

        val storage = reopen()
        storage.rotateStorageKey()
        completeStorageKeyRotation { storage.resumeStorageKeyRotation(1) }
        assertEquals(listOf(2), driver.blobs("SELECT sealed_digest FROM processed_inbound_message").map { SealedRecords.keyId(it).value })
        assertEquals(metadata, driver.strings("SELECT committed_at || '|' || finalization || '|' || discard_reason FROM processed_inbound_message"))
        val tombstone = assertNotNull(reopen().processedInbound.get(ALICE, sent.id))
        assertEquals(MessageDiscardReason.POLICY_REJECTED, tombstone.discardReason)
        assertContentEquals(ApplicationMessageDigest.of(SECRET), tombstone.digest)
    }

    @Test
    fun corruptedDiscardedDigestFailsClosedWithoutAcknowledgement() = runTest {
        start()
        val sent = alice.send(BOB, SECRET)
        val delivered = receiveAll(bob()).single()
        bob().discardReceivedMessage(delivered, MessageDiscardReason.OTHER)
        network.receive(ALICE)
        driver.exec("UPDATE processed_inbound_message SET sealed_digest = ?", driver.blob("SELECT sealed_digest FROM processed_inbound_message").flipped(30))

        alice.retryPendingMessages(BOB)
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { bob().decrypt(network.receive(BOB).single()) }
        assertEquals(0, network.waiting(ALICE), "not acknowledged blindly")
        assertTrue(reopen().processedInbound.isProcessed(ALICE, sent.id))
        assertEquals(0L, pendingRows())
    }

    @Test
    fun checkConstraintsTieTheReasonToTheOutcome() = runTest {
        start()
        alice.send(BOB, "committed".encodeToByteArray())
        val toCommit = receiveAll(bob()).single()
        bob().commitReceivedMessage(toCommit)
        alice.send(BOB, "discarded".encodeToByteArray())
        val toDiscard = receiveAll(bob()).single()
        bob().discardReceivedMessage(toDiscard, MessageDiscardReason.OTHER)
        val before = driver.dump()

        assertFailsWith<Exception> { driver.exec("UPDATE processed_inbound_message SET discard_reason = 1 WHERE finalization = 0") }
        assertFailsWith<Exception> { driver.exec("UPDATE processed_inbound_message SET discard_reason = NULL WHERE finalization = 1") }
        assertFailsWith<Exception> { driver.exec("UPDATE processed_inbound_message SET discard_reason = 6 WHERE finalization = 1") }
        assertFailsWith<Exception> { driver.exec("UPDATE processed_inbound_message SET finalization = 2") }
        assertEquals(before, driver.dump())
    }

    @Test
    fun unknownFinalizationOrReasonFailsClosed() = runTest {
        start()
        val sent = alice.send(BOB, SECRET)
        val delivered = receiveAll(bob()).single()
        bob().discardReceivedMessage(delivered, MessageDiscardReason.OTHER)
        network.receive(ALICE)

        // A damaged or foreign database without the CHECK constraints.
        fun rebuildWith(finalization: Long, reason: Long?) {
            driver.exec("DROP TABLE IF EXISTS processed_inbound_message_checked")
            driver.exec("ALTER TABLE processed_inbound_message RENAME TO processed_inbound_message_checked")
            driver.exec(
                "CREATE TABLE processed_inbound_message (sender_user_id TEXT NOT NULL, sender_device_id TEXT NOT NULL, " +
                    "message_id BLOB NOT NULL, committed_at INTEGER, sealed_digest BLOB, finalization INTEGER NOT NULL DEFAULT 0, " +
                    "discard_reason INTEGER, PRIMARY KEY (sender_user_id, sender_device_id, message_id))",
            )
            driver.exec(
                "INSERT INTO processed_inbound_message SELECT sender_user_id, sender_device_id, message_id, committed_at, sealed_digest, " +
                    "$finalization, ${reason ?: "NULL"} FROM processed_inbound_message_checked",
            )
            driver.exec("DROP TABLE processed_inbound_message_checked")
        }

        for ((finalization, reason) in listOf(2L to 1L, 1L to 9L, 1L to null, 0L to 1L)) {
            rebuildWith(finalization, reason)
            val storage = reopen()
            assertFailsWith<IllegalStateException>("finalization $finalization, reason $reason") { storage.processedInbound.get(ALICE, sent.id) }
            assertTrue(storage.processedInbound.isProcessed(ALICE, sent.id), "never treated as absent")
            alice.retryPendingMessages(BOB)
            assertFailsWith<IllegalStateException> { bob().decrypt(network.receive(BOB).single()) }
            assertEquals(0, network.waiting(ALICE), "not acknowledged")
            assertEquals(0L, pendingRows(), "not delivered again")
            assertFailsWith<IllegalStateException> { bob().discardReceivedMessage(ALICE, sent.id, MessageDiscardReason.OTHER) }
            assertFailsWith<IllegalStateException> { bob().commitReceivedMessage(ALICE, sent.id) }
        }
    }

    @Test
    fun discardedTombstonesPruneAndPendingRowsStay() = runTest {
        start()
        val discarded = alice.send(BOB, "discarded".encodeToByteArray()).id
        val delivered = receiveAll(bob()).single()
        bob().discardReceivedMessage(delivered, MessageDiscardReason.OTHER)
        alice.decrypt(network.receive(ALICE).single())
        alice.send(BOB, "pending".encodeToByteArray())
        receiveAll(bob())

        clock.now += 30.days
        assertEquals(1, bob().pruneProcessedMessages(ProcessedInboundRetentionPolicy(30.days)))
        assertFalse(reopen().processedInbound.isProcessed(ALICE, discarded))
        assertEquals(listOf("pending"), bob().allPendingReceivedMessages().map { it.text() })
        assertEquals(1L, pendingRows())
    }

    /**
     * Schema version 13 processed rows were all committed. Migration marks
     * every one committed without a reason and leaves everything else,
     * digests and times included, byte for byte unchanged.
     */
    @Test
    fun version13DatabaseMigratesProcessedRowsAsCommitted() = runTest {
        start()
        val committed = alice.send(BOB, "committed".encodeToByteArray()).id
        val first = receiveAll(bob()).single()
        bob().commitReceivedMessage(first)
        alice.decrypt(network.receive(ALICE).single())
        clock.now += 1.days
        val laterCommitted = alice.send(BOB, "later".encodeToByteArray()).id
        val later = receiveAll(bob()).single()
        bob().commitReceivedMessage(later)
        network.receive(ALICE) // lost acknowledgement: Alice keeps it pending
        alice.send(BOB, "pending".encodeToByteArray())
        receiveAll(bob())

        // Turn the database into the schema version 13 database it would have been.
        reopen()
        driver.dropVersion14Additions()
        driver.exec("PRAGMA user_version = 13")
        val fixture = TestDatabase()
        try {
            val fixtureDriver = fixture.open(Version13Schema)
            assertEquals(fixtureDriver.tables().associateWith { fixtureDriver.columns(it) }, driver.tables().associateWith { driver.columns(it) })
            assertEquals(
                fixtureDriver.strings("SELECT tbl_name || ':' || name FROM sqlite_master WHERE type = 'index' ORDER BY 1"),
                driver.strings("SELECT tbl_name || ':' || name FROM sqlite_master WHERE type = 'index' ORDER BY 1"),
            )
        } finally {
            fixture.close()
        }
        val before = driver.dump()

        val migrated = reopen()
        assertEquals(listOf(15L), driver.longs("PRAGMA user_version"))
        assertEquals(before.withCommittedFinalization(), driver.dump(), "no existing row changes")
        assertEquals(listOf(0L, 0L), driver.longs("SELECT finalization FROM processed_inbound_message"))
        assertEquals(listOf(null, null), driver.longs("SELECT discard_reason FROM processed_inbound_message"))
        for (id in listOf(committed, laterCommitted)) {
            val entry = assertNotNull(migrated.processedInbound.get(ALICE, id))
            assertEquals(InboundFinalization.COMMITTED, entry.finalization)
            assertNull(entry.discardReason)
        }
        // The migrated columns carry the same constraints as a new database.
        assertFailsWith<Exception> { driver.exec("UPDATE processed_inbound_message SET finalization = 1") }
        assertFailsWith<Exception> { driver.exec("UPDATE processed_inbound_message SET discard_reason = 1") }
        assertFailsWith<Exception> { driver.exec("UPDATE processed_inbound_message SET finalization = 2") }

        // Behavior is unchanged: the retry is acknowledged as committed, the pending one stays, retention is the same.
        assertEquals(listOf(laterCommitted, alice.pendingMessages(limit = 100, recipient = BOB).messages.last().id), alice.pendingMessages(limit = 100, recipient = BOB).messages.map { it.id })
        alice.retryPendingMessages(BOB)
        val results = network.receive(BOB).map { bob().decrypt(it) }
        assertIs<ReceiveResult.AlreadyCommitted>(results[0])
        assertEquals("pending", assertIs<ReceiveResult.Delivery>(results[1]).message.text())
        assertEquals(listOf("pending"), bob().allPendingReceivedMessages().map { it.text() })
        clock.now += 29.days
        assertEquals(1, bob().pruneProcessedMessages(ProcessedInboundRetentionPolicy(30.days)), "only the older entry")
        assertFalse(reopen().processedInbound.isProcessed(ALICE, committed))
        assertTrue(reopen().processedInbound.isProcessed(ALICE, laterCommitted))
    }
}
