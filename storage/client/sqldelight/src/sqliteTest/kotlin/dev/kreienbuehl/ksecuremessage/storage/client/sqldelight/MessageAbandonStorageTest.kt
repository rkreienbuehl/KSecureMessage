package dev.kreienbuehl.ksecuremessage.storage.client.sqldelight

import app.cash.sqldelight.db.SqlDriver
import dev.kreienbuehl.ksecuremessage.client.AbandonStatus
import dev.kreienbuehl.ksecuremessage.client.PendingMessage
import dev.kreienbuehl.ksecuremessage.client.PreKeyConfiguration
import dev.kreienbuehl.ksecuremessage.client.ReceiveResult
import dev.kreienbuehl.ksecuremessage.client.SecureMessageClient
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.storage.client.inmemory.InMemoryClientStorage
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageEncryptionException
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyProvider
import kotlinx.coroutines.async
import kotlinx.coroutines.test.runTest
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Instant

private val ALICE = DeviceAddress(UserId("alice"), DeviceId("phone"))
private val BOB = DeviceAddress(UserId("bob"), DeviceId("laptop"))
private val SECRET = "sent-and-then-abandoned".encodeToByteArray()

/**
 * Milestone 22 pending outbound pagination and explicit abandon on SQLDelight
 * storage (docs/outbound-message-lifecycle.md): Bob, on the database, is the
 * sender. An abandon survives restarts, never rewinds the sequence, removes
 * exactly one row, and pages open only the records they return; schema
 * version 14 databases migrate by gaining the recipient index only.
 */
class MessageAbandonStorageTest {
    private val database = TestDatabase()
    private val engine = KodiumProtocolEngine()
    private val network = TestRelay()
    private val clock = TestClock(Instant.fromEpochMilliseconds(1_767_225_600_000))
    private val config = PreKeyConfiguration(oneTimePreKeyTarget = 3)
    private val keys = MemoryKeyStore()
    private val provider: StorageKeyProvider = keys.provider("message-abandon")
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

    private suspend fun start() {
        alice.initialize()
        network.publish(alice)
        val bob = bob()
        bob.initialize()
        network.publish(bob)
    }

    private fun pendingRows(): Long = driver.longs("SELECT count(*) FROM pending_outbound_message").single()!!

    private suspend fun SecureMessageClient.allPending(): List<PendingMessage> {
        val all = mutableListOf<PendingMessage>()
        var after: Long? = null
        do {
            val page = pendingMessages(after, 10)
            all += page.messages
            after = page.nextAfterSequence
        } while (after != null)
        return all
    }

    @Test
    fun abandonSurvivesReopen() = runTest {
        start()
        val sent = bob().send(ALICE, SECRET)
        val kept = bob().send(ALICE, "kept".encodeToByteArray())
        network.receive(ALICE)

        assertEquals(AbandonStatus.ABANDONED, bob().abandonPendingMessage(ALICE, sent.id))
        assertEquals(1L, pendingRows(), "exactly one row removed")
        assertEquals(AbandonStatus.NOT_PENDING, bob().abandonPendingMessage(ALICE, sent.id))

        val reopened = reopen()
        assertNull(reopened.pendingOutbound.get(ALICE, sent.id))
        assertNotNull(reopened.pendingOutbound.get(ALICE, kept.id))
        assertEquals(listOf(kept.id), bob().allPending().map { it.id })
        assertEquals(1L, bob().pendingMessageCount(ALICE))
        assertEquals(listOf(kept.id), bob().retryPendingMessages(ALICE))
        assertEquals(1, network.receive(ALICE).size)
    }

    @Test
    fun sequenceStaysMonotonicAfterAbandonAndReopen() = runTest {
        start()
        val first = bob().send(ALICE, "m1".encodeToByteArray())
        val second = bob().send(ALICE, "m2".encodeToByteArray())
        val sequences = bob().allPending().map { it.sequence }
        assertEquals(2, sequences.size)
        bob().abandonPendingMessage(ALICE, first.id)
        bob().abandonPendingMessage(ALICE, second.id)
        assertEquals(0L, pendingRows())

        bob().send(ALICE, "m3".encodeToByteArray())
        val third = bob().allPending().single()
        assertTrue(third.sequence > sequences.max(), "never reused, also after a restart")
    }

    @Test
    fun pendingPaginationIsIdenticalAfterReopen() = runTest {
        start()
        val ids = (1..25).map { bob().send(ALICE, "m$it".encodeToByteArray()).id }
        network.receive(ALICE)

        val pages = mutableListOf<List<Long>>()
        val seen = mutableListOf<String>()
        var after: Long? = null
        do {
            val page = bob().pendingMessages(after, 10)
            pages += page.messages.map { it.sequence }
            seen += page.messages.map { it.plaintext.decodeToString() }
            after = page.nextAfterSequence
        } while (after != null)
        assertEquals(listOf(10, 10, 5), pages.map { it.size })
        assertEquals(pages.flatten().sorted(), pages.flatten(), "ascending")
        assertEquals((1..25).map { "m$it" }, seen)
        assertEquals(ids, bob().allPending().map { it.id })
        assertEquals(25L, bob().pendingMessageCount())

        // Abandoned between pages, across restarts: the cursor neither skips nor repeats.
        val first = bob().pendingMessages(limit = 10)
        bob().abandonPendingMessage(ALICE, ids[12])
        bob().abandonPendingMessage(ALICE, ids[3])
        val second = bob().pendingMessages(first.nextAfterSequence, 10, ALICE)
        assertEquals(ids.subList(10, 21) - ids[12], second.messages.map { it.id })
    }

    @Test
    fun pagesOpenOnlyTheRecordsTheyReturn() = runTest {
        start()
        repeat(3) { bob().send(ALICE, "m$it".encodeToByteArray()) }
        reopen()
        val last = driver.longs("SELECT max(sequence) FROM pending_outbound_message").single()!!
        val sealed = driver.blob("SELECT sealed_frame FROM pending_outbound_message WHERE sequence = $last")
        driver.exec("UPDATE pending_outbound_message SET sealed_frame = ? WHERE sequence = $last", sealed.flipped(30))

        val storage = reopen()
        assertEquals(2, storage.pendingOutbound.page(0, 2).size)
        assertEquals(2, storage.pendingOutbound.page(0, 2, ALICE).size)
        assertEquals(3L, storage.pendingOutbound.count(), "counting opens nothing")
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { storage.pendingOutbound.page(0, 3) }
        // A new client reopens the database (and closes the storage above).
        assertEquals(1, bob().pendingMessages(limit = 1).messages.size)
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { bob().pendingMessages(limit = 2) }
    }

    @Test
    fun abandonDeletesOnlyThatRowWithoutOpeningIt() = runTest {
        start()
        val sent = bob().send(ALICE, SECRET)
        val kept = bob().send(ALICE, "kept".encodeToByteArray())
        reopen()
        val before = driver.dump()
        // A damaged record can still be abandoned: removal never opens it.
        val sealed = driver.blob("SELECT sealed_frame FROM pending_outbound_message ORDER BY sequence LIMIT 1")
        driver.exec("UPDATE pending_outbound_message SET sealed_frame = ? WHERE message_id = ?", sealed.flipped(30), sent.id.toByteArray())

        assertEquals(AbandonStatus.ABANDONED, bob().abandonPendingMessage(ALICE, sent.id))
        val after = driver.dump()
        assertEquals(before - "pending_outbound_message", after - "pending_outbound_message", "nothing else changes")
        assertEquals(1, after.getValue("pending_outbound_message").size)
        assertEquals(listOf(kept.id), bob().allPending().map { it.id })
    }

    @Test
    fun acknowledgementRacingAnAbandonOnOneDatabaseHasOneWinner() = runTest {
        start()
        val sent = bob().send(ALICE, "race".encodeToByteArray())
        val delivered = assertIs<ReceiveResult.Delivery>(alice.decrypt(network.receive(ALICE).single())).message
        assertTrue(alice.commitReceivedMessage(delivered).ackSent)
        val ack = network.receive(BOB).single()
        val storage = reopen()
        // Two client instances of one application on the same storage.
        val first = SecureMessageClient(BOB, storage, engine, network, config, clock)
        val second = SecureMessageClient(BOB, storage, engine, network, config, clock)

        val acknowledged = async { assertIs<ReceiveResult.Acknowledgement>(first.decrypt(ack)).cleared }
        val abandoned = async { second.abandonPendingMessage(ALICE, sent.id) == AbandonStatus.ABANDONED }
        assertTrue(acknowledged.await() != abandoned.await(), "exactly one removal wins")
        assertEquals(0L, pendingRows())
        assertFalse(reopen().processedInbound.isProcessed(ALICE, sent.id))
    }

    /**
     * Schema version 14 had no recipient index on pending outbound messages.
     * Migration adds it and changes no row.
     */
    @Test
    fun version14DatabaseGainsTheRecipientIndexAndKeepsEveryRow() = runTest {
        start()
        val ids = (1..3).map { bob().send(ALICE, "m$it".encodeToByteArray()).id }

        reopen()
        driver.dropVersion15Additions()
        driver.exec("PRAGMA user_version = 14")
        val fixture = TestDatabase()
        try {
            val fixtureDriver = fixture.open(Version14Schema)
            assertEquals(fixtureDriver.tables().associateWith { fixtureDriver.columns(it) }, driver.tables().associateWith { driver.columns(it) })
            assertEquals(
                fixtureDriver.strings("SELECT tbl_name || ':' || name FROM sqlite_master WHERE type = 'index' ORDER BY 1"),
                driver.strings("SELECT tbl_name || ':' || name FROM sqlite_master WHERE type = 'index' ORDER BY 1"),
            )
        } finally {
            fixture.close()
        }
        val before = driver.dump()

        reopen()
        assertEquals(listOf(15L), driver.longs("PRAGMA user_version"))
        assertEquals(before, driver.dump(), "no row changes")
        assertTrue("pending_outbound_message_recipient" in driver.strings("SELECT name FROM sqlite_master WHERE type = 'index'"))
        assertEquals(ids, bob().pendingMessages(limit = 10, recipient = ALICE).messages.map { it.id })
        assertEquals(AbandonStatus.ABANDONED, bob().abandonPendingMessage(ALICE, ids[1]))
        assertEquals(listOf(ids[0], ids[2]), bob().allPending().map { it.id })
    }
}
