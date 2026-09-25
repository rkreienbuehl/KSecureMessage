package dev.kreienbuehl.ksecuremessage.storage.server.sqldelight

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.DeviceRegistration
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.MessageId
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication
import dev.kreienbuehl.ksecuremessage.model.PublicOneTimePreKey
import dev.kreienbuehl.ksecuremessage.model.PublicSignedPreKey
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationException
import dev.kreienbuehl.ksecuremessage.storage.PreKeyPublicationException
import app.cash.sqldelight.db.SqlDriver
import kotlinx.coroutines.test.runTest
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/**
 * Server state across a real restart: the old driver is closed, a new driver
 * opens new connections on the same database file, and a new storage
 * instance is opened on it.
 */
class SqlDelightServerPersistenceTest {
    private val database = TempDatabase()
    private var driver: SqlDriver = database.driver()

    private val alice = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val bob = DeviceAddress(UserId("bob"), DeviceId("laptop"))
    private val t0 = Instant.fromEpochMilliseconds(1_767_225_600_000)

    private fun key(seed: Int) = ByteArray(32) { (seed * 7 + it).toByte() }

    private suspend fun storage() = SqlDelightServerStorage.open(driver)

    /** Closes the driver and opens the database file again with a new one. */
    private suspend fun restart(): SqlDelightServerStorage {
        driver.close()
        driver = database.driver()
        return storage()
    }

    @AfterTest
    fun cleanUp() = database.close()

    private fun publication(signedPreKeyId: Int, oneTimePreKeyIds: IntRange, seed: Int = 0) = PreKeyPublication(
        address = bob,
        identityKey = key(1),
        signedPreKey = PublicSignedPreKey(SignedPreKeyId(signedPreKeyId), key(100 + signedPreKeyId), key(200 + signedPreKeyId)),
        oneTimePreKeys = oneTimePreKeyIds.map { PublicOneTimePreKey(OneTimePreKeyId(it), key(300 + it + seed)) },
    )

    private fun envelope(sender: DeviceAddress, sequence: Int) = EncryptedEnvelope(
        id = MessageId("${sender.userId.value}#$sequence"),
        sender = sender,
        recipient = bob,
        protocolVersion = 1,
        payload = byteArrayOf(sequence.toByte(), 0x5a),
    )

    @Test
    fun registrationSurvivesRestartAndIsNeverReplaced() = runTest {
        assertTrue(storage().devices.register(DeviceRegistration(alice, key(1))))

        val restarted = restart()
        assertContentEquals(key(1), restarted.devices.registration(alice)?.publicKey)
        assertFalse(restarted.devices.register(DeviceRegistration(alice, key(1))), "identical retry after restart")
        assertFailsWith<DeviceRegistrationException.Conflict> { restarted.devices.register(DeviceRegistration(alice, key(2))) }
        assertContentEquals(key(1), restart().devices.registration(alice)?.publicKey)
    }

    @Test
    fun claimedNonceStaysClaimedAcrossRestartUntilPruned() = runTest {
        val nonce = ByteArray(16) { it.toByte() }
        assertTrue(storage().authenticationNonces.claim(alice, nonce, t0, pruneBefore = t0 - 5.minutes))

        val restarted = restart()
        assertFalse(restarted.authenticationNonces.claim(alice, nonce, t0 + 1.minutes, pruneBefore = t0 - 4.minutes), "replay after restart")
        assertFalse(restart().authenticationNonces.claim(alice, nonce, t0 + 5.minutes, pruneBefore = t0), "still inside retention")
        assertTrue(
            restart().authenticationNonces.claim(alice, nonce, t0 + 5.minutes, pruneBefore = t0 + 1.milliseconds),
            "pruned after retention, so accepted again",
        )
        assertFalse(restart().authenticationNonces.claim(alice, nonce, t0 + 5.minutes, pruneBefore = t0 + 1.milliseconds))
    }

    @Test
    fun preKeysSurviveRestart() = runTest {
        storage().preKeys.publish(publication(signedPreKeyId = 3, oneTimePreKeyIds = 10..12))

        val restarted = restart()
        assertEquals(3, restarted.preKeys.oneTimePreKeyCount(bob))
        assertFailsWith<PreKeyPublicationException.SignedPreKeyConflict> {
            restarted.preKeys.publish(publication(signedPreKeyId = 2, oneTimePreKeyIds = 0..0))
        }
        val bundle = assertNotNull(restarted.preKeys.consumePreKeyBundle(bob))
        assertContentEquals(key(1), bundle.identityKey)
        assertEquals(SignedPreKeyId(3), bundle.signedPreKey.id)
        assertContentEquals(key(203), bundle.signedPreKey.signature)
        assertEquals(OneTimePreKeyId(10), bundle.oneTimePreKey?.id)
        assertContentEquals(key(310), bundle.oneTimePreKey?.publicKey)
    }

    @Test
    fun consumedOneTimePreKeyTombstoneSurvivesRestart() = runTest {
        storage().preKeys.publish(publication(signedPreKeyId = 1, oneTimePreKeyIds = 42..43))
        assertEquals(OneTimePreKeyId(42), storage().preKeys.consumePreKeyBundle(bob)?.oneTimePreKey?.id)

        val restarted = restart()
        restarted.preKeys.publish(publication(signedPreKeyId = 1, oneTimePreKeyIds = 42..43))
        restarted.preKeys.publish(publication(signedPreKeyId = 1, oneTimePreKeyIds = 42..42, seed = 99))
        assertEquals(1, restarted.preKeys.oneTimePreKeyCount(bob), "#42 was ignored")

        val again = restart()
        assertEquals(OneTimePreKeyId(43), again.preKeys.consumePreKeyBundle(bob)?.oneTimePreKey?.id)
        assertEquals(null, again.preKeys.consumePreKeyBundle(bob)?.oneTimePreKey, "#42 never becomes available again")
    }

    @Test
    fun queuedEnvelopesSurviveRestartAndDrainedOnesStayGone() = runTest {
        val first = storage()
        repeat(3) { first.mailboxes.enqueue(envelope(alice, it)) }

        val drained = restart().mailboxes.drain(bob)
        assertEquals(listOf("alice#0", "alice#1", "alice#2"), drained.map { it.id.value })
        assertEquals(alice, drained.first().sender)
        assertEquals(1, drained.first().protocolVersion)
        assertContentEquals(byteArrayOf(2, 0x5a), drained.last().payload)

        assertEquals(emptyList(), restart().mailboxes.drain(bob), "drained rows remain gone")
    }

    @Test
    fun orderHoldsAcrossDrainsAndRestarts() = runTest {
        storage().mailboxes.enqueue(envelope(alice, 0))
        storage().mailboxes.enqueue(envelope(alice, 1))
        assertEquals(2, storage().mailboxes.drain(bob).size)

        // Sequences are never reused after a drain and a restart.
        val restarted = restart()
        restarted.mailboxes.enqueue(envelope(alice, 2))
        restarted.mailboxes.enqueue(envelope(alice, 3))
        restart().mailboxes.enqueue(envelope(alice, 4))
        assertEquals(listOf("alice#2", "alice#3", "alice#4"), restart().mailboxes.drain(bob).map { it.id.value })
    }
}
