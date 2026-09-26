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
import kotlinx.coroutines.test.runTest
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/**
 * A failure inside a repository operation, injected into the driver after a
 * statement ran, rolls back every write of that operation.
 */
class SqlDelightServerRollbackTest {
    private val database = TempDatabase()
    private val driver = TestDriver(database.driver())

    private val alice = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val bob = DeviceAddress(UserId("bob"), DeviceId("laptop"))
    private val t0 = Instant.fromEpochMilliseconds(1_767_225_600_000)

    private fun key(seed: Int) = ByteArray(32) { (seed * 7 + it).toByte() }

    private suspend fun storage() = SqlDelightServerStorage.open(driver)

    @AfterTest
    fun cleanUp() = database.close()

    private fun publication(signedPreKeyId: Int, oneTimePreKeyIds: IntRange) = PreKeyPublication(
        address = bob,
        identityKey = key(1),
        signedPreKey = PublicSignedPreKey(SignedPreKeyId(signedPreKeyId), key(100 + signedPreKeyId), key(200 + signedPreKeyId)),
        oneTimePreKeys = oneTimePreKeyIds.map { PublicOneTimePreKey(OneTimePreKeyId(it), key(300 + it)) },
    )

    private fun envelope(sequence: Int) =
        EncryptedEnvelope(MessageId("m$sequence"), alice, bob, payload = byteArrayOf(sequence.toByte()))

    @Test
    fun failedRegistrationStoresNothing() = runTest {
        val storage = storage()
        driver.failAfter("INSERT OR IGNORE INTO device_registration")
        assertFailsWith<InjectedFailure> { storage.devices.register(DeviceRegistration(alice, key(1)), t0) }

        assertNull(storage.devices.registration(alice))
        assertEquals(0, driver.count("SELECT count(*) FROM device_registration"))
        assertTrue(storage.devices.register(DeviceRegistration(alice, key(2)), t0), "the address is still free")
    }

    @Test
    fun failedNonceClaimNeitherPrunesNorClaims() = runTest {
        val storage = storage()
        val old = ByteArray(16) { 1 }
        val new = ByteArray(16) { 2 }
        assertTrue(storage.authenticationNonces.claim(alice, old, t0, pruneBefore = t0 - 5.minutes))

        driver.failAfter("INSERT OR IGNORE INTO authentication_nonce")
        assertFailsWith<InjectedFailure> {
            storage.authenticationNonces.claim(alice, new, t0 + 10.minutes, pruneBefore = t0 + 5.minutes)
        }

        assertEquals(1, driver.count("SELECT count(*) FROM authentication_nonce"), "the prune was rolled back too")
        assertFalse(storage.authenticationNonces.claim(alice, old, t0, pruneBefore = t0 - 5.minutes), "old nonce still claimed")
        assertTrue(storage.authenticationNonces.claim(alice, new, t0 + 10.minutes, pruneBefore = t0 - 5.minutes), "new nonce was not claimed")
    }

    @Test
    fun failedPublicationChangesNeitherSignedPreKeyNorOneTimePreKeys() = runTest {
        val storage = storage()
        storage.preKeys.publish(publication(signedPreKeyId = 0, oneTimePreKeyIds = 40..41))

        // The signed prekey update and the first new one-time prekey have run when the failure hits.
        driver.failAfter("INSERT INTO available_one_time_prekey")
        assertFailsWith<InjectedFailure> { storage.preKeys.publish(publication(signedPreKeyId = 1, oneTimePreKeyIds = 42..43)) }

        assertEquals(2, storage.preKeys.oneTimePreKeyCount(bob))
        val bundle = storage.preKeys.consumePreKeyBundle(bob)!!
        assertEquals(SignedPreKeyId(0), bundle.signedPreKey.id)
        assertContentEquals(key(100), bundle.signedPreKey.publicKey)
        assertEquals(OneTimePreKeyId(40), bundle.oneTimePreKey?.id)
    }

    @Test
    fun failedConsumptionKeepsTheOneTimePreKeyAvailable() = runTest {
        val storage = storage()
        storage.preKeys.publish(publication(signedPreKeyId = 0, oneTimePreKeyIds = 7..7))

        // Deleted from the inventory, then the tombstone insert fails.
        driver.failBefore("INSERT INTO consumed_one_time_prekey")
        assertFailsWith<InjectedFailure> { storage.preKeys.consumePreKeyBundle(bob) }

        assertEquals(1, storage.preKeys.oneTimePreKeyCount(bob))
        assertEquals(0, driver.count("SELECT count(*) FROM consumed_one_time_prekey"))
        assertEquals(OneTimePreKeyId(7), storage.preKeys.consumePreKeyBundle(bob)?.oneTimePreKey?.id)
        assertEquals(1, driver.count("SELECT count(*) FROM consumed_one_time_prekey"))
    }

    @Test
    fun failedEnqueueStoresNoMessage() = runTest {
        val storage = storage()
        driver.failAfter("INSERT INTO mailbox_message")
        assertFailsWith<InjectedFailure> { storage.mailboxes.enqueue(envelope(0)) }

        assertEquals(0, driver.count("SELECT count(*) FROM mailbox_message"))
        assertEquals(emptyList(), storage.mailboxes.drain(bob))
    }

    @Test
    fun failedDrainKeepsEveryMessage() = runTest {
        val storage = storage()
        repeat(3) { storage.mailboxes.enqueue(envelope(it)) }

        // Selected and deleted, but not committed.
        driver.failAfter("DELETE FROM mailbox_message")
        assertFailsWith<InjectedFailure> { storage.mailboxes.drain(bob) }

        assertEquals(3, driver.count("SELECT count(*) FROM mailbox_message"))
        assertEquals(listOf("m0", "m1", "m2"), storage.mailboxes.drain(bob).map { it.id.value })
    }
}
