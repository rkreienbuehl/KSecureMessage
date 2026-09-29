package dev.kreienbuehl.ksecuremessage.storage.server.sqldelight

import app.cash.sqldelight.db.SqlDriver
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
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecoveryId
import dev.kreienbuehl.ksecuremessage.protocol.RequestNonce
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationException
import dev.kreienbuehl.ksecuremessage.storage.RecoveryReplacement
import dev.kreienbuehl.ksecuremessage.storage.RecoveryReplacementResult.ALREADY_APPLIED
import dev.kreienbuehl.ksecuremessage.storage.RecoveryReplacementResult.CONFLICT
import dev.kreienbuehl.ksecuremessage.storage.RecoveryReplacementResult.REPLACED
import dev.kreienbuehl.ksecuremessage.storage.RecoveryReplacementResult.REPLAY
import kotlinx.coroutines.test.runTest
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/**
 * Device recovery on persistent storage (docs/device-recovery.md): the
 * recovered registration survives real restarts, stale recoveries stay
 * rejected across restarts, and a recovery that fails inside its transaction
 * leaves the old registration authoritative.
 */
class SqlDelightServerRecoveryTest {
    private val database = TempDatabase()
    private var driver: SqlDriver = database.driver()

    private val laptop = DeviceAddress(UserId("alice"), DeviceId("laptop"))
    private val phone = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val bob = DeviceAddress(UserId("bob"), DeviceId("phone"))
    private val t0 = Instant.fromEpochMilliseconds(1_767_225_600_000)

    private fun key(seed: Int) = ByteArray(32) { (seed * 7 + it).toByte() }

    @AfterTest
    fun cleanUp() = database.close()

    private suspend fun storage() = SqlDelightServerStorage.open(driver)

    private suspend fun restart(): SqlDelightServerStorage {
        driver.close()
        driver = database.driver()
        return storage()
    }

    private suspend fun SqlDelightServerStorage.replacement(seed: Int) = RecoveryReplacement(
        assertNotNull(devices.registrationState(laptop)),
        assertNotNull(devices.registrationState(phone)),
        key(seed),
        DeviceRecoveryId(ByteArray(32) { seed.toByte() }),
        RequestNonce(ByteArray(16) { seed.toByte() }),
        t0,
        t0 - 5.minutes,
        t0,
    )

    private suspend fun registered(): SqlDelightServerStorage = storage().apply {
        devices.register(DeviceRegistration(laptop, key(1)), t0)
        devices.register(DeviceRegistration(phone, key(100)), t0)
    }

    private suspend fun SqlDelightServerStorage.assertKey(seed: Int, epoch: Long) {
        val state = assertNotNull(devices.registrationState(laptop))
        assertContentEquals(key(seed), state.registration.publicKey)
        assertEquals(epoch, state.authEpoch)
    }

    @Test
    fun recoveredRegistrationSurvivesRestart() = runTest {
        val storage = registered()
        val replacement = storage.replacement(2)
        assertEquals(REPLACED, storage.devices.replaceForRecovery(replacement))

        val restarted = restart()
        restarted.assertKey(2, epoch = 2)
        assertEquals(DeviceRecoveryId(ByteArray(32) { 2 }), restarted.devices.registrationState(laptop)?.recoveryId)
        assertFailsWith<DeviceRegistrationException.Conflict> { restarted.devices.register(DeviceRegistration(laptop, key(1)), t0) }
        assertEquals(ALREADY_APPLIED, restarted.devices.replaceForRecovery(replacement), "a lost response can be retried after a restart")
        restart().assertKey(2, epoch = 2)
    }

    @Test
    fun staleRecoveryStaysRejectedAcrossRestarts() = runTest {
        val first = registered().let { it.replacement(2).also { r -> assertEquals(REPLACED, it.devices.replaceForRecovery(r)) } }
        val second = restart()
        assertEquals(REPLACED, second.devices.replaceForRecovery(second.replacement(3)))
        val third = restart()
        assertEquals(CONFLICT, third.devices.replaceForRecovery(first))
        assertEquals(REPLAY, third.devices.replaceForRecovery(third.replacement(2)), "the K1 -> K2 nonce is still claimed")
        restart().assertKey(3, epoch = 3)
    }

    @Test
    fun recoveryAndRestartKeepPreKeysTombstonesAndMailbox() = runTest {
        val storage = registered()
        val publication = PreKeyPublication(
            laptop, key(10), PublicSignedPreKey(SignedPreKeyId(1), key(11), ByteArray(64) { 12 }),
            (1..3).map { PublicOneTimePreKey(OneTimePreKeyId(it), key(20 + it)) },
        )
        storage.preKeys.publish(publication)
        storage.preKeys.consumePreKeyBundle(laptop)
        storage.mailboxes.enqueue(EncryptedEnvelope(MessageId("m1"), bob, laptop, payload = byteArrayOf(1)))
        val before = driver.dump()

        assertEquals(REPLACED, storage.devices.replaceForRecovery(storage.replacement(2)))
        val after = restart()
        val dump = driver.dump()
        assertEquals(
            before - "device_registration" - "authentication_nonce" - "authentication_nonce_watermark",
            dump - "device_registration" - "authentication_nonce" - "authentication_nonce_watermark",
        )
        assertEquals(1, dump.getValue("authentication_nonce").size, "only the recovery's nonce was added")

        after.preKeys.publish(publication)
        assertEquals(2, after.preKeys.oneTimePreKeyCount(laptop), "tombstone kept")
        assertEquals(listOf("m1"), after.mailboxes.drain(laptop).map { it.id.value })
    }

    @Test
    fun failureInsideTheRecoveryTransactionKeepsTheOldRegistration() = runTest {
        val testDriver = TestDriver(driver)
        registered()
        val storage = SqlDelightServerStorage.open(testDriver)
        for ((index, statement) in listOf("INSERT OR IGNORE INTO authentication_nonce", "UPDATE device_registration").withIndex()) {
            testDriver.failAfter(statement)
            assertFailsWith<InjectedFailure>(statement) { storage.devices.replaceForRecovery(storage.replacement(2)) }
            storage.assertKey(1, epoch = 1)
            assertNull(storage.devices.registrationState(laptop)?.recoveryId)
            assertTrue(storage.authenticationNonces.claim(laptop, ByteArray(16) { (90 + index).toByte() }, t0, t0 - 5.minutes), "storage still usable")
        }
        // The nonce of the failed attempts was rolled back too: the same recovery still works.
        assertEquals(REPLACED, storage.devices.replaceForRecovery(storage.replacement(2)))
        restart().assertKey(2, epoch = 2)
    }

    @Test
    fun nonceClaimOfTheFailedRecoveryIsRolledBack() = runTest {
        val testDriver = TestDriver(driver)
        registered()
        val storage = SqlDelightServerStorage.open(testDriver)
        testDriver.failAfter("UPDATE device_registration")
        assertFailsWith<InjectedFailure> { storage.devices.replaceForRecovery(storage.replacement(2)) }
        assertTrue(storage.authenticationNonces.claim(laptop, ByteArray(16) { 2 }, t0, t0 - 5.minutes), "not claimed")
        assertFalse(storage.authenticationNonces.claim(laptop, ByteArray(16) { 2 }, t0, t0 - 5.minutes))
    }
}
