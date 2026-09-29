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
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationRotationId
import dev.kreienbuehl.ksecuremessage.protocol.RequestNonce
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationException
import dev.kreienbuehl.ksecuremessage.storage.RotationReplacement
import dev.kreienbuehl.ksecuremessage.storage.RotationReplacementResult.ALREADY_APPLIED
import dev.kreienbuehl.ksecuremessage.storage.RotationReplacementResult.CONFLICT
import dev.kreienbuehl.ksecuremessage.storage.RotationReplacementResult.REPLACED
import dev.kreienbuehl.ksecuremessage.storage.RotationReplacementResult.REPLAY
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
 * Routine device authentication key rotation on persistent storage
 * (docs/device-authentication-rotation.md): the rotated registration survives
 * real restarts, a stale K1 -> K2 stays rejected after K2 -> K3 across
 * restarts, and a rotation that fails inside its transaction leaves the old
 * registration authoritative.
 */
class SqlDelightServerRotationTest {
    private val database = TempDatabase()
    private var driver: SqlDriver = database.driver()

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

    private suspend fun SqlDelightServerStorage.rotation(seed: Int) = RotationReplacement(
        assertNotNull(devices.registrationState(phone)),
        key(seed),
        DeviceAuthenticationRotationId(ByteArray(32) { seed.toByte() }),
        RequestNonce(ByteArray(16) { seed.toByte() }),
        t0,
        t0 - 5.minutes,
        t0,
    )

    private suspend fun registered(): SqlDelightServerStorage = storage().apply {
        devices.register(DeviceRegistration(phone, key(1)), t0)
    }

    private suspend fun SqlDelightServerStorage.assertKey(seed: Int, epoch: Long) {
        val state = assertNotNull(devices.registrationState(phone))
        assertContentEquals(key(seed), state.registration.publicKey)
        assertEquals(epoch, state.authEpoch)
    }

    @Test
    fun rotatedRegistrationSurvivesRestart() = runTest {
        val storage = registered()
        val rotation = storage.rotation(2)
        assertEquals(REPLACED, storage.devices.replaceForRotation(rotation))

        val restarted = restart()
        restarted.assertKey(2, epoch = 2)
        assertEquals(DeviceAuthenticationRotationId(ByteArray(32) { 2 }), restarted.devices.registrationState(phone)?.rotationId)
        assertNull(restarted.devices.registrationState(phone)?.recoveryId)
        // K1 is gone: registering it conflicts; K2 is the registered key.
        assertFailsWith<DeviceRegistrationException.Conflict> { restarted.devices.register(DeviceRegistration(phone, key(1)), t0) }
        assertFalse(restarted.devices.register(DeviceRegistration(phone, key(2)), t0))
        assertEquals(ALREADY_APPLIED, restarted.devices.replaceForRotation(rotation), "a lost response can be retried after a restart")
        restart().assertKey(2, epoch = 2)
    }

    @Test
    fun staleRotationStaysRejectedAcrossRestarts() = runTest {
        val first = registered().let { it.rotation(2).also { r -> assertEquals(REPLACED, it.devices.replaceForRotation(r)) } }
        val second = restart()
        assertEquals(REPLACED, second.devices.replaceForRotation(second.rotation(3)))
        val third = restart()
        assertEquals(CONFLICT, third.devices.replaceForRotation(first))
        assertEquals(REPLAY, third.devices.replaceForRotation(third.rotation(2)), "the K1 -> K2 nonce is still claimed")
        restart().assertKey(3, epoch = 3)
    }

    @Test
    fun rotationAndRestartKeepPreKeysTombstonesAndMailbox() = runTest {
        val storage = registered()
        val publication = PreKeyPublication(
            phone, key(10), PublicSignedPreKey(SignedPreKeyId(1), key(11), ByteArray(64) { 12 }),
            (1..3).map { PublicOneTimePreKey(OneTimePreKeyId(it), key(20 + it)) },
        )
        storage.preKeys.publish(publication)
        storage.preKeys.consumePreKeyBundle(phone)
        storage.mailboxes.enqueue(EncryptedEnvelope(MessageId("m1"), bob, phone, payload = byteArrayOf(1)))
        storage.mailboxes.enqueue(EncryptedEnvelope(MessageId("m2"), bob, phone, payload = byteArrayOf(2)))
        val before = driver.dump()

        assertEquals(REPLACED, storage.devices.replaceForRotation(storage.rotation(2)))
        val after = restart()
        val dump = driver.dump()
        assertEquals(
            before - "device_registration" - "authentication_nonce" - "authentication_nonce_watermark",
            dump - "device_registration" - "authentication_nonce" - "authentication_nonce_watermark",
        )
        assertEquals(1, dump.getValue("authentication_nonce").size, "only the rotation's nonce was added")

        after.preKeys.publish(publication)
        assertEquals(2, after.preKeys.oneTimePreKeyCount(phone), "tombstone kept")
        assertEquals(listOf("m1", "m2"), after.mailboxes.drain(phone).map { it.id.value })
    }

    @Test
    fun failureInsideTheRotationTransactionKeepsTheOldRegistration() = runTest {
        val testDriver = TestDriver(driver)
        registered()
        val storage = SqlDelightServerStorage.open(testDriver)
        val faults = listOf(
            "before the nonce claim" to { testDriver.failBefore("INSERT OR IGNORE INTO authentication_nonce") },
            "after the nonce claim" to { testDriver.failAfter("INSERT OR IGNORE INTO authentication_nonce") },
            "before the compare-and-set" to { testDriver.failBefore("UPDATE device_registration") },
            "after the compare-and-set" to { testDriver.failAfter("UPDATE device_registration") },
        )
        for ((index, fault) in faults.withIndex()) {
            fault.second()
            assertFailsWith<InjectedFailure>(fault.first) { storage.devices.replaceForRotation(storage.rotation(2)) }
            storage.assertKey(1, epoch = 1)
            assertNull(storage.devices.registrationState(phone)?.rotationId, fault.first)
            assertTrue(storage.authenticationNonces.claim(phone, ByteArray(16) { (90 + index).toByte() }, t0, t0 - 5.minutes), "storage still usable")
        }
        // The nonce of the failed attempts was rolled back too: the same rotation still works.
        assertEquals(REPLACED, storage.devices.replaceForRotation(storage.rotation(2)))
        restart().assertKey(2, epoch = 2)
    }
}
