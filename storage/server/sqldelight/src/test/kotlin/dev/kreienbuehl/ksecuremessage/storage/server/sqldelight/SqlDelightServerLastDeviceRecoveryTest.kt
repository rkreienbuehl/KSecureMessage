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
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryChallengeId
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryId
import dev.kreienbuehl.ksecuremessage.protocol.RequestNonce
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationException
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryChallengeIssue
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryChallengeRequest
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryKeyException
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryReplacement
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryReplacementResult.ALREADY_APPLIED
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryReplacementResult.CHALLENGE_INVALID
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryReplacementResult.REPLACED
import dev.kreienbuehl.ksecuremessage.storage.RotationReplacement
import dev.kreienbuehl.ksecuremessage.storage.RotationReplacementResult
import dev.kreienbuehl.ksecuremessage.storage.StoredLastDeviceRecoveryChallenge
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
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/**
 * Last-device recovery on persistent storage (docs/last-device-recovery.md):
 * recovery keys and challenges survive real restarts, a committed recovery
 * stays authoritative and retryable after a restart, a stale recovery stays
 * rejected, and a recovery that fails inside its transaction leaves the old
 * registration and the challenge in place.
 */
class SqlDelightServerLastDeviceRecoveryTest {
    private val database = TempDatabase()
    private var driver: SqlDriver = database.driver()

    private val phone = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val bob = DeviceAddress(UserId("bob"), DeviceId("phone"))
    private val t0 = Instant.fromEpochMilliseconds(1_767_225_600_000)

    private fun key(seed: Int) = ByteArray(32) { (seed * 7 + it).toByte() }
    private val recoveryKey = ByteArray(32) { (0xC0 + it).toByte() }

    @AfterTest
    fun cleanUp() = database.close()

    private suspend fun storage() = SqlDelightServerStorage.open(driver)

    private suspend fun restart(): SqlDelightServerStorage {
        driver.close()
        driver = database.driver()
        return storage()
    }

    private suspend fun registered(): SqlDelightServerStorage = storage().apply {
        devices.register(DeviceRegistration(phone, key(1)), t0)
        lastDeviceRecovery.registerRecoveryKey(phone.userId, recoveryKey, t0)
    }

    private suspend fun SqlDelightServerStorage.issue(seed: Int = 1, at: Instant = t0): StoredLastDeviceRecoveryChallenge =
        assertIs<LastDeviceRecoveryChallengeIssue.Issued>(
            lastDeviceRecovery.issueChallenge(
                LastDeviceRecoveryChallengeRequest(
                    phone, LastDeviceRecoveryChallengeId(ByteArray(16) { seed.toByte() }), ByteArray(32) { seed.toByte() }, at, at + 5.minutes,
                ),
            ),
        ).challenge

    private suspend fun SqlDelightServerStorage.recovery(challenge: StoredLastDeviceRecoveryChallenge, seed: Int, at: Instant = t0 + 1.minutes) =
        LastDeviceRecoveryReplacement(
            assertNotNull(devices.registrationState(phone)),
            recoveryKey,
            challenge.challenge.id,
            challenge.challenge.nonce,
            key(seed),
            LastDeviceRecoveryId(ByteArray(32) { seed.toByte() }),
            at,
        )

    private suspend fun SqlDelightServerStorage.assertKey(seed: Int, epoch: Long) {
        val state = assertNotNull(devices.registrationState(phone))
        assertContentEquals(key(seed), state.registration.publicKey)
        assertEquals(epoch, state.authEpoch)
    }

    @Test
    fun recoveryKeyAndChallengeSurviveRestart() = runTest {
        val challenge = registered().issue()
        val restarted = restart()
        assertContentEquals(recoveryKey, restarted.lastDeviceRecovery.recoveryKey(phone.userId))
        assertFailsWith<LastDeviceRecoveryKeyException.Conflict> {
            restarted.lastDeviceRecovery.registerRecoveryKey(phone.userId, key(9), t0)
        }
        val again = restarted.issue(2, at = t0 + 4.minutes)
        assertEquals(challenge.challenge.id, again.challenge.id, "the challenge is still valid after the restart")
        assertEquals(REPLACED, restarted.devices.replaceForLastDeviceRecovery(restarted.recovery(challenge, 2, at = t0 + 5.minutes)))
        restart().assertKey(2, epoch = 2)
    }

    @Test
    fun recoveredRegistrationSurvivesRestartAndRetriesAreRecognized() = runTest {
        val storage = registered()
        val recovery = storage.recovery(storage.issue(), 2)
        assertEquals(REPLACED, storage.devices.replaceForLastDeviceRecovery(recovery))

        val restarted = restart()
        restarted.assertKey(2, epoch = 2)
        val state = assertNotNull(restarted.devices.registrationState(phone))
        assertEquals(LastDeviceRecoveryId(ByteArray(32) { 2 }), state.lastDeviceRecoveryId)
        assertEquals(t0 + 1.minutes, state.authKeyInstalledAt)
        assertNull(restarted.lastDeviceRecovery.challenge(phone), "consumed")
        // K1 is gone: registering it conflicts; K2 is the registered key.
        assertFailsWith<DeviceRegistrationException.Conflict> { restarted.devices.register(DeviceRegistration(phone, key(1)), t0) }
        assertFalse(restarted.devices.register(DeviceRegistration(phone, key(2)), t0))
        assertEquals(ALREADY_APPLIED, restarted.devices.replaceForLastDeviceRecovery(recovery), "a lost response can be retried after a restart")
        restart().assertKey(2, epoch = 2)
    }

    @Test
    fun staleRecoveryStaysRejectedAcrossRestarts() = runTest {
        val storage = registered()
        val first = storage.recovery(storage.issue(), 2)
        assertEquals(REPLACED, storage.devices.replaceForLastDeviceRecovery(first))
        val second = restart()
        val rotation = RotationReplacement(
            assertNotNull(second.devices.registrationState(phone)), key(3), DeviceAuthenticationRotationId(ByteArray(32) { 3 }),
            RequestNonce(ByteArray(16) { 3 }), t0, t0 - 5.minutes, t0 + 2.minutes,
        )
        assertEquals(RotationReplacementResult.REPLACED, second.devices.replaceForRotation(rotation))
        val third = restart()
        assertEquals(CHALLENGE_INVALID, third.devices.replaceForLastDeviceRecovery(first))
        restart().assertKey(3, epoch = 3)
    }

    @Test
    fun recoveryAndRestartKeepPreKeysTombstonesMailboxAndNonces() = runTest {
        val storage = registered()
        val publication = PreKeyPublication(
            phone, key(10), PublicSignedPreKey(SignedPreKeyId(1), key(11), ByteArray(64) { 12 }),
            (1..3).map { PublicOneTimePreKey(OneTimePreKeyId(it), key(20 + it)) },
        )
        storage.preKeys.publish(publication)
        storage.preKeys.consumePreKeyBundle(phone)
        storage.mailboxes.enqueue(EncryptedEnvelope(MessageId("m1"), bob, phone, payload = byteArrayOf(1)))
        storage.mailboxes.enqueue(EncryptedEnvelope(MessageId("m2"), bob, phone, payload = byteArrayOf(2)))
        storage.authenticationNonces.claim(phone, ByteArray(16) { 7 }, t0, t0 - 5.minutes)
        val challenge = storage.issue()
        val before = driver.dump()

        assertEquals(REPLACED, storage.devices.replaceForLastDeviceRecovery(storage.recovery(challenge, 2)))
        val after = restart()
        val dump = driver.dump()
        val changed = listOf("device_registration", "last_device_recovery_challenge")
        assertEquals(before - changed, dump - changed, "only the registration and the challenge changed; no nonce was added")
        assertEquals(emptyList(), dump.getValue("last_device_recovery_challenge"))

        after.preKeys.publish(publication)
        assertEquals(2, after.preKeys.oneTimePreKeyCount(phone), "tombstone kept")
        assertEquals(listOf("m1", "m2"), after.mailboxes.drain(phone).map { it.id.value })
    }

    @Test
    fun failureInsideTheRecoveryTransactionKeepsTheOldRegistrationAndTheChallenge() = runTest {
        val testDriver = TestDriver(driver)
        registered().issue()
        val storage = SqlDelightServerStorage.open(testDriver)
        val challenge = assertNotNull(storage.lastDeviceRecovery.challenge(phone))
        val faults = listOf(
            "before the prune" to { testDriver.failBefore("DELETE FROM last_device_recovery_challenge WHERE expires_at") },
            "before the challenge consumption" to { testDriver.failBefore("DELETE FROM last_device_recovery_challenge WHERE user_id") },
            "after the challenge consumption" to { testDriver.failAfter("DELETE FROM last_device_recovery_challenge WHERE user_id") },
            "before the compare-and-set" to { testDriver.failBefore("UPDATE device_registration") },
            "after the compare-and-set" to { testDriver.failAfter("UPDATE device_registration") },
        )
        for (fault in faults) {
            fault.second()
            assertFailsWith<InjectedFailure>(fault.first) { storage.devices.replaceForLastDeviceRecovery(storage.recovery(challenge, 2)) }
            storage.assertKey(1, epoch = 1)
            assertNull(storage.devices.registrationState(phone)?.lastDeviceRecoveryId, fault.first)
            assertEquals(challenge.challenge.id, storage.lastDeviceRecovery.challenge(phone)?.challenge?.id, fault.first)
        }
        assertEquals(REPLACED, storage.devices.replaceForLastDeviceRecovery(storage.recovery(challenge, 2)))
        restart().assertKey(2, epoch = 2)
    }

    @Test
    fun failedChallengeIssueAndKeyRegistrationStoreNothing() = runTest {
        val testDriver = TestDriver(driver)
        storage().devices.register(DeviceRegistration(phone, key(1)), t0)
        val storage = SqlDelightServerStorage.open(testDriver)
        testDriver.failAfter("INSERT INTO last_device_recovery_key")
        assertFailsWith<InjectedFailure> { storage.lastDeviceRecovery.registerRecoveryKey(phone.userId, recoveryKey, t0) }
        assertNull(storage.lastDeviceRecovery.recoveryKey(phone.userId))
        storage.lastDeviceRecovery.registerRecoveryKey(phone.userId, recoveryKey, t0)

        storage.issue(1)
        testDriver.failAfter("INSERT INTO last_device_recovery_challenge")
        assertFailsWith<InjectedFailure> { storage.issue(2, at = t0 + 10.minutes) }
        assertEquals(LastDeviceRecoveryChallengeId(ByteArray(16) { 1 }), storage.lastDeviceRecovery.challenge(phone)?.challenge?.id, "the old challenge was not deleted")
    }
}
