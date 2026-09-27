package dev.kreienbuehl.ksecuremessage.storage.server.sqldelight

import app.cash.sqldelight.db.SqlDriver
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.DeviceRegistration
import dev.kreienbuehl.ksecuremessage.model.RecoveryKeyResetId
import dev.kreienbuehl.ksecuremessage.model.RecoveryKeyResetStatus
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryChallengeId
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryKey
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyResetCompletionId
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRotationId
import dev.kreienbuehl.ksecuremessage.protocol.RequestNonce
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryChallengeIssue
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryChallengeRequest
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyResetCancellation
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyResetCancellationAuthority
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyResetCancellationResult
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyResetCompletionResult
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyResetCompletionTransition
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyResetRequest
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyResetRequestResult
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyRotationResult
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyRotationTransition
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
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/**
 * Delayed recovery key resets on persistent storage (docs/recovery-key-reset.md):
 * a pending reset and its timing survive real restarts (the delay never
 * restarts), completion, cancellation and exact retries work after a restart,
 * a failure inside a reset transaction changes nothing, and the database
 * never holds private recovery key material.
 */
class SqlDelightServerRecoveryKeyResetTest {
    private val database = TempDatabase()
    private var driver: SqlDriver = database.driver()

    private val phone = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val laptop = DeviceAddress(UserId("alice"), DeviceId("laptop"))
    private val alice = phone.userId
    private val t0 = Instant.fromEpochMilliseconds(1_767_225_600_000)
    private val eligible = t0 + 72.hours

    private fun key(seed: Int) = ByteArray(32) { (seed * 7 + it).toByte() }
    private val seeds = listOf(0xA0, 0xB0, 0xC0).map { first -> ByteArray(32) { (first + it).toByte() } }
    private val recoveryKeys = seeds.map { LastDeviceRecoveryKey.decode(kotlin.io.encoding.Base64.UrlSafe.withPadding(kotlin.io.encoding.Base64.PaddingOption.ABSENT).encode(it)) }
    private fun r(index: Int) = recoveryKeys[index - 1].publicKey

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
        devices.register(DeviceRegistration(laptop, key(2)), t0)
        lastDeviceRecovery.registerRecoveryKey(alice, r(1), t0)
    }

    private suspend fun SqlDelightServerStorage.request(id: Int = 1, at: Instant = t0) =
        lastDeviceRecovery.requestRecoveryKeyReset(
            RecoveryKeyResetRequest(assertNotNull(devices.registrationState(phone)), RecoveryKeyResetId(ByteArray(16) { id.toByte() }), at, at + 72.hours),
        )

    private suspend fun SqlDelightServerStorage.completion(reset: RecoveryKeyResetStatus.Pending, to: Int, at: Instant = reset.eligibleAt) =
        RecoveryKeyResetCompletionTransition(
            alice, reset.resetId, reset.recoveryPublicKey, reset.recoveryKeyEpoch, reset.requestedAt, reset.eligibleAt, r(to),
            assertNotNull(devices.registrationState(laptop)), RecoveryKeyResetCompletionId(ByteArray(32) { to.toByte() }), at,
        )

    private suspend fun SqlDelightServerStorage.issue(seed: Int, at: Instant = t0) =
        lastDeviceRecovery.issueChallenge(
            LastDeviceRecoveryChallengeRequest(phone, LastDeviceRecoveryChallengeId(ByteArray(16) { seed.toByte() }), ByteArray(32) { seed.toByte() }, at, at + 5.minutes),
        )

    @Test
    fun aPendingResetAndItsDelaySurviveRestarts() = runTest {
        val reset = assertIs<RecoveryKeyResetRequestResult.Created>(registered().request()).reset
        var storage = restart()
        assertEquals(reset, storage.lastDeviceRecovery.pendingRecoveryKeyReset(alice))
        // A repeated request after the restart returns the same reset: the delay did not restart.
        assertEquals(reset, assertIs<RecoveryKeyResetRequestResult.Existing>(storage.request(id = 2, at = t0 + 1.hours)).reset)
        storage = restart()
        assertEquals(RecoveryKeyResetCompletionResult.NOT_YET_ELIGIBLE, storage.lastDeviceRecovery.completeRecoveryKeyReset(storage.completion(reset, 2, at = eligible - 1.minutes)))
        storage = restart()
        val completion = storage.completion(reset, 2)
        assertEquals(RecoveryKeyResetCompletionResult.COMPLETED, storage.lastDeviceRecovery.completeRecoveryKeyReset(completion))
        storage = restart()
        val state = assertNotNull(storage.lastDeviceRecovery.recoveryKeyState(alice))
        assertEquals(2, state.epoch)
        assertContentEquals(r(2), state.publicKey)
        assertEquals(eligible, state.installedAt)
        assertEquals(RecoveryKeyResetCompletionId(ByteArray(32) { 2 }), state.resetCompletionId)
        assertNull(storage.lastDeviceRecovery.pendingRecoveryKeyReset(alice))
        // Exact retry after a restart: no second increment.
        assertEquals(RecoveryKeyResetCompletionResult.ALREADY_APPLIED, storage.lastDeviceRecovery.completeRecoveryKeyReset(completion))
        assertEquals(2, restart().lastDeviceRecovery.recoveryKeyState(alice)?.epoch)
    }

    @Test
    fun aCancellationAfterARestartKeepsTheKey() = runTest {
        val reset = assertIs<RecoveryKeyResetRequestResult.Created>(registered().request()).reset
        var storage = restart()
        assertEquals(
            RecoveryKeyResetCancellationResult.CANCELLED,
            storage.lastDeviceRecovery.cancelRecoveryKeyReset(
                RecoveryKeyResetCancellation(alice, reset.resetId, RecoveryKeyResetCancellationAuthority.RecoveryKey(r(1), 1)),
            ),
        )
        storage = restart()
        assertNull(storage.lastDeviceRecovery.pendingRecoveryKeyReset(alice))
        val state = assertNotNull(storage.lastDeviceRecovery.recoveryKeyState(alice))
        assertEquals(1, state.epoch)
        assertContentEquals(r(1), state.publicKey)
        assertEquals(RecoveryKeyResetCompletionResult.NOT_PENDING, storage.lastDeviceRecovery.completeRecoveryKeyReset(storage.completion(reset, 2)))
    }

    @Test
    fun aRotationRemovesThePendingResetDurably() = runTest {
        val storage = registered()
        val reset = assertIs<RecoveryKeyResetRequestResult.Created>(storage.request()).reset
        val rotation = RecoveryKeyRotationTransition(
            alice, r(1), 1, r(3), assertNotNull(storage.devices.registrationState(phone)), RecoveryKeyRotationId(ByteArray(32) { 3 }),
            RequestNonce(ByteArray(16) { 3 }), t0, t0 - 5.minutes, t0 + 1.minutes,
        )
        assertEquals(RecoveryKeyRotationResult.ROTATED, storage.lastDeviceRecovery.rotateRecoveryKey(rotation))
        val reopened = restart()
        assertNull(reopened.lastDeviceRecovery.pendingRecoveryKeyReset(alice))
        assertEquals(RecoveryKeyResetCompletionResult.NOT_PENDING, reopened.lastDeviceRecovery.completeRecoveryKeyReset(reopened.completion(reset, 2)))
        assertContentEquals(r(3), reopened.lastDeviceRecovery.recoveryKeyState(alice)?.publicKey)
    }

    @Test
    fun failureInsideAResetTransactionChangesNothing() = runTest {
        registered().issue(1)
        val testDriver = TestDriver(driver)
        val storage = SqlDelightServerStorage.open(testDriver)

        testDriver.failAfter("INSERT INTO last_device_recovery_key_reset")
        assertFailsWith<InjectedFailure> { storage.request() }
        assertNull(storage.lastDeviceRecovery.pendingRecoveryKeyReset(alice))

        val reset = assertIs<RecoveryKeyResetRequestResult.Created>(storage.request()).reset
        val wipeChallenges = TestDriver.Fault({ it.trimEnd().endsWith("DELETE FROM last_device_recovery_challenge WHERE user_id = ?") }, afterExecution = true)
        val faults = listOf(
            "after the compare-and-set" to { testDriver.failAfter("UPDATE last_device_recovery_key_state") },
            "after the challenge removal" to { testDriver.fault = wipeChallenges },
            "after the reset removal" to { testDriver.failAfter("DELETE FROM last_device_recovery_key_reset WHERE user_id = ?") },
        )
        for ((name, arm) in faults) {
            arm()
            assertFailsWith<InjectedFailure>(name) { storage.lastDeviceRecovery.completeRecoveryKeyReset(storage.completion(reset, 2)) }
            val state = assertNotNull(storage.lastDeviceRecovery.recoveryKeyState(alice))
            assertEquals(1, state.epoch, name)
            assertContentEquals(r(1), state.publicKey, name)
            assertNull(state.resetCompletionId, name)
            assertEquals(reset, storage.lastDeviceRecovery.pendingRecoveryKeyReset(alice), name)
            assertNotNull(storage.lastDeviceRecovery.challenge(phone), name)
        }

        testDriver.failAfter("DELETE FROM last_device_recovery_key_reset WHERE user_id = ? AND reset_id = ?")
        assertFailsWith<InjectedFailure> {
            storage.lastDeviceRecovery.cancelRecoveryKeyReset(
                RecoveryKeyResetCancellation(alice, reset.resetId, RecoveryKeyResetCancellationAuthority.Device(assertNotNull(storage.devices.registrationState(laptop)))),
            )
        }
        assertEquals(reset, storage.lastDeviceRecovery.pendingRecoveryKeyReset(alice))

        assertEquals(RecoveryKeyResetCompletionResult.COMPLETED, storage.lastDeviceRecovery.completeRecoveryKeyReset(storage.completion(reset, 2)))
        assertEquals(2, restart().lastDeviceRecovery.recoveryKeyState(alice)?.epoch)
    }

    @Test
    fun theDatabaseNeverHoldsPrivateRecoveryKeyMaterial() = runTest {
        val storage = registered()
        storage.issue(1)
        val first = assertIs<RecoveryKeyResetRequestResult.Created>(storage.request()).reset
        assertEquals(RecoveryKeyResetCompletionResult.COMPLETED, storage.lastDeviceRecovery.completeRecoveryKeyReset(storage.completion(first, 2)))
        val second = assertIs<RecoveryKeyResetRequestResult.Created>(storage.request(id = 2, at = eligible)).reset
        assertEquals(eligible, second.requestedAt)
        driver.close()
        driver = database.driver()
        val file = java.nio.file.Files.readAllBytes(database.path)
        val blobs = driver.dump().values.flatten().joinToString("|")
        for (seed in seeds) {
            assertFalse(file.containsSubsequence(seed), "no seed in the database file")
            assertFalse(blobs.contains(seed.toHex(), ignoreCase = true), "no seed in any column")
        }
        assertFalse(blobs.contains(r(1).toHex(), ignoreCase = true), "the reset-out public key is not kept either")
        assertEquals(true, blobs.contains(r(2).toHex(), ignoreCase = true))
        assertIs<LastDeviceRecoveryChallengeIssue.Issued>(storage().issue(2, at = eligible))
    }

    private fun ByteArray.toHex(): String = joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }

    private fun ByteArray.containsSubsequence(needle: ByteArray): Boolean =
        (0..size - needle.size).any { start -> needle.indices.all { this[start + it] == needle[it] } }
}
