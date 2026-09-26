package dev.kreienbuehl.ksecuremessage.storage.server.sqldelight

import app.cash.sqldelight.db.SqlDriver
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.DeviceRegistration
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryChallengeId
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryId
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryKey
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRevocationId
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRotationId
import dev.kreienbuehl.ksecuremessage.protocol.RequestNonce
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryChallengeIssue
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryChallengeRequest
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryReplacement
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryReplacementResult
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyRevocationResult
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyRevocationTransition
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyRotationResult
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyRotationTransition
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyStatus
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
 * Recovery key lifecycle on persistent storage (docs/recovery-key-lifecycle.md):
 * rotation, revocation and re-registration survive real restarts with a
 * monotonic epoch, stale transitions stay rejected after restarts, a
 * transition that fails inside its transaction changes nothing, a challenge
 * bound to an older recovery key epoch is refused even if it survived, and
 * the database never holds private recovery key material.
 */
class SqlDelightServerRecoveryKeyLifecycleTest {
    private val database = TempDatabase()
    private var driver: SqlDriver = database.driver()

    private val phone = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val alice = phone.userId
    private val t0 = Instant.fromEpochMilliseconds(1_767_225_600_000)

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
        lastDeviceRecovery.registerRecoveryKey(alice, r(1), t0)
    }

    private suspend fun SqlDelightServerStorage.rotation(from: Int, to: Int, epoch: Long, at: Instant = t0 + 1.minutes) =
        RecoveryKeyRotationTransition(
            alice, r(from), epoch, r(to), assertNotNull(devices.registrationState(phone)),
            RecoveryKeyRotationId(ByteArray(32) { (from * 16 + to).toByte() }), RequestNonce(ByteArray(16) { (from * 16 + to).toByte() }),
            t0, t0 - 5.minutes, at,
        )

    private suspend fun SqlDelightServerStorage.revocation(of: Int, epoch: Long, at: Instant = t0 + 2.minutes) =
        RecoveryKeyRevocationTransition(
            alice, r(of), epoch, assertNotNull(devices.registrationState(phone)),
            RecoveryKeyRevocationId(ByteArray(32) { (100 + of).toByte() }), RequestNonce(ByteArray(16) { (100 + of).toByte() }),
            t0, t0 - 5.minutes, at,
        )

    private suspend fun SqlDelightServerStorage.issue(seed: Int, at: Instant = t0) =
        lastDeviceRecovery.issueChallenge(
            LastDeviceRecoveryChallengeRequest(phone, LastDeviceRecoveryChallengeId(ByteArray(16) { seed.toByte() }), ByteArray(32) { seed.toByte() }, at, at + 5.minutes),
        )

    @Test
    fun lifecycleSurvivesRestartsWithAMonotonicEpoch() = runTest {
        val first = registered().let { storage ->
            val challenge = assertIs<LastDeviceRecoveryChallengeIssue.Issued>(storage.issue(1)).challenge
            val rotation = storage.rotation(1, 2, epoch = 1)
            assertEquals(RecoveryKeyRotationResult.ROTATED, storage.lastDeviceRecovery.rotateRecoveryKey(rotation))
            assertNull(storage.lastDeviceRecovery.challenge(phone))
            challenge to rotation
        }

        var storage = restart()
        var state = assertNotNull(storage.lastDeviceRecovery.recoveryKeyState(alice))
        assertEquals(2, state.epoch)
        assertContentEquals(r(2), state.publicKey)
        assertEquals(t0 + 1.minutes, state.installedAt)
        assertEquals(RecoveryKeyRotationResult.ALREADY_APPLIED, storage.lastDeviceRecovery.rotateRecoveryKey(first.second), "exact retry after a restart")
        // R1 is stale: neither a new rotation from it nor the old challenge recovers anything.
        assertEquals(RecoveryKeyRotationResult.CONFLICT, storage.lastDeviceRecovery.rotateRecoveryKey(storage.rotation(1, 3, epoch = 1)))
        val oldChallenge = first.first
        assertEquals(
            LastDeviceRecoveryReplacementResult.NOT_CONFIGURED,
            storage.devices.replaceForLastDeviceRecovery(
                LastDeviceRecoveryReplacement(
                    assertNotNull(storage.devices.registrationState(phone)), r(1), oldChallenge.challenge.id, oldChallenge.challenge.nonce,
                    key(9), LastDeviceRecoveryId(ByteArray(32) { 9 }), t0 + 2.minutes,
                ),
            ),
        )

        val revocation = storage.revocation(2, epoch = 2)
        assertEquals(RecoveryKeyRevocationResult.REVOKED, storage.lastDeviceRecovery.revokeRecoveryKey(revocation))
        storage = restart()
        state = assertNotNull(storage.lastDeviceRecovery.recoveryKeyState(alice))
        assertEquals(RecoveryKeyStatus.REVOKED, state.status)
        assertEquals(3, state.epoch)
        assertEquals(t0 + 2.minutes, state.transitionedAt)
        assertEquals(LastDeviceRecoveryChallengeIssue.NotConfigured, storage.issue(2, at = t0 + 3.minutes))
        assertEquals(RecoveryKeyRevocationResult.ALREADY_APPLIED, storage.lastDeviceRecovery.revokeRecoveryKey(revocation))

        assertEquals(true, storage.lastDeviceRecovery.registerRecoveryKey(alice, r(3), t0 + 4.minutes))
        storage = restart()
        state = assertNotNull(storage.lastDeviceRecovery.recoveryKeyState(alice))
        assertEquals(RecoveryKeyStatus.ACTIVE, state.status)
        assertEquals(4, state.epoch, "never reset")
        assertContentEquals(r(3), state.publicKey)
        assertEquals(RecoveryKeyRevocationResult.CONFLICT, storage.lastDeviceRecovery.revokeRecoveryKey(revocation), "stale after re-registration")
        assertEquals(RecoveryKeyRotationResult.CONFLICT, storage.lastDeviceRecovery.rotateRecoveryKey(first.second))
        assertEquals(4, assertIs<LastDeviceRecoveryChallengeIssue.Issued>(storage.issue(3, at = t0 + 5.minutes)).challenge.recoveryKeyEpoch)
        assertEquals(1, storage.devices.registrationState(phone)?.authEpoch, "device authentication untouched")
    }

    @Test
    fun failureInsideATransitionChangesNothing() = runTest {
        registered().issue(1)
        val testDriver = TestDriver(driver)
        val storage = SqlDelightServerStorage.open(testDriver)
        // The statement nonces of the rotation (1 -> 2) and the revocation (of 1).
        val rotationNonce = ByteArray(16) { 0x12 }
        val revocationNonce = ByteArray(16) { 101 }
        val wipe = TestDriver.Fault({ it.trimEnd().endsWith("DELETE FROM last_device_recovery_challenge WHERE user_id = ?") }, afterExecution = true)
        val faults = listOf(
            "before the nonce claim" to { testDriver.failBefore("INSERT OR IGNORE INTO authentication_nonce") },
            "after the nonce claim" to { testDriver.failAfter("INSERT OR IGNORE INTO authentication_nonce") },
            "after the compare-and-set" to { testDriver.failAfter("UPDATE last_device_recovery_key_state") },
            "after the challenge removal" to { testDriver.fault = wipe },
        )
        suspend fun assertUnchanged(name: String) {
            val state = assertNotNull(storage.lastDeviceRecovery.recoveryKeyState(alice))
            assertEquals(RecoveryKeyStatus.ACTIVE, state.status, name)
            assertEquals(1, state.epoch, name)
            assertContentEquals(r(1), state.publicKey, name)
            assertNotNull(storage.lastDeviceRecovery.challenge(phone), name)
        }
        for ((name, arm) in faults) {
            arm()
            assertFailsWith<InjectedFailure>(name) { storage.lastDeviceRecovery.rotateRecoveryKey(storage.rotation(1, 2, epoch = 1)) }
            assertUnchanged("rotation $name")
            arm()
            assertFailsWith<InjectedFailure>(name) { storage.lastDeviceRecovery.revokeRecoveryKey(storage.revocation(1, epoch = 1)) }
            assertUnchanged("revocation $name")
        }
        // Neither nonce stayed claimed: the claim rolled back with the transition.
        assertEquals(0L, driver.count("SELECT count(*) FROM authentication_nonce"))

        assertEquals(RecoveryKeyRotationResult.ROTATED, storage.lastDeviceRecovery.rotateRecoveryKey(storage.rotation(1, 2, epoch = 1)))
        assertFalse(storage.authenticationNonces.claim(phone, rotationNonce, t0, t0 - 5.minutes), "claimed on success")
        assertEquals(true, storage.authenticationNonces.claim(phone, revocationNonce, t0, t0 - 5.minutes))
        assertEquals(RecoveryKeyRevocationResult.REVOKED, storage.lastDeviceRecovery.revokeRecoveryKey(storage.revocation(2, epoch = 2)))
        // A registration after the revocation is a guarded UPDATE too; a failure keeps the revoked state.
        testDriver.failAfter("UPDATE last_device_recovery_key_state")
        assertFailsWith<InjectedFailure> { storage.lastDeviceRecovery.registerRecoveryKey(alice, r(3), t0) }
        assertEquals(RecoveryKeyStatus.REVOKED, storage.lastDeviceRecovery.recoveryKeyState(alice)?.status)
        assertEquals(3, restart().lastDeviceRecovery.recoveryKeyState(alice)?.epoch)
    }

    @Test
    fun aChallengeFromAnOlderRecoveryKeyEpochIsRefused() = runTest {
        val storage = registered()
        val challenge = assertIs<LastDeviceRecoveryChallengeIssue.Issued>(storage.issue(1)).challenge
        assertEquals(RecoveryKeyRotationResult.ROTATED, storage.lastDeviceRecovery.rotateRecoveryKey(storage.rotation(1, 2, epoch = 1)))
        // Put the old challenge back behind the storage's back, as if the removal had been lost.
        driver.execute(
            null,
            "INSERT INTO last_device_recovery_challenge VALUES ('alice', 'phone', ?, ?, 1, ?, ${t0.toEpochMilliseconds()}, ${(t0 + 5.minutes).toEpochMilliseconds()}, 1)",
            3,
        ) {
            bindBytes(0, challenge.challenge.id.bytes)
            bindBytes(1, challenge.challenge.nonce)
            bindBytes(2, key(1))
        }
        assertEquals(1, storage.lastDeviceRecovery.challenge(phone)?.recoveryKeyEpoch)
        // Even with the current key R2, the epoch-1 challenge authorizes nothing.
        assertEquals(
            LastDeviceRecoveryReplacementResult.CHALLENGE_INVALID,
            storage.devices.replaceForLastDeviceRecovery(
                LastDeviceRecoveryReplacement(
                    assertNotNull(storage.devices.registrationState(phone)), r(2), challenge.challenge.id, challenge.challenge.nonce,
                    key(9), LastDeviceRecoveryId(ByteArray(32) { 9 }), t0 + 1.minutes,
                ),
            ),
        )
        // And issuing replaces it with one for the current epoch.
        val fresh = assertIs<LastDeviceRecoveryChallengeIssue.Issued>(storage.issue(2, at = t0 + 1.minutes)).challenge
        assertEquals(2, fresh.recoveryKeyEpoch)
        assertFalse(fresh.challenge.id == challenge.challenge.id)
    }

    @Test
    fun theDatabaseNeverHoldsPrivateRecoveryKeyMaterial() = runTest {
        val storage = registered()
        storage.issue(1)
        storage.lastDeviceRecovery.rotateRecoveryKey(storage.rotation(1, 2, epoch = 1))
        storage.lastDeviceRecovery.revokeRecoveryKey(storage.revocation(2, epoch = 2))
        storage.lastDeviceRecovery.registerRecoveryKey(alice, r(3), t0)
        driver.close()
        driver = database.driver()
        val file = java.nio.file.Files.readAllBytes(database.path)
        val blobs = driver.dump().values.flatten().joinToString("|")
        for (seed in seeds) {
            assertFalse(file.containsSubsequence(seed), "no seed in the database file")
            assertFalse(blobs.contains(seed.toHex(), ignoreCase = true), "no seed in any column")
        }
        assertFalse(blobs.contains(r(1).toHex(), ignoreCase = true), "the rotated-out public key is not kept either")
        assertEquals(true, blobs.contains(r(3).toHex(), ignoreCase = true))
    }

    private fun ByteArray.toHex(): String = joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }

    private fun ByteArray.containsSubsequence(needle: ByteArray): Boolean =
        (0..size - needle.size).any { start -> needle.indices.all { this[start + it] == needle[it] } }
}
