package dev.kreienbuehl.ksecuremessage.storage.testing

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
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecoveryId
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryChallengeId
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryId
import dev.kreienbuehl.ksecuremessage.protocol.RequestNonce
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationState
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryChallengeIssue
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryChallengeRequest
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryKeyException
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryReplacement
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryReplacementResult.ALREADY_APPLIED
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryReplacementResult.CHALLENGE_INVALID
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryReplacementResult.CONFLICT
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryReplacementResult.EPOCH_EXHAUSTED
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryReplacementResult.EXPIRED
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryReplacementResult.NOT_CONFIGURED
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryReplacementResult.NOT_REGISTERED
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryReplacementResult.REPLACED
import dev.kreienbuehl.ksecuremessage.storage.RecoveryReplacement
import dev.kreienbuehl.ksecuremessage.storage.RecoveryReplacementResult
import dev.kreienbuehl.ksecuremessage.storage.RotationReplacement
import dev.kreienbuehl.ksecuremessage.storage.RotationReplacementResult
import dev.kreienbuehl.ksecuremessage.storage.ServerStorage
import dev.kreienbuehl.ksecuremessage.storage.StoredLastDeviceRecoveryChallenge
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
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
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/**
 * Last-device recovery behavior every server storage must have
 * (docs/last-device-recovery.md): one recovery key per user, registered once
 * and never replaced; at most one challenge per device, reused while valid,
 * pruned after expiry; and
 * [dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationRepository.replaceForLastDeviceRecovery]
 * as a compare-and-set on the device's key and epoch that consumes the
 * challenge in the same step, is idempotent for the recovery that installed
 * the current key, shares its compare-and-set with device recovery and
 * routine rotation, and leaves everything else alone.
 *
 * Signatures are the service's job and not checked here.
 */
abstract class LastDeviceRecoveryRepositoryContractTest {
    /** Returns a new, empty storage. */
    protected abstract suspend fun newStorage(): ServerStorage

    /** Sets the registered [address]'s authentication epoch directly, for the exhaustion boundary. */
    protected abstract suspend fun setAuthEpoch(storage: ServerStorage, address: DeviceAddress, authEpoch: Long)

    private val phone = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val laptop = DeviceAddress(UserId("alice"), DeviceId("laptop"))
    private val bobPhone = DeviceAddress(UserId("bob"), DeviceId("phone"))
    private val now = Instant.fromEpochMilliseconds(1_767_225_600_000)

    private fun key(seed: Int) = ByteArray(32) { (seed * 7 + it).toByte() }
    private fun recoveryKey(seed: Int) = ByteArray(32) { (seed * 11 + it + 1).toByte() }
    private fun challengeId(seed: Int) = LastDeviceRecoveryChallengeId(ByteArray(16) { (seed * 5 + it).toByte() })
    private fun challengeNonce(seed: Int) = ByteArray(32) { (seed * 19 + it).toByte() }
    private fun recoveryId(seed: Int) = LastDeviceRecoveryId(ByteArray(32) { (seed * 23 + it).toByte() })
    private fun deviceRecoveryId(seed: Int) = DeviceRecoveryId(ByteArray(32) { (seed * 17 + it).toByte() })
    private fun rotationId(seed: Int) = DeviceAuthenticationRotationId(ByteArray(32) { (seed * 13 + it).toByte() })
    private fun nonce(seed: Int) = RequestNonce(ByteArray(16) { (seed * 3 + it).toByte() })

    /** phone with key 1 and laptop with key 100 (both alice), bob's phone with key 200, all at epoch 1; alice has recovery key 1. */
    private suspend fun registered(withRecoveryKey: Boolean = true): ServerStorage = newStorage().apply {
        assertTrue(devices.register(DeviceRegistration(phone, key(1)), now))
        assertTrue(devices.register(DeviceRegistration(laptop, key(100)), now))
        assertTrue(devices.register(DeviceRegistration(bobPhone, key(200)), now))
        if (withRecoveryKey) assertTrue(lastDeviceRecovery.registerRecoveryKey(phone.userId, recoveryKey(1), now))
    }

    private suspend fun ServerStorage.state(address: DeviceAddress = phone): DeviceRegistrationState =
        assertNotNull(devices.registrationState(address))

    private suspend fun ServerStorage.issue(
        seed: Int = 1,
        target: DeviceAddress = phone,
        at: Instant = now,
    ): StoredLastDeviceRecoveryChallenge {
        val issue = lastDeviceRecovery.issueChallenge(
            LastDeviceRecoveryChallengeRequest(target, challengeId(seed), challengeNonce(seed), at, at + 5.minutes),
        )
        return assertIs<LastDeviceRecoveryChallengeIssue.Issued>(issue).challenge
    }

    private suspend fun ServerStorage.recovery(
        challenge: StoredLastDeviceRecoveryChallenge,
        replacementKey: Int,
        id: Int = replacementKey,
        expected: DeviceRegistrationState? = null,
        recoveryKey: ByteArray = recoveryKey(1),
        at: Instant = now + 1.minutes,
    ) = LastDeviceRecoveryReplacement(
        expected = expected ?: state(challenge.challenge.target),
        expectedRecoveryPublicKey = recoveryKey,
        challengeId = challenge.challenge.id,
        challengeNonce = challenge.challenge.nonce,
        replacementPublicKey = key(replacementKey),
        recoveryId = recoveryId(id),
        now = at,
    )

    private suspend fun ServerStorage.rotation(replacementKey: Int, expected: DeviceRegistrationState? = null) = RotationReplacement(
        expected = expected ?: state(),
        replacementPublicKey = key(replacementKey),
        rotationId = rotationId(replacementKey),
        nonce = nonce(replacementKey),
        timestamp = now,
        pruneBefore = now - 5.minutes,
        installedAt = now + 2.minutes,
    )

    private suspend fun ServerStorage.deviceRecovery(replacementKey: Int, target: DeviceRegistrationState? = null) = RecoveryReplacement(
        expectedTarget = target ?: state(),
        expectedAuthorizer = state(laptop),
        replacementPublicKey = key(replacementKey),
        recoveryId = deviceRecoveryId(replacementKey),
        nonce = nonce(1000 + replacementKey),
        timestamp = now,
        pruneBefore = now - 5.minutes,
        installedAt = now + 2.minutes,
    )

    private suspend fun ServerStorage.assertKey(expected: Int, epoch: Long, lastDeviceRecovery: Int? = null) {
        val state = state()
        assertContentEquals(key(expected), state.registration.publicKey)
        assertContentEquals(key(expected), devices.registration(phone)?.publicKey)
        assertEquals(epoch, state.authEpoch)
        assertEquals(lastDeviceRecovery?.let(::recoveryId), state.lastDeviceRecoveryId)
        if (lastDeviceRecovery != null) {
            assertNull(state.recoveryId)
            assertNull(state.rotationId)
        }
    }

    @Test
    fun recoveryKeyIsRegisteredOnceAndNeverReplaced() = runTest {
        val storage = newStorage()
        assertNull(storage.lastDeviceRecovery.recoveryKey(phone.userId))
        assertTrue(storage.lastDeviceRecovery.registerRecoveryKey(phone.userId, recoveryKey(1), now))
        assertContentEquals(recoveryKey(1), storage.lastDeviceRecovery.recoveryKey(phone.userId))

        assertFalse(storage.lastDeviceRecovery.registerRecoveryKey(phone.userId, recoveryKey(1), now + 1.days), "same key: idempotent")
        assertFailsWith<LastDeviceRecoveryKeyException.Conflict> {
            storage.lastDeviceRecovery.registerRecoveryKey(phone.userId, recoveryKey(2), now)
        }
        assertContentEquals(recoveryKey(1), storage.lastDeviceRecovery.recoveryKey(phone.userId), "a different key never overwrites")

        assertNull(storage.lastDeviceRecovery.recoveryKey(bobPhone.userId), "per user")
        assertTrue(storage.lastDeviceRecovery.registerRecoveryKey(bobPhone.userId, recoveryKey(2), now))
        assertContentEquals(recoveryKey(2), storage.lastDeviceRecovery.recoveryKey(bobPhone.userId))
        assertContentEquals(recoveryKey(1), storage.lastDeviceRecovery.recoveryKey(phone.userId))

        assertFailsWith<IllegalArgumentException> {
            storage.lastDeviceRecovery.registerRecoveryKey(UserId("carol"), ByteArray(31), now)
        }
        assertNull(storage.lastDeviceRecovery.recoveryKey(UserId("carol")))
    }

    @Test
    fun concurrentRecoveryKeyRegistrationsHaveExactlyOneWinner() = runTest {
        repeat(10) {
            val storage = newStorage()
            val results = withContext(Dispatchers.Default) {
                (1..16).map { seed ->
                    async {
                        try {
                            if (storage.lastDeviceRecovery.registerRecoveryKey(phone.userId, recoveryKey(seed), now)) seed else null
                        } catch (e: LastDeviceRecoveryKeyException.Conflict) {
                            null
                        }
                    }
                }.awaitAll()
            }
            val winner = results.filterNotNull().single()
            assertContentEquals(recoveryKey(winner), storage.lastDeviceRecovery.recoveryKey(phone.userId))
        }
    }

    @Test
    fun challengeNeedsARegistrationAndARecoveryKey() = runTest {
        val storage = registered(withRecoveryKey = false)
        val unknown = DeviceAddress(UserId("alice"), DeviceId("watch"))
        fun request(target: DeviceAddress) =
            LastDeviceRecoveryChallengeRequest(target, challengeId(1), challengeNonce(1), now, now + 5.minutes)
        assertEquals(LastDeviceRecoveryChallengeIssue.NotRegistered, storage.lastDeviceRecovery.issueChallenge(request(unknown)))
        assertEquals(LastDeviceRecoveryChallengeIssue.NotConfigured, storage.lastDeviceRecovery.issueChallenge(request(phone)))
        assertNull(storage.lastDeviceRecovery.challenge(phone))

        assertTrue(storage.lastDeviceRecovery.registerRecoveryKey(phone.userId, recoveryKey(1), now))
        assertEquals(LastDeviceRecoveryChallengeIssue.NotConfigured, storage.lastDeviceRecovery.issueChallenge(request(bobPhone)), "per user")
        val challenge = storage.issue()
        assertEquals(phone, challenge.challenge.target)
        assertEquals(challengeId(1), challenge.challenge.id)
        assertContentEquals(challengeNonce(1), challenge.challenge.nonce)
        assertEquals(1, challenge.challenge.authEpoch)
        assertEquals(now + 5.minutes, challenge.challenge.expiresAt)
        assertContentEquals(key(1), challenge.authPublicKey)
        val stored = assertNotNull(storage.lastDeviceRecovery.challenge(phone))
        assertEquals(challengeId(1), stored.challenge.id)
    }

    @Test
    fun validChallengeIsReusedAndReplacedOnlyWhenOutdated() = runTest {
        val storage = registered()
        val first = storage.issue(1)
        val again = storage.issue(2, at = now + 4.minutes)
        assertEquals(first.challenge.id, again.challenge.id, "one challenge per device while it is valid")
        assertContentEquals(first.challenge.nonce, again.challenge.nonce)
        assertEquals(first.challenge.expiresAt, again.challenge.expiresAt)
        val boundary = storage.issue(3, at = now + 5.minutes)
        assertEquals(first.challenge.id, boundary.challenge.id, "valid until and including expiresAt")

        val afterExpiry = storage.issue(4, at = now + 5.minutes + 1.milliseconds)
        assertEquals(challengeId(4), afterExpiry.challenge.id)

        // Another device's challenge is independent.
        assertEquals(challengeId(5), storage.issue(5, target = laptop, at = now + 6.minutes).challenge.id)

        assertEquals(RotationReplacementResult.REPLACED, storage.devices.replaceForRotation(storage.rotation(2)))
        val afterRotation = storage.issue(6, at = now + 6.minutes)
        assertEquals(challengeId(6), afterRotation.challenge.id, "a challenge for an outdated key or epoch is replaced")
        assertEquals(2, afterRotation.challenge.authEpoch)
        assertContentEquals(key(2), afterRotation.authPublicKey)
    }

    @Test
    fun expiredChallengesArePruned() = runTest {
        val storage = registered()
        storage.issue(1, target = phone)
        storage.issue(2, target = laptop, at = now + 3.minutes)
        storage.issue(3, target = phone, at = now + 5.minutes) // reused, not pruned
        assertNotNull(storage.lastDeviceRecovery.challenge(phone))

        // Issuing for laptop after phone's challenge expired prunes phone's.
        storage.issue(4, target = laptop, at = now + 6.minutes)
        assertNull(storage.lastDeviceRecovery.challenge(phone))
        assertEquals(challengeId(2), assertNotNull(storage.lastDeviceRecovery.challenge(laptop)).challenge.id)

        // A recovery attempt prunes too.
        val challenge = storage.issue(5, target = phone, at = now + 7.minutes)
        assertEquals(
            CHALLENGE_INVALID,
            storage.devices.replaceForLastDeviceRecovery(storage.recovery(challenge, 9, at = now + 9.minutes).let {
                LastDeviceRecoveryReplacement(it.expected, it.expectedRecoveryPublicKey, challengeId(99), it.challengeNonce, key(9), recoveryId(9), it.now)
            }),
        )
        assertNull(storage.lastDeviceRecovery.challenge(laptop), "laptop's challenge expired at +8 minutes")
        assertNotNull(storage.lastDeviceRecovery.challenge(phone))
    }

    @Test
    fun recoveryReplacesTheKeyOnceAndConsumesTheChallenge() = runTest {
        val storage = registered()
        val challenge = storage.issue()
        val installedAt = now + 3.minutes
        val recovery = storage.recovery(challenge, 2, at = installedAt)

        assertEquals(REPLACED, storage.devices.replaceForLastDeviceRecovery(recovery))
        storage.assertKey(2, epoch = 2, lastDeviceRecovery = 2)
        assertEquals(installedAt, storage.state().authKeyInstalledAt)
        assertNull(storage.lastDeviceRecovery.challenge(phone), "the challenge is consumed")

        // Exact retry: recognized by the recovery ID although the challenge is gone; nothing changes.
        assertEquals(ALREADY_APPLIED, storage.devices.replaceForLastDeviceRecovery(recovery))
        assertEquals(ALREADY_APPLIED, storage.devices.replaceForLastDeviceRecovery(storage.recovery(challenge, 2, at = now + 1.days)))
        storage.assertKey(2, epoch = 2, lastDeviceRecovery = 2)
        assertEquals(installedAt, storage.state().authKeyInstalledAt)

        // The consumed challenge never authorizes another replacement key.
        assertEquals(CHALLENGE_INVALID, storage.devices.replaceForLastDeviceRecovery(storage.recovery(challenge, 3)))
        assertEquals(
            CHALLENGE_INVALID,
            storage.devices.replaceForLastDeviceRecovery(storage.recovery(challenge, 3, expected = recovery.expected)),
        )
        storage.assertKey(2, epoch = 2, lastDeviceRecovery = 2)

        // Other devices and users are untouched.
        assertContentEquals(key(100), storage.state(laptop).registration.publicKey)
        assertContentEquals(key(200), storage.state(bobPhone).registration.publicKey)
    }

    @Test
    fun unknownOrMismatchedChallengeIsRejectedAndKept() = runTest {
        val storage = registered()
        val challenge = storage.issue()
        val base = storage.recovery(challenge, 2)
        val wrongId = LastDeviceRecoveryReplacement(base.expected, recoveryKey(1), challengeId(9), challenge.challenge.nonce, key(2), recoveryId(2), base.now)
        val wrongNonce = LastDeviceRecoveryReplacement(base.expected, recoveryKey(1), challenge.challenge.id, challengeNonce(9), key(2), recoveryId(2), base.now)
        assertEquals(CHALLENGE_INVALID, storage.devices.replaceForLastDeviceRecovery(wrongId))
        assertEquals(CHALLENGE_INVALID, storage.devices.replaceForLastDeviceRecovery(wrongNonce))

        // A challenge of another device of the same user does not work for this one.
        val laptopChallenge = storage.issue(7, target = laptop)
        val crossDevice = LastDeviceRecoveryReplacement(
            base.expected, recoveryKey(1), laptopChallenge.challenge.id, laptopChallenge.challenge.nonce, key(2), recoveryId(2), base.now,
        )
        assertEquals(CHALLENGE_INVALID, storage.devices.replaceForLastDeviceRecovery(crossDevice))

        storage.assertKey(1, epoch = 1)
        assertEquals(challengeId(1), assertNotNull(storage.lastDeviceRecovery.challenge(phone)).challenge.id)
        assertEquals(REPLACED, storage.devices.replaceForLastDeviceRecovery(base))
    }

    @Test
    fun expiredChallengeIsRejected() = runTest {
        val storage = registered()
        val challenge = storage.issue()
        assertEquals(EXPIRED, storage.devices.replaceForLastDeviceRecovery(storage.recovery(challenge, 2, at = now + 5.minutes + 1.milliseconds)))
        storage.assertKey(1, epoch = 1)
        assertNull(storage.lastDeviceRecovery.challenge(phone), "the expired challenge was pruned")
        assertEquals(CHALLENGE_INVALID, storage.devices.replaceForLastDeviceRecovery(storage.recovery(challenge, 2, at = now + 1.minutes)))

        val boundary = storage.issue(2, at = now + 10.minutes)
        assertEquals(REPLACED, storage.devices.replaceForLastDeviceRecovery(storage.recovery(boundary, 2, at = now + 15.minutes)))
        storage.assertKey(2, epoch = 2, lastDeviceRecovery = 2)
    }

    @Test
    fun recoveryNeedsTheUsersOwnRegisteredRecoveryKey() = runTest {
        val storage = registered(withRecoveryKey = false)
        assertTrue(storage.lastDeviceRecovery.registerRecoveryKey(bobPhone.userId, recoveryKey(2), now))
        // No challenge can be issued for alice; even with a crafted replacement, bob's recovery key never recovers alice.
        val crafted = LastDeviceRecoveryReplacement(storage.state(), recoveryKey(2), challengeId(1), challengeNonce(1), key(2), recoveryId(2), now)
        assertEquals(NOT_CONFIGURED, storage.devices.replaceForLastDeviceRecovery(crafted))

        assertTrue(storage.lastDeviceRecovery.registerRecoveryKey(phone.userId, recoveryKey(1), now))
        val challenge = storage.issue()
        assertEquals(NOT_CONFIGURED, storage.devices.replaceForLastDeviceRecovery(storage.recovery(challenge, 2, recoveryKey = recoveryKey(2))))
        storage.assertKey(1, epoch = 1)
        assertNotNull(storage.lastDeviceRecovery.challenge(phone), "the challenge stays")

        val unknown = DeviceAddress(UserId("alice"), DeviceId("watch"))
        val missing = LastDeviceRecoveryReplacement(
            DeviceRegistrationState(DeviceRegistration(unknown, key(1)), 1, now, null),
            recoveryKey(1), challenge.challenge.id, challenge.challenge.nonce, key(2), recoveryId(2), now,
        )
        assertEquals(NOT_REGISTERED, storage.devices.replaceForLastDeviceRecovery(missing))
        assertNull(storage.devices.registrationState(unknown))
    }

    @Test
    fun changedRegistrationConflicts() = runTest {
        val storage = registered()
        val challenge = storage.issue()
        val stale = storage.state()
        // A routine rotation lands after the challenge was issued.
        assertEquals(RotationReplacementResult.REPLACED, storage.devices.replaceForRotation(storage.rotation(2)))
        assertEquals(CONFLICT, storage.devices.replaceForLastDeviceRecovery(storage.recovery(challenge, 3, expected = stale)))
        assertEquals(CONFLICT, storage.devices.replaceForLastDeviceRecovery(storage.recovery(challenge, 3)), "the challenge is for the old state")
        assertEquals(2, storage.state().authEpoch)
        assertContentEquals(key(2), storage.state().registration.publicKey)

        // Replacing the key with itself is never a transition.
        val fresh = storage.issue(2, at = now + 1.minutes)
        assertEquals(CONFLICT, storage.devices.replaceForLastDeviceRecovery(storage.recovery(fresh, 2)))
        assertEquals(2, storage.state().authEpoch)
        assertNotNull(storage.lastDeviceRecovery.challenge(phone))
    }

    @Test
    fun staleRecoveryCannotRestoreAnOlderKey() = runTest {
        val storage = registered()
        val challenge = storage.issue()
        val first = storage.recovery(challenge, 2)
        assertEquals(REPLACED, storage.devices.replaceForLastDeviceRecovery(first))
        // K2 -> K3 by routine rotation, then the old K1 -> K2 recovery is replayed.
        assertEquals(RotationReplacementResult.REPLACED, storage.devices.replaceForRotation(storage.rotation(3)))
        assertEquals(CHALLENGE_INVALID, storage.devices.replaceForLastDeviceRecovery(first))
        assertContentEquals(key(3), storage.state().registration.publicKey)
        assertEquals(3, storage.state().authEpoch)
        assertEquals(rotationId(3), storage.state().rotationId)
        assertNull(storage.state().lastDeviceRecoveryId, "a rotation clears the last-device recovery ID")

        // Also after a device recovery K3 -> K4 and a new challenge.
        assertEquals(RecoveryReplacementResult.REPLACED, storage.devices.replaceForRecovery(storage.deviceRecovery(4)))
        assertNull(storage.state().lastDeviceRecoveryId, "a device recovery clears it too")
        storage.issue(9, at = now + 2.minutes)
        assertEquals(CHALLENGE_INVALID, storage.devices.replaceForLastDeviceRecovery(first))
        assertContentEquals(key(4), storage.state().registration.publicKey)
        assertEquals(4, storage.state().authEpoch)
    }

    @Test
    fun lastDeviceRecoveryAndTheOtherTransitionsShareTheMetadata() = runTest {
        val storage = registered()
        assertEquals(REPLACED, storage.devices.replaceForLastDeviceRecovery(storage.recovery(storage.issue(1), 2)))
        storage.assertKey(2, epoch = 2, lastDeviceRecovery = 2)
        assertEquals(RotationReplacementResult.REPLACED, storage.devices.replaceForRotation(storage.rotation(3)))
        assertEquals(rotationId(3), storage.state().rotationId)
        assertNull(storage.state().lastDeviceRecoveryId)
        assertEquals(REPLACED, storage.devices.replaceForLastDeviceRecovery(storage.recovery(storage.issue(2, at = now + 1.minutes), 4)))
        storage.assertKey(4, epoch = 4, lastDeviceRecovery = 4)
        assertEquals(RecoveryReplacementResult.REPLACED, storage.devices.replaceForRecovery(storage.deviceRecovery(5)))
        assertEquals(deviceRecoveryId(5), storage.state().recoveryId)
        assertNull(storage.state().lastDeviceRecoveryId)
        assertNull(storage.state().rotationId)
        assertEquals(5, storage.state().authEpoch)
    }

    @Test
    fun epochNeverWraps() = runTest {
        val storage = registered()
        setAuthEpoch(storage, phone, Long.MAX_VALUE - 1)
        assertEquals(REPLACED, storage.devices.replaceForLastDeviceRecovery(storage.recovery(storage.issue(1), 2)))
        storage.assertKey(2, epoch = Long.MAX_VALUE, lastDeviceRecovery = 2)

        val challenge = storage.issue(2, at = now + 1.minutes)
        assertEquals(EPOCH_EXHAUSTED, storage.devices.replaceForLastDeviceRecovery(storage.recovery(challenge, 3)))
        storage.assertKey(2, epoch = Long.MAX_VALUE, lastDeviceRecovery = 2)
        assertNotNull(storage.lastDeviceRecovery.challenge(phone), "the challenge is not consumed")
    }

    @Test
    fun concurrentIdenticalRecoveriesReplaceOnce() = runTest {
        repeat(10) {
            val storage = registered()
            val recovery = storage.recovery(storage.issue(), 2)
            val results = withContext(Dispatchers.Default) {
                List(32) { async { storage.devices.replaceForLastDeviceRecovery(recovery) } }.awaitAll()
            }
            assertEquals(1, results.count { it == REPLACED })
            assertEquals(31, results.count { it == ALREADY_APPLIED })
            storage.assertKey(2, epoch = 2, lastDeviceRecovery = 2)
        }
    }

    @Test
    fun concurrentDifferentRecoveriesOfOneChallengeHaveExactlyOneWinner() = runTest {
        repeat(10) {
            val storage = registered()
            val challenge = storage.issue()
            val expected = storage.state()
            val results = withContext(Dispatchers.Default) {
                (2..33).map { seed ->
                    async { seed to storage.devices.replaceForLastDeviceRecovery(storage.recovery(challenge, seed, expected = expected)) }
                }.awaitAll()
            }
            val winner = results.single { it.second == REPLACED }.first
            assertTrue(results.all { it.second == REPLACED || it.second == CHALLENGE_INVALID })
            storage.assertKey(winner, epoch = 2, lastDeviceRecovery = winner)
        }
    }

    @Test
    fun concurrentLastDeviceRecoveryDeviceRecoveryAndRotationHaveExactlyOneWinner() = runTest {
        repeat(20) {
            val storage = registered()
            val challenge = storage.issue()
            val expected = storage.state()
            val laptopState = storage.state(laptop)
            val results = withContext(Dispatchers.Default) {
                val lastDevice = (2..11).map { seed ->
                    async { storage.devices.replaceForLastDeviceRecovery(storage.recovery(challenge, seed, expected = expected)) == REPLACED }
                }
                val recoveries = (40..49).map { seed ->
                    async {
                        val recovery = RecoveryReplacement(
                            expected, laptopState, key(seed), deviceRecoveryId(seed), nonce(seed), now, now - 5.minutes, now,
                        )
                        storage.devices.replaceForRecovery(recovery) == RecoveryReplacementResult.REPLACED
                    }
                }
                val rotations = (60..69).map { seed ->
                    async { storage.devices.replaceForRotation(storage.rotation(seed, expected = expected)) == RotationReplacementResult.REPLACED }
                }
                (lastDevice + recoveries + rotations).awaitAll()
            }
            assertEquals(1, results.count { it }, "exactly one transition wins")
            val state = storage.state()
            assertEquals(2, state.authEpoch)
            assertEquals(1, listOfNotNull(state.recoveryId, state.rotationId, state.lastDeviceRecoveryId).size)
        }
    }

    @Test
    fun recoveryLeavesPreKeysMailboxNoncesAndOtherDevicesAlone() = runTest {
        val storage = registered()
        val signed = PublicSignedPreKey(SignedPreKeyId(1), ByteArray(64) { 5 }, ByteArray(64) { 6 })
        val oneTime = listOf(1, 2, 3).map { PublicOneTimePreKey(OneTimePreKeyId(it), ByteArray(64) { _ -> it.toByte() }) }
        val publication = PreKeyPublication(phone, ByteArray(64) { 4 }, signed, oneTime)
        storage.preKeys.publish(publication)
        assertEquals(OneTimePreKeyId(1), assertNotNull(storage.preKeys.consumePreKeyBundle(phone)).oneTimePreKey?.id)
        val envelope = EncryptedEnvelope(MessageId("m1"), bobPhone, phone, payload = byteArrayOf(1, 2, 3))
        storage.mailboxes.enqueue(envelope)
        assertTrue(storage.authenticationNonces.claim(phone, nonce(50).bytes, now, now))
        val laptopChallenge = storage.issue(3, target = laptop)

        assertEquals(REPLACED, storage.devices.replaceForLastDeviceRecovery(storage.recovery(storage.issue(), 2)))

        assertFalse(storage.authenticationNonces.claim(phone, nonce(50).bytes, now, now), "nonces stay claimed")
        assertEquals(2, storage.preKeys.oneTimePreKeyCount(phone))
        storage.preKeys.publish(publication) // re-upload: the consumed one stays consumed
        assertEquals(2, storage.preKeys.oneTimePreKeyCount(phone))
        val bundle = assertNotNull(storage.preKeys.consumePreKeyBundle(phone))
        assertContentEquals(publication.identityKey, bundle.identityKey)
        assertEquals(OneTimePreKeyId(2), bundle.oneTimePreKey?.id)
        val drained = storage.mailboxes.drain(phone).single()
        assertEquals(envelope.id, drained.id)
        assertContentEquals(envelope.payload, drained.payload)
        assertEquals(laptopChallenge.challenge.id, assertNotNull(storage.lastDeviceRecovery.challenge(laptop)).challenge.id)
        assertContentEquals(recoveryKey(1), storage.lastDeviceRecovery.recoveryKey(phone.userId), "the recovery key stays registered")
    }

    @Test
    fun valuesAreCopied() = runTest {
        val storage = registered()
        val challenge = storage.issue()
        val replacementKey = key(2)
        val recoveryPublicKey = recoveryKey(1)
        val nonce = challenge.challenge.nonce
        val recovery = LastDeviceRecoveryReplacement(storage.state(), recoveryPublicKey, challenge.challenge.id, nonce, replacementKey, recoveryId(2), now)
        replacementKey.fill(0)
        recoveryPublicKey.fill(0)
        nonce.fill(0)
        assertNotNull(storage.lastDeviceRecovery.recoveryKey(phone.userId)).fill(0)
        challenge.authPublicKey.fill(0)
        assertEquals(REPLACED, storage.devices.replaceForLastDeviceRecovery(recovery))
        storage.state().registration.publicKey.fill(0)
        storage.assertKey(2, epoch = 2, lastDeviceRecovery = 2)
        assertContentEquals(recoveryKey(1), storage.lastDeviceRecovery.recoveryKey(phone.userId))
    }
}
