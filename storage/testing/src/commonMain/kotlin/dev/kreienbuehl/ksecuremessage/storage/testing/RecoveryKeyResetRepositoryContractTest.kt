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
import dev.kreienbuehl.ksecuremessage.model.RecoveryKeyResetId
import dev.kreienbuehl.ksecuremessage.model.RecoveryKeyResetStatus
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationRotationId
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryChallengeId
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryId
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyResetCompletionId
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRevocationId
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRotationId
import dev.kreienbuehl.ksecuremessage.protocol.RequestNonce
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationState
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryChallengeIssue
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryChallengeRequest
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryReplacement
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryReplacementResult
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyResetCancellation
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyResetCancellationAuthority
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyResetCancellationResult
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyResetCompletionResult
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyResetCompletionTransition
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyResetRequest
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyResetRequestResult
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyRevocationResult
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyRevocationTransition
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyRotationResult
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyRotationTransition
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyState
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyStatus
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
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/**
 * Delayed recovery key reset behavior every server storage must have
 * (docs/recovery-key-reset.md): at most one pending reset per user, bound to
 * the ACTIVE key and epoch read in the request's own step and returned
 * unchanged to every later request; completion as a compare-and-set on the
 * reset, the recovery key state and the completing registration, only from
 * the eligibility time on, together with the removal of the reset and every
 * challenge; exact retries recognized by the stored completion ID;
 * cancellation by a current device or the current recovery key without any
 * other change; every other recovery key transition removing the reset; and
 * nothing else touched.
 *
 * Signatures, ServerAuth and the delay policy are the service's job and not
 * checked here.
 */
abstract class RecoveryKeyResetRepositoryContractTest {
    /** Returns a new, empty storage. */
    protected abstract suspend fun newStorage(): ServerStorage

    /** Sets [userId]'s recovery key epoch directly, for the exhaustion boundary. */
    protected abstract suspend fun setRecoveryKeyEpoch(storage: ServerStorage, userId: UserId, epoch: Long)

    private val phone = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val laptop = DeviceAddress(UserId("alice"), DeviceId("laptop"))
    private val bobPhone = DeviceAddress(UserId("bob"), DeviceId("phone"))
    private val alice = phone.userId
    private val now = Instant.fromEpochMilliseconds(1_767_225_600_000)
    private val delay = 72.hours
    private val eligible = now + delay

    private fun key(seed: Int) = ByteArray(32) { (seed * 7 + it).toByte() }
    private fun recoveryKey(seed: Int) = ByteArray(32) { (seed * 11 + it + 1).toByte() }
    private fun resetId(seed: Int) = RecoveryKeyResetId(ByteArray(16) { (seed * 23 + it).toByte() })
    private fun completionId(seed: Int) = RecoveryKeyResetCompletionId(ByteArray(32) { (seed * 29 + it).toByte() })
    private fun nonce(seed: Int) = RequestNonce(ByteArray(16) { (seed * 3 + it).toByte() })

    /** phone (key 1), laptop (key 100), bob's phone (key 200), all at epoch 1; alice has recovery key 1, bob recovery key 50. */
    private suspend fun registered(): ServerStorage = newStorage().apply {
        assertTrue(devices.register(DeviceRegistration(phone, key(1)), now))
        assertTrue(devices.register(DeviceRegistration(laptop, key(100)), now))
        assertTrue(devices.register(DeviceRegistration(bobPhone, key(200)), now))
        assertTrue(lastDeviceRecovery.registerRecoveryKey(alice, recoveryKey(1), now))
        assertTrue(lastDeviceRecovery.registerRecoveryKey(bobPhone.userId, recoveryKey(50), now))
    }

    private suspend fun ServerStorage.device(address: DeviceAddress = phone): DeviceRegistrationState =
        assertNotNull(devices.registrationState(address))

    private suspend fun ServerStorage.recoveryState(userId: UserId = alice): RecoveryKeyState =
        assertNotNull(lastDeviceRecovery.recoveryKeyState(userId))

    private suspend fun ServerStorage.request(
        requester: DeviceAddress = phone,
        id: Int = 1,
        at: Instant = now,
        eligibleAt: Instant = at + delay,
    ): RecoveryKeyResetRequestResult =
        lastDeviceRecovery.requestRecoveryKeyReset(RecoveryKeyResetRequest(device(requester), resetId(id), at, eligibleAt))

    private suspend fun ServerStorage.created(requester: DeviceAddress = phone, id: Int = 1, at: Instant = now): RecoveryKeyResetStatus.Pending =
        assertIs<RecoveryKeyResetRequestResult.Created>(request(requester, id, at)).reset

    private suspend fun ServerStorage.completion(
        reset: RecoveryKeyResetStatus.Pending,
        to: Int,
        id: Int = to,
        completer: DeviceRegistrationState? = null,
        at: Instant = reset.eligibleAt,
    ) = RecoveryKeyResetCompletionTransition(
        userId = reset.userId,
        resetId = reset.resetId,
        expectedPublicKey = reset.recoveryPublicKey,
        expectedEpoch = reset.recoveryKeyEpoch,
        requestedAt = reset.requestedAt,
        eligibleAt = reset.eligibleAt,
        newPublicKey = recoveryKey(to),
        expectedCompleter = completer ?: device(laptop),
        completionId = completionId(id),
        now = at,
    )

    private suspend fun ServerStorage.complete(
        reset: RecoveryKeyResetStatus.Pending,
        to: Int,
        id: Int = to,
        completer: DeviceRegistrationState? = null,
        at: Instant = reset.eligibleAt,
    ) = lastDeviceRecovery.completeRecoveryKeyReset(completion(reset, to, id, completer, at))

    private suspend fun ServerStorage.cancelByDevice(reset: RecoveryKeyResetStatus.Pending, device: DeviceRegistrationState? = null) =
        lastDeviceRecovery.cancelRecoveryKeyReset(
            RecoveryKeyResetCancellation(reset.userId, reset.resetId, RecoveryKeyResetCancellationAuthority.Device(device ?: device(laptop))),
        )

    private suspend fun ServerStorage.cancelByRecoveryKey(reset: RecoveryKeyResetStatus.Pending, key: Int = 1, epoch: Long = reset.recoveryKeyEpoch) =
        lastDeviceRecovery.cancelRecoveryKeyReset(
            RecoveryKeyResetCancellation(reset.userId, reset.resetId, RecoveryKeyResetCancellationAuthority.RecoveryKey(recoveryKey(key), epoch)),
        )

    private suspend fun ServerStorage.rotation(from: Int, to: Int, epoch: Long, authorizer: DeviceRegistrationState? = null) =
        RecoveryKeyRotationTransition(
            alice, recoveryKey(from), epoch, recoveryKey(to), authorizer ?: device(), RecoveryKeyRotationId(ByteArray(32) { (to + it).toByte() }),
            nonce(1000 + to), now, now - 5.minutes, now + 1.minutes,
        )

    private suspend fun ServerStorage.revocation(of: Int, epoch: Long, authorizer: DeviceRegistrationState? = null) =
        RecoveryKeyRevocationTransition(
            alice, recoveryKey(of), epoch, authorizer ?: device(), RecoveryKeyRevocationId(ByteArray(32) { (of + it).toByte() }),
            nonce(2000 + of), now, now - 5.minutes, now + 2.minutes,
        )

    private suspend fun ServerStorage.challenge(target: DeviceAddress = phone, seed: Int = 1, at: Instant = now): StoredLastDeviceRecoveryChallenge =
        assertIs<LastDeviceRecoveryChallengeIssue.Issued>(
            lastDeviceRecovery.issueChallenge(
                LastDeviceRecoveryChallengeRequest(
                    target, LastDeviceRecoveryChallengeId(ByteArray(16) { (seed * 5 + it).toByte() }),
                    ByteArray(32) { (seed * 19 + it).toByte() }, at, at + 5.minutes,
                ),
            ),
        ).challenge

    private suspend fun ServerStorage.lastDeviceRecovery(challenge: StoredLastDeviceRecoveryChallenge, recoveryKey: Int, replacement: Int, at: Instant) =
        devices.replaceForLastDeviceRecovery(
            LastDeviceRecoveryReplacement(
                device(challenge.challenge.target), recoveryKey(recoveryKey), challenge.challenge.id, challenge.challenge.nonce,
                key(replacement), LastDeviceRecoveryId(ByteArray(32) { (replacement + it).toByte() }), at,
            ),
        )

    private suspend fun ServerStorage.assertActive(key: Int, epoch: Long, installedAt: Instant, completion: Int? = null) {
        val state = recoveryState()
        assertEquals(RecoveryKeyStatus.ACTIVE, state.status)
        assertEquals(epoch, state.epoch)
        assertContentEquals(recoveryKey(key), state.publicKey)
        assertEquals(installedAt, state.installedAt)
        assertEquals(completion?.let(::completionId), state.resetCompletionId)
        if (completion != null) {
            assertNull(state.rotationId)
            assertNull(state.revocationId)
        }
    }

    private suspend fun ServerStorage.pending(userId: UserId = alice) = lastDeviceRecovery.pendingRecoveryKeyReset(userId)

    @Test
    fun aResetIsRequestedOnlyForAnActiveKeyAndBindsIt() = runTest {
        val storage = registered()
        assertNull(storage.pending())
        val reset = storage.created()
        assertEquals(resetId(1), reset.resetId)
        assertEquals(phone, reset.requestedBy)
        assertEquals(now, reset.requestedAt)
        assertEquals(eligible, reset.eligibleAt)
        assertEquals(1, reset.recoveryKeyEpoch)
        assertContentEquals(recoveryKey(1), reset.recoveryPublicKey)
        assertEquals(reset, storage.pending())
        assertNull(storage.pending(bobPhone.userId), "per user")
        storage.assertActive(1, epoch = 1, installedAt = now)

        val unconfigured = newStorage()
        assertTrue(unconfigured.devices.register(DeviceRegistration(phone, key(1)), now))
        assertSame(RecoveryKeyResetRequestResult.NotConfigured, unconfigured.request())
        assertNull(unconfigured.pending())

        val revoked = registered()
        assertEquals(RecoveryKeyRevocationResult.REVOKED, revoked.lastDeviceRecovery.revokeRecoveryKey(revoked.revocation(1, epoch = 1)))
        assertSame(RecoveryKeyResetRequestResult.NotConfigured, revoked.request())
        assertNull(revoked.pending())
    }

    @Test
    fun aRepeatedRequestReturnsThePendingResetUnchanged() = runTest {
        val storage = registered()
        val reset = storage.created()
        // Later, by another device, even after eligibility: the delay never restarts or shortens.
        for (at in listOf(now + 1.hours, eligible, eligible + 1.days)) {
            val again = assertIs<RecoveryKeyResetRequestResult.Existing>(storage.request(laptop, id = 2, at = at, eligibleAt = at + 1.milliseconds))
            assertEquals(reset, again.reset)
        }
        assertEquals(reset, storage.pending())
    }

    @Test
    fun aRequestByAChangedRegistrationConflicts() = runTest {
        val storage = registered()
        val stale = storage.device()
        assertEquals(
            RotationReplacementResult.REPLACED,
            storage.devices.replaceForRotation(
                RotationReplacement(stale, key(2), DeviceAuthenticationRotationId(ByteArray(32)), nonce(9), now, now - 5.minutes, now),
            ),
        )
        val result = storage.lastDeviceRecovery.requestRecoveryKeyReset(RecoveryKeyResetRequest(stale, resetId(1), now, eligible))
        assertSame(RecoveryKeyResetRequestResult.Conflict, result)
        assertNull(storage.pending())
    }

    @Test
    fun completionOnlyFromTheEligibilityTime() = runTest {
        val storage = registered()
        val reset = storage.created()
        assertEquals(RecoveryKeyResetCompletionResult.NOT_YET_ELIGIBLE, storage.complete(reset, 2, at = now))
        assertEquals(RecoveryKeyResetCompletionResult.NOT_YET_ELIGIBLE, storage.complete(reset, 2, at = eligible - 1.milliseconds))
        storage.assertActive(1, epoch = 1, installedAt = now)
        assertEquals(reset, storage.pending())

        val challenge = storage.challenge(laptop, at = eligible)
        assertEquals(RecoveryKeyResetCompletionResult.COMPLETED, storage.complete(reset, 2, at = eligible))
        storage.assertActive(2, epoch = 2, installedAt = eligible, completion = 2)
        assertEquals(eligible, storage.recoveryState().transitionedAt)
        assertNull(storage.pending())
        assertNull(storage.lastDeviceRecovery.challenge(laptop), "completion removes every challenge of the user")
        assertEquals(
            LastDeviceRecoveryReplacementResult.NOT_CONFIGURED,
            storage.lastDeviceRecovery(challenge, recoveryKey = 1, replacement = 5, at = eligible),
        )
        // New challenges bind the new key's epoch.
        assertEquals(2, storage.challenge(laptop, seed = 2, at = eligible).recoveryKeyEpoch)
    }

    @Test
    fun completionAfterTheEligibilityTimeUsesTheCompletionTime() = runTest {
        val storage = registered()
        val reset = storage.created()
        val later = eligible + 3.days
        assertEquals(RecoveryKeyResetCompletionResult.COMPLETED, storage.complete(reset, 2, at = later))
        storage.assertActive(2, epoch = 2, installedAt = later, completion = 2)
    }

    @Test
    fun exactRetriesAreRecognizedAndWriteNothing() = runTest {
        val storage = registered()
        val reset = storage.created()
        val completion = storage.completion(reset, 2)
        assertEquals(RecoveryKeyResetCompletionResult.COMPLETED, storage.lastDeviceRecovery.completeRecoveryKeyReset(completion))
        repeat(3) {
            assertEquals(RecoveryKeyResetCompletionResult.ALREADY_APPLIED, storage.lastDeviceRecovery.completeRecoveryKeyReset(completion))
        }
        storage.assertActive(2, epoch = 2, installedAt = eligible, completion = 2)
        // A different completion of the same, completed reset is not a retry.
        assertEquals(RecoveryKeyResetCompletionResult.NOT_PENDING, storage.complete(reset, 3))
        assertEquals(RecoveryKeyResetCompletionResult.NOT_PENDING, storage.complete(reset, 2, id = 7))
        storage.assertActive(2, epoch = 2, installedAt = eligible, completion = 2)
    }

    @Test
    fun staleOrMismatchingCompletionsConflict() = runTest {
        val storage = registered()
        val reset = storage.created()
        assertEquals(RecoveryKeyResetCompletionResult.NOT_PENDING, storage.complete(storage.otherReset(reset, id = 9), 2))
        assertEquals(RecoveryKeyResetCompletionResult.CONFLICT, storage.complete(storage.otherReset(reset, epoch = 2), 2))
        assertEquals(RecoveryKeyResetCompletionResult.CONFLICT, storage.complete(storage.otherReset(reset, key = 3), 2))
        assertEquals(RecoveryKeyResetCompletionResult.CONFLICT, storage.complete(storage.otherReset(reset, requestedAt = now + 1.milliseconds), 2))
        assertEquals(RecoveryKeyResetCompletionResult.CONFLICT, storage.complete(storage.otherReset(reset, eligibleAt = now + 1.milliseconds), 2, at = eligible))
        assertEquals(RecoveryKeyResetCompletionResult.CONFLICT, storage.complete(reset, 1), "the new key must differ")
        // A completing device whose registration changed.
        val stale = storage.device(laptop)
        storage.devices.replaceForRotation(
            RotationReplacement(stale, key(101), DeviceAuthenticationRotationId(ByteArray(32) { 1 }), nonce(8), now, now - 5.minutes, now),
        )
        assertEquals(RecoveryKeyResetCompletionResult.CONFLICT, storage.complete(reset, 2, completer = stale))
        storage.assertActive(1, epoch = 1, installedAt = now)
        assertEquals(reset, storage.pending())
        assertEquals(RecoveryKeyResetCompletionResult.COMPLETED, storage.complete(reset, 2))
    }

    @Test
    fun aResetBoundToAnOlderStateNeverApplies() = runTest {
        val storage = registered()
        val reset = storage.created()
        // The state moves on behind the storage's back (no transition removed the reset).
        setRecoveryKeyEpoch(storage, alice, 7)
        assertEquals(RecoveryKeyResetCompletionResult.CONFLICT, storage.complete(reset, 2))
        assertEquals(RecoveryKeyResetCancellationResult.CONFLICT, storage.cancelByRecoveryKey(reset))
        assertEquals(7, storage.recoveryState().epoch)
        assertContentEquals(recoveryKey(1), storage.recoveryState().publicKey)
        assertFailsWith<IllegalStateException> { storage.pending() }
    }

    private fun ServerStorage.otherReset(
        reset: RecoveryKeyResetStatus.Pending,
        id: Int? = null,
        epoch: Long = reset.recoveryKeyEpoch,
        key: Int? = null,
        requestedAt: Instant = reset.requestedAt,
        eligibleAt: Instant = reset.eligibleAt,
    ) = RecoveryKeyResetStatus.Pending(
        id?.let(::resetId) ?: reset.resetId, reset.requestedBy, requestedAt, eligibleAt, epoch,
        key?.let(::recoveryKey) ?: reset.recoveryPublicKey,
    )

    @Test
    fun theEpochGrowsAndNeverWraps() = runTest {
        val storage = registered()
        val first = storage.created()
        assertEquals(RecoveryKeyResetCompletionResult.COMPLETED, storage.complete(first, 2))
        val second = storage.created(id = 2, at = eligible)
        assertEquals(2, second.recoveryKeyEpoch)
        assertContentEquals(recoveryKey(2), second.recoveryPublicKey)
        assertEquals(RecoveryKeyResetCompletionResult.COMPLETED, storage.complete(second, 3))
        storage.assertActive(3, epoch = 3, installedAt = second.eligibleAt, completion = 3)

        // At the maximum a pending reset can never complete: the request is refused.
        setRecoveryKeyEpoch(storage, alice, Long.MAX_VALUE)
        assertSame(RecoveryKeyResetRequestResult.EpochExhausted, storage.request(id = 3))
        assertNull(storage.pending())

        // And a reset pending when the epoch reaches the maximum fails closed on completion.
        val boundary = registered()
        setRecoveryKeyEpoch(boundary, alice, Long.MAX_VALUE - 1)
        val almost = boundary.created()
        assertEquals(RecoveryKeyResetCompletionResult.COMPLETED, boundary.complete(almost, 2))
        assertEquals(Long.MAX_VALUE, boundary.recoveryState().epoch)
        assertSame(RecoveryKeyResetRequestResult.EpochExhausted, boundary.request(id = 2, at = eligible))
    }

    @Test
    fun anyCurrentDeviceOfTheUserCancels() = runTest {
        val storage = registered()
        val challenge = storage.challenge()
        val reset = storage.created()
        assertEquals(RecoveryKeyResetCancellationResult.CANCELLED, storage.cancelByDevice(reset))
        assertNull(storage.pending())
        storage.assertActive(1, epoch = 1, installedAt = now)
        assertEquals(challenge.challenge.id, storage.lastDeviceRecovery.challenge(phone)?.challenge?.id, "a cancellation keeps the challenges")
        assertEquals(RecoveryKeyResetCancellationResult.NOT_PENDING, storage.cancelByDevice(reset), "no tombstone: a retry is NOT_PENDING")
        assertEquals(RecoveryKeyResetCompletionResult.NOT_PENDING, storage.complete(reset, 2))

        // A new request after a cancellation starts a new, full delay.
        val next = storage.created(laptop, id = 2, at = now + 1.days)
        assertEquals(resetId(2), next.resetId)
        assertEquals(now + 1.days + delay, next.eligibleAt)

        // Only the current registration of a device cancels.
        val stale = storage.device(laptop)
        storage.devices.replaceForRotation(
            RotationReplacement(stale, key(101), DeviceAuthenticationRotationId(ByteArray(32) { 2 }), nonce(7), now, now - 5.minutes, now),
        )
        assertEquals(RecoveryKeyResetCancellationResult.CONFLICT, storage.cancelByDevice(next, stale))
        assertEquals(RecoveryKeyResetCancellationResult.NOT_PENDING, storage.cancelByDevice(storage.otherReset(next, id = 5)))
        assertEquals(next, storage.pending())
        assertEquals(RecoveryKeyResetCancellationResult.CANCELLED, storage.cancelByDevice(next, storage.device()))
    }

    @Test
    fun theCurrentRecoveryKeyCancels() = runTest {
        val storage = registered()
        val challenge = storage.challenge()
        val reset = storage.created()
        assertEquals(RecoveryKeyResetCancellationResult.CONFLICT, storage.cancelByRecoveryKey(reset, key = 2))
        assertEquals(RecoveryKeyResetCancellationResult.CONFLICT, storage.cancelByRecoveryKey(reset, epoch = 2))
        assertEquals(reset, storage.pending())
        assertEquals(RecoveryKeyResetCancellationResult.CANCELLED, storage.cancelByRecoveryKey(reset))
        assertNull(storage.pending())
        storage.assertActive(1, epoch = 1, installedAt = now)
        assertEquals(challenge.challenge.id, storage.lastDeviceRecovery.challenge(phone)?.challenge?.id)
    }

    @Test
    fun aCompletedResetCannotBeCancelledOrRolledBack() = runTest {
        val storage = registered()
        val reset = storage.created()
        assertEquals(RecoveryKeyResetCompletionResult.COMPLETED, storage.complete(reset, 2))
        assertEquals(RecoveryKeyResetCancellationResult.NOT_PENDING, storage.cancelByRecoveryKey(reset))
        assertEquals(RecoveryKeyResetCancellationResult.NOT_PENDING, storage.cancelByDevice(reset))
        storage.assertActive(2, epoch = 2, installedAt = eligible, completion = 2)
    }

    @Test
    fun everyOtherRecoveryKeyTransitionRemovesTheReset() = runTest {
        val rotated = registered()
        val reset = rotated.created()
        assertEquals(RecoveryKeyRotationResult.ROTATED, rotated.lastDeviceRecovery.rotateRecoveryKey(rotated.rotation(1, 3, epoch = 1)))
        assertNull(rotated.pending())
        assertEquals(RecoveryKeyResetCompletionResult.NOT_PENDING, rotated.complete(reset, 2), "a stale reset never overwrites R3")
        assertEquals(RecoveryKeyResetCancellationResult.NOT_PENDING, rotated.cancelByRecoveryKey(reset))
        assertContentEquals(recoveryKey(3), rotated.recoveryState().publicKey)
        assertEquals(2, rotated.recoveryState().epoch)
        assertNull(rotated.recoveryState().resetCompletionId)

        val revoked = registered()
        val revokedReset = revoked.created()
        assertEquals(RecoveryKeyRevocationResult.REVOKED, revoked.lastDeviceRecovery.revokeRecoveryKey(revoked.revocation(1, epoch = 1)))
        assertNull(revoked.pending())
        assertEquals(RecoveryKeyResetCompletionResult.NOT_PENDING, revoked.complete(revokedReset, 2))
        assertEquals(RecoveryKeyStatus.REVOKED, revoked.recoveryState().status)
        // Re-registration after the revocation starts without a reset, at the next epoch.
        assertTrue(revoked.lastDeviceRecovery.registerRecoveryKey(alice, recoveryKey(4), now))
        assertNull(revoked.pending())
        assertEquals(3, revoked.recoveryState().epoch)
        assertEquals(RecoveryKeyResetCompletionResult.NOT_PENDING, revoked.complete(revokedReset, 2))
        assertContentEquals(recoveryKey(4), revoked.recoveryState().publicKey)
    }

    @Test
    fun aRotationAfterACompletedResetClearsTheCompletionId() = runTest {
        val storage = registered()
        assertEquals(RecoveryKeyResetCompletionResult.COMPLETED, storage.complete(storage.created(), 2))
        assertEquals(RecoveryKeyRotationResult.ROTATED, storage.lastDeviceRecovery.rotateRecoveryKey(storage.rotation(2, 3, epoch = 2)))
        val state = storage.recoveryState()
        assertEquals(3, state.epoch)
        assertNull(state.resetCompletionId)
        assertNotNull(state.rotationId)
    }

    @Test
    fun theRequestLeavesChallengesAndLastDeviceRecoveryWithTheCurrentKey() = runTest {
        val storage = registered()
        val challenge = storage.challenge()
        storage.created()
        assertEquals(challenge.challenge.id, storage.lastDeviceRecovery.challenge(phone)?.challenge?.id)
        // The current key stays authoritative during the delay.
        assertEquals(LastDeviceRecoveryReplacementResult.REPLACED, storage.lastDeviceRecovery(challenge, recoveryKey = 1, replacement = 5, at = now + 1.minutes))
        assertNotNull(storage.pending(), "a device recovery does not touch the reset")
    }

    @Test
    fun resetsLeaveDevicesPreKeysMailboxAndNoncesAlone() = runTest {
        val storage = registered()
        val signed = PublicSignedPreKey(SignedPreKeyId(1), ByteArray(64) { 5 }, ByteArray(64) { 6 })
        val publication = PreKeyPublication(phone, ByteArray(64) { 4 }, signed, listOf(1, 2).map { PublicOneTimePreKey(OneTimePreKeyId(it), ByteArray(64) { _ -> it.toByte() }) })
        storage.preKeys.publish(publication)
        assertEquals(OneTimePreKeyId(1), storage.preKeys.consumePreKeyBundle(phone)?.oneTimePreKey?.id)
        storage.mailboxes.enqueue(EncryptedEnvelope(MessageId("m1"), bobPhone, phone, payload = byteArrayOf(1)))
        assertTrue(storage.authenticationNonces.claim(laptop, nonce(1).bytes, now, now - 5.minutes))
        val devicesBefore = listOf(phone, laptop, bobPhone).map { storage.device(it) }

        val cancelled = storage.created()
        assertEquals(RecoveryKeyResetCancellationResult.CANCELLED, storage.cancelByDevice(cancelled))
        val reset = storage.created(id = 2)
        assertEquals(RecoveryKeyResetCompletionResult.COMPLETED, storage.complete(reset, 2))

        val devicesAfter = listOf(phone, laptop, bobPhone).map { storage.device(it) }
        for ((before, after) in devicesBefore.zip(devicesAfter)) {
            assertContentEquals(before.registration.publicKey, after.registration.publicKey)
            assertEquals(before.authEpoch, after.authEpoch)
            assertEquals(before.authKeyInstalledAt, after.authKeyInstalledAt)
            assertEquals(before.recoveryId, after.recoveryId)
            assertEquals(before.rotationId, after.rotationId)
            assertEquals(before.lastDeviceRecoveryId, after.lastDeviceRecoveryId)
        }
        assertEquals(1, storage.preKeys.oneTimePreKeyCount(phone))
        storage.preKeys.publish(publication)
        assertEquals(1, storage.preKeys.oneTimePreKeyCount(phone), "tombstone kept")
        assertEquals(listOf("m1"), storage.mailboxes.drain(phone).map { it.id.value })
        assertTrue(!storage.authenticationNonces.claim(laptop, nonce(1).bytes, now, now - 5.minutes), "nonces are never cleared")
        assertContentEquals(recoveryKey(50), storage.lastDeviceRecovery.recoveryKey(bobPhone.userId))
        assertNull(storage.pending(bobPhone.userId))
    }

    @Test
    fun valuesAreCopied() = runTest {
        val storage = registered()
        val reset = storage.created()
        reset.recoveryPublicKey.fill(0)
        assertContentEquals(recoveryKey(1), assertNotNull(storage.pending()).recoveryPublicKey)
        val transition = storage.completion(reset, 2)
        transition.newPublicKey.fill(0)
        assertEquals(RecoveryKeyResetCompletionResult.COMPLETED, storage.lastDeviceRecovery.completeRecoveryKeyReset(transition))
        storage.assertActive(2, epoch = 2, installedAt = eligible, completion = 2)
    }

    @Test
    fun concurrentIdenticalRequestsCreateOneReset() = runTest {
        repeat(10) {
            val storage = registered()
            val requester = storage.device()
            val results = withContext(Dispatchers.Default) {
                List(32) { i ->
                    async {
                        storage.lastDeviceRecovery.requestRecoveryKeyReset(
                            RecoveryKeyResetRequest(requester, resetId(i + 1), now + (i * 10).milliseconds, now + (i * 10).milliseconds + delay),
                        )
                    }
                }.awaitAll()
            }
            val created = results.filterIsInstance<RecoveryKeyResetRequestResult.Created>()
            assertEquals(1, created.size)
            assertEquals(31, results.count { it is RecoveryKeyResetRequestResult.Existing })
            val winner = created.single().reset
            for (existing in results.filterIsInstance<RecoveryKeyResetRequestResult.Existing>()) assertEquals(winner, existing.reset)
            assertEquals(winner, storage.pending())
        }
    }

    @Test
    fun concurrentRequestsOfTwoDevicesCreateOneReset() = runTest {
        repeat(20) {
            val storage = registered()
            val (a, b) = withContext(Dispatchers.Default) {
                val x = async { storage.request(phone, id = 1) }
                val y = async { storage.request(laptop, id = 2) }
                x.await() to y.await()
            }
            val resets = listOf(a, b).map {
                when (it) {
                    is RecoveryKeyResetRequestResult.Created -> it.reset
                    is RecoveryKeyResetRequestResult.Existing -> it.reset
                    else -> error("Unexpected $it")
                }
            }
            assertEquals(1, listOf(a, b).count { it is RecoveryKeyResetRequestResult.Created })
            assertEquals(resets[0], resets[1])
            assertEquals(resets[0], storage.pending())
        }
    }

    @Test
    fun concurrentCompletionAndCancellationHaveExactlyOneWinner() = runTest {
        for (byRecoveryKey in listOf(false, true)) {
            repeat(20) {
                val storage = registered()
                val reset = storage.created()
                val completion = storage.completion(reset, 2)
                val laptopState = storage.device(laptop)
                val (completed, cancelled) = withContext(Dispatchers.Default) {
                    val x = async { storage.lastDeviceRecovery.completeRecoveryKeyReset(completion) }
                    val y = async { if (byRecoveryKey) storage.cancelByRecoveryKey(reset) else storage.cancelByDevice(reset, laptopState) }
                    x.await() to y.await()
                }
                if (completed == RecoveryKeyResetCompletionResult.COMPLETED) {
                    assertEquals(RecoveryKeyResetCancellationResult.NOT_PENDING, cancelled)
                    storage.assertActive(2, epoch = 2, installedAt = eligible, completion = 2)
                } else {
                    assertEquals(RecoveryKeyResetCompletionResult.NOT_PENDING, completed)
                    assertEquals(RecoveryKeyResetCancellationResult.CANCELLED, cancelled)
                    storage.assertActive(1, epoch = 1, installedAt = now)
                }
                assertNull(storage.pending())
            }
        }
    }

    @Test
    fun concurrentCompletionAndRotationOrRevocationHaveExactlyOneWinner() = runTest {
        repeat(20) {
            val storage = registered()
            val reset = storage.created()
            val completion = storage.completion(reset, 2)
            val rotation = storage.rotation(1, 3, epoch = 1)
            val (completed, rotated) = withContext(Dispatchers.Default) {
                val x = async { storage.lastDeviceRecovery.completeRecoveryKeyReset(completion) }
                val y = async { storage.lastDeviceRecovery.rotateRecoveryKey(rotation) }
                x.await() to y.await()
            }
            if (completed == RecoveryKeyResetCompletionResult.COMPLETED) {
                assertEquals(RecoveryKeyRotationResult.CONFLICT, rotated)
                storage.assertActive(2, epoch = 2, installedAt = eligible, completion = 2)
            } else {
                assertEquals(RecoveryKeyResetCompletionResult.NOT_PENDING, completed)
                assertEquals(RecoveryKeyRotationResult.ROTATED, rotated)
                assertContentEquals(recoveryKey(3), storage.recoveryState().publicKey)
                assertEquals(2, storage.recoveryState().epoch)
            }
            assertNull(storage.pending())
        }
        repeat(20) {
            val storage = registered()
            val reset = storage.created()
            val completion = storage.completion(reset, 2)
            val revocation = storage.revocation(1, epoch = 1)
            val (completed, revoked) = withContext(Dispatchers.Default) {
                val x = async { storage.lastDeviceRecovery.completeRecoveryKeyReset(completion) }
                val y = async { storage.lastDeviceRecovery.revokeRecoveryKey(revocation) }
                x.await() to y.await()
            }
            if (completed == RecoveryKeyResetCompletionResult.COMPLETED) {
                assertEquals(RecoveryKeyRevocationResult.CONFLICT, revoked)
                storage.assertActive(2, epoch = 2, installedAt = eligible, completion = 2)
            } else {
                assertEquals(RecoveryKeyResetCompletionResult.NOT_PENDING, completed)
                assertEquals(RecoveryKeyRevocationResult.REVOKED, revoked)
                assertEquals(RecoveryKeyStatus.REVOKED, storage.recoveryState().status)
            }
            assertNull(storage.pending())
        }
    }

    @Test
    fun concurrentRequestAndRotationNeverBindAnObsoleteKey() = runTest {
        repeat(20) {
            val storage = registered()
            val rotation = storage.rotation(1, 3, epoch = 1)
            val (requested, rotated) = withContext(Dispatchers.Default) {
                val x = async { storage.request() }
                val y = async { storage.lastDeviceRecovery.rotateRecoveryKey(rotation) }
                x.await() to y.await()
            }
            assertEquals(RecoveryKeyRotationResult.ROTATED, rotated)
            val reset = storage.pending()
            if (reset != null) {
                // The request committed after the rotation: it bound R3 at epoch 2.
                assertIs<RecoveryKeyResetRequestResult.Created>(requested)
                assertEquals(2, reset.recoveryKeyEpoch)
                assertContentEquals(recoveryKey(3), reset.recoveryPublicKey)
            } else {
                // The request committed first; the rotation removed it.
                assertIs<RecoveryKeyResetRequestResult.Created>(requested)
            }
        }
    }

    @Test
    fun concurrentCancellationAndRotationBothSucceedWithoutRollback() = runTest {
        repeat(20) {
            val storage = registered()
            val reset = storage.created()
            val laptopState = storage.device(laptop)
            val rotation = storage.rotation(1, 3, epoch = 1)
            val (cancelled, rotated) = withContext(Dispatchers.Default) {
                val x = async { storage.cancelByDevice(reset, laptopState) }
                val y = async { storage.lastDeviceRecovery.rotateRecoveryKey(rotation) }
                x.await() to y.await()
            }
            assertEquals(RecoveryKeyRotationResult.ROTATED, rotated)
            assertTrue(cancelled == RecoveryKeyResetCancellationResult.CANCELLED || cancelled == RecoveryKeyResetCancellationResult.NOT_PENDING)
            assertNull(storage.pending())
            assertContentEquals(recoveryKey(3), storage.recoveryState().publicKey)
        }
    }

    @Test
    fun completionAndLastDeviceRecoveryInBothOrders() = runTest {
        // Another device recovers first: the recovery key state is unchanged and the completion still applies.
        val recoveryFirst = registered()
        val reset = recoveryFirst.created()
        val challenge = recoveryFirst.challenge(phone, at = eligible)
        assertEquals(LastDeviceRecoveryReplacementResult.REPLACED, recoveryFirst.lastDeviceRecovery(challenge, 1, 5, at = eligible))
        assertEquals(RecoveryKeyResetCompletionResult.COMPLETED, recoveryFirst.complete(reset, 2))

        // The completing device itself recovers first: its old registration no longer completes.
        val completerRecovered = registered()
        val reset2 = completerRecovered.created()
        val stale = completerRecovered.device(laptop)
        val laptopChallenge = completerRecovered.challenge(laptop, at = eligible)
        assertEquals(LastDeviceRecoveryReplacementResult.REPLACED, completerRecovered.lastDeviceRecovery(laptopChallenge, 1, 105, at = eligible))
        assertEquals(RecoveryKeyResetCompletionResult.CONFLICT, completerRecovered.complete(reset2, 2, completer = stale))
        assertEquals(RecoveryKeyResetCompletionResult.COMPLETED, completerRecovered.complete(reset2, 2, completer = completerRecovered.device(laptop)))

        // The completion first: the R1 challenge is gone and R1 recovers nothing.
        val completionFirst = registered()
        val reset3 = completionFirst.created()
        val oldChallenge = completionFirst.challenge(phone, at = eligible)
        assertEquals(RecoveryKeyResetCompletionResult.COMPLETED, completionFirst.complete(reset3, 2))
        assertEquals(LastDeviceRecoveryReplacementResult.NOT_CONFIGURED, completionFirst.lastDeviceRecovery(oldChallenge, 1, 5, at = eligible))
        val fresh = completionFirst.challenge(phone, seed = 3, at = eligible)
        assertEquals(2, fresh.recoveryKeyEpoch)
        assertEquals(LastDeviceRecoveryReplacementResult.REPLACED, completionFirst.lastDeviceRecovery(fresh, 2, 5, at = eligible))

        // Concurrently, the completer being the recovered device: exactly one wins.
        repeat(20) {
            val storage = registered()
            val r = storage.created()
            val completion = storage.completion(r, 2)
            val c = storage.challenge(laptop, at = eligible)
            val (completed, recovered) = withContext(Dispatchers.Default) {
                val x = async { storage.lastDeviceRecovery.completeRecoveryKeyReset(completion) }
                val y = async { storage.lastDeviceRecovery(c, 1, 105, at = eligible) }
                x.await() to y.await()
            }
            if (completed == RecoveryKeyResetCompletionResult.COMPLETED) {
                assertEquals(LastDeviceRecoveryReplacementResult.NOT_CONFIGURED, recovered)
                storage.assertActive(2, epoch = 2, installedAt = eligible, completion = 2)
            } else {
                assertEquals(RecoveryKeyResetCompletionResult.CONFLICT, completed)
                assertEquals(LastDeviceRecoveryReplacementResult.REPLACED, recovered)
                storage.assertActive(1, epoch = 1, installedAt = now)
                assertNotNull(storage.pending())
            }
        }
    }
}
