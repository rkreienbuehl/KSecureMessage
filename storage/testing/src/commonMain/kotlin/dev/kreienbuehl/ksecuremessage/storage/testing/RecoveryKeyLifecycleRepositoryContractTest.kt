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
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryChallengeId
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryId
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRevocationId
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRotationId
import dev.kreienbuehl.ksecuremessage.protocol.RequestNonce
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationState
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryChallengeIssue
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryChallengeRequest
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryKeyException
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryReplacement
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryReplacementResult
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
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/**
 * Recovery key lifecycle behavior every server storage must have
 * (docs/recovery-key-lifecycle.md): a per-user recovery key epoch that
 * starts at 1, grows by one with every rotation, revocation and registration
 * after a revocation, never decreases and never wraps; rotation and
 * revocation as compare-and-set on the recovery key state and the authorizing
 * device's registration, together with the nonce claim and the removal of
 * every challenge of the user; exact retries recognized by the stored
 * transition ID; stale transitions rejected; and nothing else touched.
 *
 * Signatures and ServerAuth are the service's job and not checked here.
 */
abstract class RecoveryKeyLifecycleRepositoryContractTest {
    /** Returns a new, empty storage. */
    protected abstract suspend fun newStorage(): ServerStorage

    /** Sets [userId]'s recovery key epoch directly, for the exhaustion boundary. */
    protected abstract suspend fun setRecoveryKeyEpoch(storage: ServerStorage, userId: UserId, epoch: Long)

    private val phone = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val laptop = DeviceAddress(UserId("alice"), DeviceId("laptop"))
    private val bobPhone = DeviceAddress(UserId("bob"), DeviceId("phone"))
    private val alice = phone.userId
    private val now = Instant.fromEpochMilliseconds(1_767_225_600_000)

    private fun key(seed: Int) = ByteArray(32) { (seed * 7 + it).toByte() }
    private fun recoveryKey(seed: Int) = ByteArray(32) { (seed * 11 + it + 1).toByte() }
    private fun rotationId(seed: Int) = RecoveryKeyRotationId(ByteArray(32) { (seed * 13 + it).toByte() })
    private fun revocationId(seed: Int) = RecoveryKeyRevocationId(ByteArray(32) { (seed * 17 + it).toByte() })
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

    private suspend fun ServerStorage.rotation(
        from: Int,
        to: Int,
        epoch: Long,
        id: Int = to,
        nonce: Int = 1000 + id,
        authorizer: DeviceRegistrationState? = null,
        at: Instant = now + 1.minutes,
    ) = RecoveryKeyRotationTransition(
        userId = alice,
        expectedPublicKey = recoveryKey(from),
        expectedEpoch = epoch,
        newPublicKey = recoveryKey(to),
        expectedAuthorizer = authorizer ?: device(),
        rotationId = rotationId(id),
        nonce = nonce(nonce),
        timestamp = now,
        pruneBefore = now - 5.minutes,
        now = at,
    )

    private suspend fun ServerStorage.revocation(
        of: Int,
        epoch: Long,
        id: Int = of,
        nonce: Int = 2000 + id,
        authorizer: DeviceRegistrationState? = null,
        at: Instant = now + 2.minutes,
    ) = RecoveryKeyRevocationTransition(
        userId = alice,
        expectedPublicKey = recoveryKey(of),
        expectedEpoch = epoch,
        expectedAuthorizer = authorizer ?: device(),
        revocationId = revocationId(id),
        nonce = nonce(nonce),
        timestamp = now,
        pruneBefore = now - 5.minutes,
        now = at,
    )

    private suspend fun ServerStorage.issue(target: DeviceAddress = phone, seed: Int = 1, at: Instant = now): LastDeviceRecoveryChallengeIssue =
        lastDeviceRecovery.issueChallenge(
            LastDeviceRecoveryChallengeRequest(
                target, LastDeviceRecoveryChallengeId(ByteArray(16) { (seed * 5 + it).toByte() }), ByteArray(32) { (seed * 19 + it).toByte() },
                at, at + 5.minutes,
            ),
        )

    private suspend fun ServerStorage.challenge(target: DeviceAddress = phone, seed: Int = 1, at: Instant = now): StoredLastDeviceRecoveryChallenge =
        assertIs<LastDeviceRecoveryChallengeIssue.Issued>(issue(target, seed, at)).challenge

    private suspend fun ServerStorage.lastDeviceRecovery(
        challenge: StoredLastDeviceRecoveryChallenge,
        recoveryKey: Int,
        replacement: Int,
        at: Instant = now + 1.minutes,
    ) = devices.replaceForLastDeviceRecovery(
        LastDeviceRecoveryReplacement(
            device(challenge.challenge.target), recoveryKey(recoveryKey), challenge.challenge.id, challenge.challenge.nonce,
            key(replacement), LastDeviceRecoveryId(ByteArray(32) { (replacement + it).toByte() }), at,
        ),
    )

    private suspend fun ServerStorage.assertActive(key: Int, epoch: Long, installedAt: Instant, rotation: Int? = null) {
        val state = recoveryState()
        assertEquals(RecoveryKeyStatus.ACTIVE, state.status)
        assertEquals(epoch, state.epoch)
        assertContentEquals(recoveryKey(key), state.publicKey)
        assertContentEquals(recoveryKey(key), lastDeviceRecovery.recoveryKey(alice))
        assertEquals(installedAt, state.installedAt)
        assertEquals(rotation?.let(::rotationId), state.rotationId)
        assertNull(state.revocationId)
    }

    private suspend fun ServerStorage.assertRevoked(epoch: Long, revokedAt: Instant, revocation: Int) {
        val state = recoveryState()
        assertEquals(RecoveryKeyStatus.REVOKED, state.status)
        assertEquals(epoch, state.epoch)
        assertNull(state.publicKey)
        assertNull(state.installedAt)
        assertNull(lastDeviceRecovery.recoveryKey(alice))
        assertEquals(revokedAt, state.transitionedAt)
        assertEquals(revocationId(revocation), state.revocationId)
        assertNull(state.rotationId)
    }

    @Test
    fun firstRegistrationStartsAtEpochOne() = runTest {
        val storage = newStorage()
        assertNull(storage.lastDeviceRecovery.recoveryKeyState(alice), "never configured")
        assertTrue(storage.lastDeviceRecovery.registerRecoveryKey(alice, recoveryKey(1), now))
        storage.assertActive(1, epoch = 1, installedAt = now)
        assertEquals(now, storage.recoveryState().transitionedAt)

        assertFalse(storage.lastDeviceRecovery.registerRecoveryKey(alice, recoveryKey(1), now + 1.days), "idempotent")
        storage.assertActive(1, epoch = 1, installedAt = now)
        assertFailsWith<LastDeviceRecoveryKeyException.Conflict> {
            storage.lastDeviceRecovery.registerRecoveryKey(alice, recoveryKey(2), now + 1.days)
        }
        storage.assertActive(1, epoch = 1, installedAt = now)
    }

    @Test
    fun rotationReplacesTheKeyOnceAndExactRetriesChangeNothing() = runTest {
        val storage = registered()
        val rotation = storage.rotation(1, 2, epoch = 1)
        assertEquals(RecoveryKeyRotationResult.ROTATED, storage.lastDeviceRecovery.rotateRecoveryKey(rotation))
        storage.assertActive(2, epoch = 2, installedAt = now + 1.minutes, rotation = 2)
        assertEquals(now + 1.minutes, storage.recoveryState().transitionedAt)

        // The response was lost: the same rotation again, also later and with another request nonce.
        assertEquals(RecoveryKeyRotationResult.ALREADY_APPLIED, storage.lastDeviceRecovery.rotateRecoveryKey(rotation))
        assertEquals(
            RecoveryKeyRotationResult.ALREADY_APPLIED,
            storage.lastDeviceRecovery.rotateRecoveryKey(storage.rotation(1, 2, epoch = 1, nonce = 77, at = now + 1.days)),
        )
        storage.assertActive(2, epoch = 2, installedAt = now + 1.minutes, rotation = 2)

        // Bob's recovery key is independent.
        assertContentEquals(recoveryKey(50), storage.lastDeviceRecovery.recoveryKey(bobPhone.userId))
        assertEquals(1, storage.recoveryState(bobPhone.userId).epoch)
    }

    @Test
    fun rotationNeedsTheCurrentStateAndAChange() = runTest {
        val storage = newStorage()
        assertTrue(storage.devices.register(DeviceRegistration(phone, key(1)), now))
        assertEquals(RecoveryKeyRotationResult.NOT_CONFIGURED, storage.lastDeviceRecovery.rotateRecoveryKey(storage.rotation(1, 2, epoch = 1)))
        assertNull(storage.lastDeviceRecovery.recoveryKeyState(alice))

        assertTrue(storage.lastDeviceRecovery.registerRecoveryKey(alice, recoveryKey(1), now))
        val conflicts = listOf(
            storage.rotation(1, 1, epoch = 1), // same key
            storage.rotation(1, 2, epoch = 2), // wrong epoch
            storage.rotation(1, 2, epoch = 3), // wrong epoch
            storage.rotation(3, 2, epoch = 1), // wrong current key
        )
        for (rotation in conflicts) {
            assertEquals(RecoveryKeyRotationResult.CONFLICT, storage.lastDeviceRecovery.rotateRecoveryKey(rotation), rotation.toString())
        }
        storage.assertActive(1, epoch = 1, installedAt = now)
        // No conflict claimed its nonce.
        assertTrue(storage.authenticationNonces.claim(phone, nonce(1001).bytes, now, now - 5.minutes))
        assertTrue(storage.authenticationNonces.claim(phone, nonce(1002).bytes, now, now - 5.minutes))
    }

    @Test
    fun staleRotationCannotRestoreOldAuthority() = runTest {
        val storage = registered()
        val first = storage.rotation(1, 2, epoch = 1)
        assertEquals(RecoveryKeyRotationResult.ROTATED, storage.lastDeviceRecovery.rotateRecoveryKey(first))
        assertEquals(RecoveryKeyRotationResult.ROTATED, storage.lastDeviceRecovery.rotateRecoveryKey(storage.rotation(2, 3, epoch = 2)))
        // Replaying R1 -> R2 is no exact retry any more (R3 is active) and conflicts.
        assertEquals(RecoveryKeyRotationResult.CONFLICT, storage.lastDeviceRecovery.rotateRecoveryKey(first))
        // Nor can any statement built on R1 or R2 change it.
        assertEquals(RecoveryKeyRotationResult.CONFLICT, storage.lastDeviceRecovery.rotateRecoveryKey(storage.rotation(1, 4, epoch = 1)))
        assertEquals(RecoveryKeyRotationResult.CONFLICT, storage.lastDeviceRecovery.rotateRecoveryKey(storage.rotation(2, 1, epoch = 2)))
        assertEquals(RecoveryKeyRevocationResult.CONFLICT, storage.lastDeviceRecovery.revokeRecoveryKey(storage.revocation(1, epoch = 1)))
        assertEquals(RecoveryKeyRevocationResult.CONFLICT, storage.lastDeviceRecovery.revokeRecoveryKey(storage.revocation(2, epoch = 2)))
        storage.assertActive(3, epoch = 3, installedAt = now + 1.minutes, rotation = 3)
    }

    @Test
    fun theAuthorizingRegistrationMustBeUnchanged() = runTest {
        val storage = registered()
        val authorizer = storage.device()
        // The authorizing device's key is replaced (here by a routine rotation) after it authenticated.
        val rotated = storage.devices.replaceForRotation(
            RotationReplacement(authorizer, key(2), DeviceAuthenticationRotationId(ByteArray(32) { 1 }), nonce(9), now, now - 5.minutes, now),
        )
        assertEquals(RotationReplacementResult.REPLACED, rotated)
        assertEquals(
            RecoveryKeyRotationResult.CONFLICT,
            storage.lastDeviceRecovery.rotateRecoveryKey(storage.rotation(1, 2, epoch = 1, authorizer = authorizer)),
        )
        assertEquals(
            RecoveryKeyRevocationResult.CONFLICT,
            storage.lastDeviceRecovery.revokeRecoveryKey(storage.revocation(1, epoch = 1, authorizer = authorizer)),
        )
        storage.assertActive(1, epoch = 1, installedAt = now)
        // With the current registration it works.
        assertEquals(RecoveryKeyRotationResult.ROTATED, storage.lastDeviceRecovery.rotateRecoveryKey(storage.rotation(1, 2, epoch = 1)))
    }

    @Test
    fun claimedNonceIsAReplayAndStaysClaimed() = runTest {
        val storage = registered()
        assertTrue(storage.authenticationNonces.claim(phone, nonce(5).bytes, now, now - 5.minutes))
        assertEquals(RecoveryKeyRotationResult.REPLAY, storage.lastDeviceRecovery.rotateRecoveryKey(storage.rotation(1, 2, epoch = 1, nonce = 5)))
        assertEquals(RecoveryKeyRevocationResult.REPLAY, storage.lastDeviceRecovery.revokeRecoveryKey(storage.revocation(1, epoch = 1, nonce = 5)))
        storage.assertActive(1, epoch = 1, installedAt = now)

        // The nonce is claimed under the authorizing device, in the ServerAuth namespace, and stays claimed.
        assertEquals(RecoveryKeyRotationResult.ROTATED, storage.lastDeviceRecovery.rotateRecoveryKey(storage.rotation(1, 2, epoch = 1, nonce = 6)))
        assertFalse(storage.authenticationNonces.claim(phone, nonce(6).bytes, now, now - 5.minutes))
        assertTrue(storage.authenticationNonces.claim(laptop, nonce(6).bytes, now, now - 5.minutes), "per device")
    }

    @Test
    fun revocationRemovesTheKeyOnce() = runTest {
        val storage = registered()
        val revocation = storage.revocation(1, epoch = 1)
        assertEquals(RecoveryKeyRevocationResult.REVOKED, storage.lastDeviceRecovery.revokeRecoveryKey(revocation))
        storage.assertRevoked(epoch = 2, revokedAt = now + 2.minutes, revocation = 1)

        // Lost response: the same revocation again changes nothing.
        assertEquals(RecoveryKeyRevocationResult.ALREADY_APPLIED, storage.lastDeviceRecovery.revokeRecoveryKey(revocation))
        assertEquals(
            RecoveryKeyRevocationResult.ALREADY_APPLIED,
            storage.lastDeviceRecovery.revokeRecoveryKey(storage.revocation(1, epoch = 1, nonce = 99, at = now + 1.days)),
        )
        storage.assertRevoked(epoch = 2, revokedAt = now + 2.minutes, revocation = 1)

        // Another revocation or a rotation of the revoked key conflicts; the key never comes back.
        assertEquals(RecoveryKeyRevocationResult.CONFLICT, storage.lastDeviceRecovery.revokeRecoveryKey(storage.revocation(1, epoch = 2, id = 7)))
        assertEquals(RecoveryKeyRotationResult.CONFLICT, storage.lastDeviceRecovery.rotateRecoveryKey(storage.rotation(1, 2, epoch = 2)))
        assertEquals(RecoveryKeyRotationResult.CONFLICT, storage.lastDeviceRecovery.rotateRecoveryKey(storage.rotation(1, 2, epoch = 1)))
        storage.assertRevoked(epoch = 2, revokedAt = now + 2.minutes, revocation = 1)
        assertEquals(LastDeviceRecoveryChallengeIssue.NotConfigured, storage.issue())

        assertEquals(RecoveryKeyRevocationResult.NOT_CONFIGURED, newStorage().lastDeviceRecovery.revokeRecoveryKey(
            RecoveryKeyRevocationTransition(alice, recoveryKey(1), 1, storage.device(), revocationId(1), nonce(1), now, now, now),
        ))
    }

    @Test
    fun registrationAfterRevocationContinuesTheEpoch() = runTest {
        val storage = registered()
        assertEquals(RecoveryKeyRotationResult.ROTATED, storage.lastDeviceRecovery.rotateRecoveryKey(storage.rotation(1, 2, epoch = 1)))
        assertEquals(RecoveryKeyRevocationResult.REVOKED, storage.lastDeviceRecovery.revokeRecoveryKey(storage.revocation(2, epoch = 2)))
        storage.assertRevoked(epoch = 3, revokedAt = now + 2.minutes, revocation = 2)

        assertTrue(storage.lastDeviceRecovery.registerRecoveryKey(alice, recoveryKey(3), now + 1.days))
        storage.assertActive(3, epoch = 4, installedAt = now + 1.days)
        assertEquals(now + 1.days, storage.recoveryState().transitionedAt)
        assertFalse(storage.lastDeviceRecovery.registerRecoveryKey(alice, recoveryKey(3), now + 2.days))
        assertFailsWith<LastDeviceRecoveryKeyException.Conflict> {
            storage.lastDeviceRecovery.registerRecoveryKey(alice, recoveryKey(1), now + 2.days)
        }
        storage.assertActive(3, epoch = 4, installedAt = now + 1.days)

        // The old revocation and rotation are stale now.
        assertEquals(RecoveryKeyRevocationResult.CONFLICT, storage.lastDeviceRecovery.revokeRecoveryKey(storage.revocation(2, epoch = 2)))
        assertEquals(RecoveryKeyRotationResult.CONFLICT, storage.lastDeviceRecovery.rotateRecoveryKey(storage.rotation(1, 2, epoch = 1)))
        // And the new key rotates normally.
        assertEquals(RecoveryKeyRotationResult.ROTATED, storage.lastDeviceRecovery.rotateRecoveryKey(storage.rotation(3, 4, epoch = 4)))
        storage.assertActive(4, epoch = 5, installedAt = now + 1.minutes, rotation = 4)
    }

    @Test
    fun rotationAndRevocationInvalidateEveryChallengeOfTheUser() = runTest {
        val storage = registered()
        val phoneChallenge = storage.challenge(phone, 1)
        storage.challenge(laptop, 2)
        val bobChallenge = storage.challenge(bobPhone, 3)
        assertEquals(1, phoneChallenge.recoveryKeyEpoch)

        assertEquals(RecoveryKeyRotationResult.ROTATED, storage.lastDeviceRecovery.rotateRecoveryKey(storage.rotation(1, 2, epoch = 1)))
        assertNull(storage.lastDeviceRecovery.challenge(phone))
        assertNull(storage.lastDeviceRecovery.challenge(laptop))
        assertEquals(bobChallenge.challenge.id, storage.lastDeviceRecovery.challenge(bobPhone)?.challenge?.id, "other users keep theirs")

        // The old challenge works with neither the old nor the new recovery key.
        assertEquals(LastDeviceRecoveryReplacementResult.NOT_CONFIGURED, storage.lastDeviceRecovery(phoneChallenge, recoveryKey = 1, replacement = 5))
        assertEquals(LastDeviceRecoveryReplacementResult.CHALLENGE_INVALID, storage.lastDeviceRecovery(phoneChallenge, recoveryKey = 2, replacement = 5))
        assertContentEquals(key(1), storage.device().registration.publicKey)

        // A new challenge is issued under the new epoch and works with the new key.
        val fresh = storage.challenge(phone, 4, at = now + 1.minutes)
        assertEquals(2, fresh.recoveryKeyEpoch)
        assertEquals(LastDeviceRecoveryReplacementResult.REPLACED, storage.lastDeviceRecovery(fresh, recoveryKey = 2, replacement = 5, at = now + 2.minutes))

        // Revocation removes the challenges too, and no new one is issued.
        storage.challenge(laptop, 5, at = now + 2.minutes)
        assertEquals(RecoveryKeyRevocationResult.REVOKED, storage.lastDeviceRecovery.revokeRecoveryKey(storage.revocation(2, epoch = 2, authorizer = storage.device(laptop))))
        assertNull(storage.lastDeviceRecovery.challenge(laptop))
        assertEquals(LastDeviceRecoveryChallengeIssue.NotConfigured, storage.issue(laptop, 6, at = now + 3.minutes))
        assertEquals(bobChallenge.challenge.id, storage.lastDeviceRecovery.challenge(bobPhone)?.challenge?.id)
    }

    @Test
    fun aChallengeFromBeforeARevocationIsDeadAfterReRegistration() = runTest {
        val storage = registered()
        val old = storage.challenge(phone, 1)
        assertEquals(RecoveryKeyRevocationResult.REVOKED, storage.lastDeviceRecovery.revokeRecoveryKey(storage.revocation(1, epoch = 1)))
        assertEquals(LastDeviceRecoveryReplacementResult.NOT_CONFIGURED, storage.lastDeviceRecovery(old, recoveryKey = 1, replacement = 5))
        // Even the same key registered again does not revive the old challenge: it was removed and the epoch moved on.
        assertTrue(storage.lastDeviceRecovery.registerRecoveryKey(alice, recoveryKey(1), now + 1.minutes))
        assertEquals(3, storage.recoveryState().epoch)
        assertEquals(LastDeviceRecoveryReplacementResult.CHALLENGE_INVALID, storage.lastDeviceRecovery(old, recoveryKey = 1, replacement = 5))
        assertEquals(3, storage.challenge(phone, 2, at = now + 1.minutes).recoveryKeyEpoch)
    }

    @Test
    fun epochNeverWraps() = runTest {
        val storage = registered()
        setRecoveryKeyEpoch(storage, alice, Long.MAX_VALUE - 1)
        assertEquals(RecoveryKeyRotationResult.ROTATED, storage.lastDeviceRecovery.rotateRecoveryKey(storage.rotation(1, 2, epoch = Long.MAX_VALUE - 1)))
        storage.assertActive(2, epoch = Long.MAX_VALUE, installedAt = now + 1.minutes, rotation = 2)
        storage.challenge(phone, 1)

        assertEquals(RecoveryKeyRotationResult.EPOCH_EXHAUSTED, storage.lastDeviceRecovery.rotateRecoveryKey(storage.rotation(2, 3, epoch = Long.MAX_VALUE)))
        assertEquals(RecoveryKeyRevocationResult.EPOCH_EXHAUSTED, storage.lastDeviceRecovery.revokeRecoveryKey(storage.revocation(2, epoch = Long.MAX_VALUE)))
        storage.assertActive(2, epoch = Long.MAX_VALUE, installedAt = now + 1.minutes, rotation = 2)
        assertNotNull(storage.lastDeviceRecovery.challenge(phone), "nothing changed")
        assertTrue(storage.authenticationNonces.claim(phone, nonce(1003).bytes, now, now - 5.minutes), "no nonce claimed")

        // A revocation reaching the maximum leaves no way to register again: fails closed.
        val other = registered()
        setRecoveryKeyEpoch(other, alice, Long.MAX_VALUE - 1)
        assertEquals(RecoveryKeyRevocationResult.REVOKED, other.lastDeviceRecovery.revokeRecoveryKey(other.revocation(1, epoch = Long.MAX_VALUE - 1)))
        assertFailsWith<LastDeviceRecoveryKeyException.EpochExhausted> {
            other.lastDeviceRecovery.registerRecoveryKey(alice, recoveryKey(2), now)
        }
        assertEquals(RecoveryKeyStatus.REVOKED, other.recoveryState().status)
        assertEquals(Long.MAX_VALUE, other.recoveryState().epoch)
    }

    @Test
    fun transitionsLeaveDevicesPreKeysMailboxAndNoncesAlone() = runTest {
        val storage = registered()
        val signed = PublicSignedPreKey(SignedPreKeyId(1), ByteArray(64) { 5 }, ByteArray(64) { 6 })
        val publication = PreKeyPublication(phone, ByteArray(64) { 4 }, signed, listOf(1, 2).map { PublicOneTimePreKey(OneTimePreKeyId(it), ByteArray(64) { _ -> it.toByte() }) })
        storage.preKeys.publish(publication)
        assertEquals(OneTimePreKeyId(1), storage.preKeys.consumePreKeyBundle(phone)?.oneTimePreKey?.id)
        storage.mailboxes.enqueue(EncryptedEnvelope(MessageId("m1"), bobPhone, phone, payload = byteArrayOf(1)))
        assertTrue(storage.authenticationNonces.claim(laptop, nonce(1).bytes, now, now - 5.minutes))
        val devicesBefore = listOf(phone, laptop, bobPhone).map { storage.device(it) }

        assertEquals(RecoveryKeyRotationResult.ROTATED, storage.lastDeviceRecovery.rotateRecoveryKey(storage.rotation(1, 2, epoch = 1)))
        assertEquals(RecoveryKeyRevocationResult.REVOKED, storage.lastDeviceRecovery.revokeRecoveryKey(storage.revocation(2, epoch = 2)))
        assertTrue(storage.lastDeviceRecovery.registerRecoveryKey(alice, recoveryKey(3), now))

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
        assertFalse(storage.authenticationNonces.claim(laptop, nonce(1).bytes, now, now - 5.minutes), "nonces are never cleared")
        assertContentEquals(recoveryKey(50), storage.lastDeviceRecovery.recoveryKey(bobPhone.userId))
    }

    @Test
    fun concurrentIdenticalRotationsRotateOnce() = runTest {
        repeat(10) {
            val storage = registered()
            val rotation = storage.rotation(1, 2, epoch = 1)
            val results = withContext(Dispatchers.Default) {
                List(32) { async { storage.lastDeviceRecovery.rotateRecoveryKey(rotation) } }.awaitAll()
            }
            assertEquals(1, results.count { it == RecoveryKeyRotationResult.ROTATED })
            assertEquals(31, results.count { it == RecoveryKeyRotationResult.ALREADY_APPLIED })
            storage.assertActive(2, epoch = 2, installedAt = now + 1.minutes, rotation = 2)
        }
    }

    @Test
    fun concurrentIdenticalRevocationsRevokeOnce() = runTest {
        repeat(10) {
            val storage = registered()
            val revocation = storage.revocation(1, epoch = 1)
            val results = withContext(Dispatchers.Default) {
                List(32) { async { storage.lastDeviceRecovery.revokeRecoveryKey(revocation) } }.awaitAll()
            }
            assertEquals(1, results.count { it == RecoveryKeyRevocationResult.REVOKED })
            assertEquals(31, results.count { it == RecoveryKeyRevocationResult.ALREADY_APPLIED })
            storage.assertRevoked(epoch = 2, revokedAt = now + 2.minutes, revocation = 1)
        }
    }

    @Test
    fun concurrentCompetingRotationsHaveExactlyOneWinner() = runTest {
        repeat(10) {
            val storage = registered()
            val authorizer = storage.device()
            val results = withContext(Dispatchers.Default) {
                (2..33).map { to ->
                    async { to to storage.lastDeviceRecovery.rotateRecoveryKey(storage.rotation(1, to, epoch = 1, authorizer = authorizer)) }
                }.awaitAll()
            }
            val winner = results.single { it.second == RecoveryKeyRotationResult.ROTATED }.first
            assertTrue(results.all { it.second == RecoveryKeyRotationResult.ROTATED || it.second == RecoveryKeyRotationResult.CONFLICT })
            storage.assertActive(winner, epoch = 2, installedAt = now + 1.minutes, rotation = winner)
        }
    }

    @Test
    fun concurrentRotationAndRevocationHaveExactlyOneWinner() = runTest {
        repeat(20) {
            val storage = registered()
            val authorizer = storage.device()
            val rotation = storage.rotation(1, 2, epoch = 1, authorizer = authorizer)
            val revocation = storage.revocation(1, epoch = 1, authorizer = authorizer)
            val (rotated, revoked) = withContext(Dispatchers.Default) {
                val a = async { storage.lastDeviceRecovery.rotateRecoveryKey(rotation) }
                val b = async { storage.lastDeviceRecovery.revokeRecoveryKey(revocation) }
                a.await() to b.await()
            }
            if (rotated == RecoveryKeyRotationResult.ROTATED) {
                assertEquals(RecoveryKeyRevocationResult.CONFLICT, revoked)
                storage.assertActive(2, epoch = 2, installedAt = now + 1.minutes, rotation = 2)
            } else {
                assertEquals(RecoveryKeyRotationResult.CONFLICT, rotated)
                assertEquals(RecoveryKeyRevocationResult.REVOKED, revoked)
                storage.assertRevoked(epoch = 2, revokedAt = now + 2.minutes, revocation = 1)
            }
        }
    }

    @Test
    fun rotationAndLastDeviceRecoveryInBothOrders() = runTest {
        // Rotation first: the old challenge is gone and R1 no longer recovers anything.
        val rotationFirst = registered()
        val challenge1 = rotationFirst.challenge(phone, 1)
        assertEquals(RecoveryKeyRotationResult.ROTATED, rotationFirst.lastDeviceRecovery.rotateRecoveryKey(rotationFirst.rotation(1, 2, epoch = 1, authorizer = rotationFirst.device(laptop))))
        assertEquals(LastDeviceRecoveryReplacementResult.NOT_CONFIGURED, rotationFirst.lastDeviceRecovery(challenge1, recoveryKey = 1, replacement = 5))
        assertContentEquals(key(1), rotationFirst.device().registration.publicKey)

        // Last-device recovery first: the recovery key state is unchanged, so the rotation still succeeds.
        val recoveryFirst = registered()
        val challenge2 = recoveryFirst.challenge(phone, 1)
        val rotation = recoveryFirst.rotation(1, 2, epoch = 1, authorizer = recoveryFirst.device(laptop))
        assertEquals(LastDeviceRecoveryReplacementResult.REPLACED, recoveryFirst.lastDeviceRecovery(challenge2, recoveryKey = 1, replacement = 5))
        assertEquals(1, recoveryFirst.recoveryState().epoch, "device transitions never change the recovery key epoch")
        assertEquals(RecoveryKeyRotationResult.ROTATED, recoveryFirst.lastDeviceRecovery.rotateRecoveryKey(rotation))
        assertEquals(2, recoveryFirst.device().authEpoch)
    }

    @Test
    fun concurrentRotationAndLastDeviceRecoveryAreConsistent() = runTest {
        repeat(20) {
            val storage = registered()
            val challenge = storage.challenge(phone, 1)
            // The rotation is authorized by the laptop; the last-device recovery targets the phone.
            val rotation = storage.rotation(1, 2, epoch = 1, authorizer = storage.device(laptop))
            val expected = storage.device()
            val replacement = LastDeviceRecoveryReplacement(
                expected, recoveryKey(1), challenge.challenge.id, challenge.challenge.nonce, key(5), LastDeviceRecoveryId(ByteArray(32) { 5 }), now + 1.minutes,
            )
            val (rotated, recovered) = withContext(Dispatchers.Default) {
                val a = async { storage.lastDeviceRecovery.rotateRecoveryKey(rotation) }
                val b = async { storage.devices.replaceForLastDeviceRecovery(replacement) }
                a.await() to b.await()
            }
            assertEquals(RecoveryKeyRotationResult.ROTATED, rotated, "a device transition never blocks a recovery key rotation")
            assertTrue(recovered == LastDeviceRecoveryReplacementResult.REPLACED || recovered == LastDeviceRecoveryReplacementResult.NOT_CONFIGURED)
            val device = storage.device()
            assertEquals(if (recovered == LastDeviceRecoveryReplacementResult.REPLACED) 2 else 1, device.authEpoch)
            storage.assertActive(2, epoch = 2, installedAt = now + 1.minutes, rotation = 2)
            assertNull(storage.lastDeviceRecovery.challenge(phone))
        }
    }

    @Test
    fun concurrentRotationAndLastDeviceRecoveryOfTheAuthorizerHaveExactlyOneWinner() = runTest {
        repeat(20) {
            val storage = registered()
            val challenge = storage.challenge(phone, 1)
            // The phone authorizes the rotation and is the target of the last-device recovery.
            val rotation = storage.rotation(1, 2, epoch = 1, authorizer = storage.device())
            val replacement = LastDeviceRecoveryReplacement(
                storage.device(), recoveryKey(1), challenge.challenge.id, challenge.challenge.nonce, key(5), LastDeviceRecoveryId(ByteArray(32) { 5 }), now + 1.minutes,
            )
            val (rotated, recovered) = withContext(Dispatchers.Default) {
                val a = async { storage.lastDeviceRecovery.rotateRecoveryKey(rotation) }
                val b = async { storage.devices.replaceForLastDeviceRecovery(replacement) }
                a.await() to b.await()
            }
            val wins = listOf(rotated == RecoveryKeyRotationResult.ROTATED, recovered == LastDeviceRecoveryReplacementResult.REPLACED)
            assertEquals(1, wins.count { it }, "exactly one: $rotated / $recovered")
        }
    }

    @Test
    fun concurrentRevocationAndLastDeviceRecoveryAreConsistent() = runTest {
        repeat(20) {
            val storage = registered()
            val challenge = storage.challenge(phone, 1)
            val revocation = storage.revocation(1, epoch = 1, authorizer = storage.device(laptop))
            val replacement = LastDeviceRecoveryReplacement(
                storage.device(), recoveryKey(1), challenge.challenge.id, challenge.challenge.nonce, key(5), LastDeviceRecoveryId(ByteArray(32) { 5 }), now + 1.minutes,
            )
            val (revoked, recovered) = withContext(Dispatchers.Default) {
                val a = async { storage.lastDeviceRecovery.revokeRecoveryKey(revocation) }
                val b = async { storage.devices.replaceForLastDeviceRecovery(replacement) }
                a.await() to b.await()
            }
            assertEquals(RecoveryKeyRevocationResult.REVOKED, revoked)
            assertTrue(recovered == LastDeviceRecoveryReplacementResult.REPLACED || recovered == LastDeviceRecoveryReplacementResult.NOT_CONFIGURED)
            assertEquals(if (recovered == LastDeviceRecoveryReplacementResult.REPLACED) 2 else 1, storage.device().authEpoch)
            storage.assertRevoked(epoch = 2, revokedAt = now + 2.minutes, revocation = 1)
            assertNull(storage.lastDeviceRecovery.challenge(phone))
            assertEquals(LastDeviceRecoveryChallengeIssue.NotConfigured, storage.issue(phone, 2, at = now + 3.minutes))
        }
    }

    @Test
    fun valuesAreCopied() = runTest {
        val storage = registered()
        storage.recoveryState().publicKey?.fill(0)
        assertNotNull(storage.lastDeviceRecovery.recoveryKey(alice)).fill(0)
        val rotation = storage.rotation(1, 2, epoch = 1)
        rotation.newPublicKey.fill(0)
        rotation.expectedPublicKey.fill(0)
        assertEquals(RecoveryKeyRotationResult.ROTATED, storage.lastDeviceRecovery.rotateRecoveryKey(rotation))
        storage.assertActive(2, epoch = 2, installedAt = now + 1.minutes, rotation = 2)
    }
}
