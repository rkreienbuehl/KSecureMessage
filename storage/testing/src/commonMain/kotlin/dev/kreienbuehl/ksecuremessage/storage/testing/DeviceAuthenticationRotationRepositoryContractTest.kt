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
import dev.kreienbuehl.ksecuremessage.protocol.RequestNonce
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationState
import dev.kreienbuehl.ksecuremessage.storage.RecoveryReplacement
import dev.kreienbuehl.ksecuremessage.storage.RecoveryReplacementResult
import dev.kreienbuehl.ksecuremessage.storage.RotationReplacement
import dev.kreienbuehl.ksecuremessage.storage.RotationReplacementResult.ALREADY_APPLIED
import dev.kreienbuehl.ksecuremessage.storage.RotationReplacementResult.CONFLICT
import dev.kreienbuehl.ksecuremessage.storage.RotationReplacementResult.EPOCH_EXHAUSTED
import dev.kreienbuehl.ksecuremessage.storage.RotationReplacementResult.NOT_REGISTERED
import dev.kreienbuehl.ksecuremessage.storage.RotationReplacementResult.REPLACED
import dev.kreienbuehl.ksecuremessage.storage.RotationReplacementResult.REPLAY
import dev.kreienbuehl.ksecuremessage.storage.ServerStorage
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/**
 * Routine rotation behavior every server storage must have
 * (docs/device-authentication-rotation.md):
 * [dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationRepository.replaceForRotation]
 * is a compare-and-set on the device's key and epoch, joined with the nonce
 * claim, idempotent for the rotation that installed the current key, shares
 * its compare-and-set with recovery, never wraps the epoch, and leaves
 * everything else alone.
 *
 * Signatures are the service's job and not checked here.
 */
abstract class DeviceAuthenticationRotationRepositoryContractTest {
    /** Returns a new, empty storage. */
    protected abstract suspend fun newStorage(): ServerStorage

    /** Sets the registered [address]'s authentication epoch directly, for the exhaustion boundary. */
    protected abstract suspend fun setAuthEpoch(storage: ServerStorage, address: DeviceAddress, authEpoch: Long)

    private val phone = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val laptop = DeviceAddress(UserId("alice"), DeviceId("laptop"))
    private val bob = DeviceAddress(UserId("bob"), DeviceId("phone"))
    private val now = Instant.fromEpochMilliseconds(1_767_225_600_000)

    private fun key(seed: Int) = ByteArray(32) { (seed * 7 + it).toByte() }
    private fun rotationId(seed: Int) = DeviceAuthenticationRotationId(ByteArray(32) { (seed * 13 + it).toByte() })
    private fun recoveryId(seed: Int) = DeviceRecoveryId(ByteArray(32) { (seed * 17 + it).toByte() })
    private fun nonce(seed: Int) = RequestNonce(ByteArray(16) { (seed * 3 + it).toByte() })

    /** phone with key 1 and laptop (a possible recovery authorizer) with key 100, both at epoch 1. */
    private suspend fun registered(): ServerStorage = newStorage().apply {
        assertTrue(devices.register(DeviceRegistration(phone, key(1)), now))
        assertTrue(devices.register(DeviceRegistration(laptop, key(100)), now))
    }

    private suspend fun ServerStorage.state(address: DeviceAddress = phone): DeviceRegistrationState =
        assertNotNull(devices.registrationState(address))

    private suspend fun ServerStorage.rotation(
        replacementKey: Int,
        id: Int = replacementKey,
        nonce: Int = replacementKey,
        expected: DeviceRegistrationState? = null,
        installedAt: Instant = now,
    ) = RotationReplacement(
        expected = expected ?: state(),
        replacementPublicKey = key(replacementKey),
        rotationId = rotationId(id),
        nonce = nonce(nonce),
        timestamp = now,
        pruneBefore = now - 5.minutes,
        installedAt = installedAt,
    )

    private suspend fun ServerStorage.recovery(
        replacementKey: Int,
        id: Int = replacementKey,
        target: DeviceRegistrationState? = null,
        installedAt: Instant = now,
    ) =
        RecoveryReplacement(
            expectedTarget = target ?: state(),
            expectedAuthorizer = state(laptop),
            replacementPublicKey = key(replacementKey),
            recoveryId = recoveryId(id),
            nonce = nonce(1000 + id),
            timestamp = now,
            pruneBefore = now - 5.minutes,
            installedAt = installedAt,
        )

    private suspend fun ServerStorage.assertKey(expected: Int, epoch: Long, rotation: Int? = null, recovery: Int? = null) {
        val state = state()
        assertContentEquals(key(expected), state.registration.publicKey)
        assertContentEquals(key(expected), devices.registration(phone)?.publicKey)
        assertEquals(epoch, state.authEpoch)
        assertEquals(rotation?.let(::rotationId), state.rotationId)
        assertEquals(recovery?.let(::recoveryId), state.recoveryId)
    }

    @Test
    fun installationTimeFollowsEveryTransitionAndNoRetry() = runTest {
        val storage = registered()
        val t1 = now
        assertEquals(t1, storage.state().authKeyInstalledAt)

        val t2 = t1 + 30.days
        val rotation = storage.rotation(2, installedAt = t2)
        assertEquals(REPLACED, storage.devices.replaceForRotation(rotation))
        assertEquals(t2, storage.state().authKeyInstalledAt)

        val t3 = t2 + 100.days
        assertEquals(RecoveryReplacementResult.REPLACED, storage.devices.replaceForRecovery(storage.recovery(3, installedAt = t3)))
        assertEquals(t3, storage.state().authKeyInstalledAt)

        val t4 = t3 + 1.days
        val second = storage.rotation(4, installedAt = t4)
        assertEquals(REPLACED, storage.devices.replaceForRotation(second))
        assertEquals(t4, storage.state().authKeyInstalledAt)

        // Exact retry, stale rotation, replay and registration probe of the current key: time stays t4.
        val t5 = t4 + 1.days
        assertEquals(ALREADY_APPLIED, storage.devices.replaceForRotation(storage.rotation(4, installedAt = t5)))
        assertEquals(CONFLICT, storage.devices.replaceForRotation(rotation))
        assertTrue(storage.authenticationNonces.claim(phone, nonce(9).bytes, now, now))
        assertEquals(REPLAY, storage.devices.replaceForRotation(storage.rotation(5, id = 9, nonce = 9, installedAt = t5)))
        assertFalse(storage.devices.register(DeviceRegistration(phone, key(4)), t5))
        assertEquals(t4, storage.state().authKeyInstalledAt)
        storage.assertKey(4, epoch = 4, rotation = 4)
        assertEquals(t1, storage.state(laptop).authKeyInstalledAt, "other devices keep theirs")
    }

    @Test
    fun firstRegistrationHasNoTransition() = runTest {
        val storage = registered()
        storage.assertKey(1, epoch = 1)
    }

    @Test
    fun rotationInstallsTheNewKeyAndIncrementsTheEpochOnce() = runTest {
        val storage = registered()
        assertEquals(REPLACED, storage.devices.replaceForRotation(storage.rotation(2)))
        storage.assertKey(2, epoch = 2, rotation = 2)
        // Registration of the new key is idempotent; the laptop is not changed.
        assertFalse(storage.devices.register(DeviceRegistration(phone, key(2)), now))
        assertContentEquals(key(100), storage.state(laptop).registration.publicKey)
        assertEquals(1, storage.state(laptop).authEpoch)
    }

    @Test
    fun retryOfTheAppliedRotationChangesNothing() = runTest {
        val storage = registered()
        val rotation = storage.rotation(2)
        assertEquals(REPLACED, storage.devices.replaceForRotation(rotation))
        assertEquals(ALREADY_APPLIED, storage.devices.replaceForRotation(rotation))
        assertEquals(ALREADY_APPLIED, storage.devices.replaceForRotation(storage.rotation(2)), "also against the new state")
        storage.assertKey(2, epoch = 2, rotation = 2)
    }

    @Test
    fun unexpectedStateConflictsAndChangesNothing() = runTest {
        val storage = registered()
        val otherKey = DeviceRegistrationState(DeviceRegistration(phone, key(9)), 1, now, null)
        assertEquals(CONFLICT, storage.devices.replaceForRotation(storage.rotation(2, expected = otherKey)), "other key")
        val otherEpoch = DeviceRegistrationState(DeviceRegistration(phone, key(1)), 2, now, null)
        assertEquals(CONFLICT, storage.devices.replaceForRotation(storage.rotation(2, expected = otherEpoch)), "other epoch")
        storage.assertKey(1, epoch = 1)
        assertTrue(storage.authenticationNonces.claim(phone, nonce(2).bytes, now, now), "no nonce was claimed")
    }

    @Test
    fun missingDeviceIsReported() = runTest {
        val storage = newStorage()
        val expected = DeviceRegistrationState(DeviceRegistration(phone, key(1)), 1, now, null)
        assertEquals(NOT_REGISTERED, storage.devices.replaceForRotation(storage.rotation(2, expected = expected)))
        assertNull(storage.devices.registration(phone), "rotation never registers")
    }

    @Test
    fun sameKeyRotationConflictsWithoutAnEpochChange() = runTest {
        val storage = registered()
        assertEquals(CONFLICT, storage.devices.replaceForRotation(storage.rotation(1)))
        storage.assertKey(1, epoch = 1)
        assertTrue(storage.authenticationNonces.claim(phone, nonce(1).bytes, now, now))
    }

    @Test
    fun claimedNonceIsAReplayAndTheRotationNonceIsClaimed() = runTest {
        val storage = registered()
        assertTrue(storage.authenticationNonces.claim(phone, nonce(2).bytes, now, now))
        assertEquals(REPLAY, storage.devices.replaceForRotation(storage.rotation(2)))
        storage.assertKey(1, epoch = 1)

        assertEquals(REPLACED, storage.devices.replaceForRotation(storage.rotation(3)))
        assertFalse(storage.authenticationNonces.claim(phone, nonce(3).bytes, now, now), "the rotation claimed its nonce")
        assertTrue(storage.authenticationNonces.claim(laptop, nonce(3).bytes, now, now), "under the device's address only")
    }

    @Test
    fun staleRotationCannotRestoreAnOlderKey() = runTest {
        val storage = registered()
        val first = storage.rotation(2)
        assertEquals(REPLACED, storage.devices.replaceForRotation(first))
        assertEquals(REPLACED, storage.devices.replaceForRotation(storage.rotation(3)))
        storage.assertKey(3, epoch = 3, rotation = 3)

        // K1 -> K2 again, against its original state or presented as if against the current one.
        assertEquals(CONFLICT, storage.devices.replaceForRotation(first))
        assertEquals(REPLAY, storage.devices.replaceForRotation(storage.rotation(2)))
        storage.assertKey(3, epoch = 3, rotation = 3)
    }

    @Test
    fun rotationAndRecoveryShareTheTransitionMetadata() = runTest {
        val storage = registered()
        // Rotation K1 -> K2, then recovery K2 -> K3, then rotation K3 -> K4.
        assertEquals(REPLACED, storage.devices.replaceForRotation(storage.rotation(2)))
        storage.assertKey(2, epoch = 2, rotation = 2)
        assertEquals(RecoveryReplacementResult.REPLACED, storage.devices.replaceForRecovery(storage.recovery(3)))
        storage.assertKey(3, epoch = 3, recovery = 3)
        assertEquals(REPLACED, storage.devices.replaceForRotation(storage.rotation(4)))
        storage.assertKey(4, epoch = 4, rotation = 4)

        // Neither kind of ID ever matches the other: an older rotation or recovery is not "already applied".
        assertEquals(CONFLICT, storage.devices.replaceForRotation(storage.rotation(2, expected = DeviceRegistrationState(DeviceRegistration(phone, key(1)), 1, now, null))))
        assertEquals(
            RecoveryReplacementResult.CONFLICT,
            storage.devices.replaceForRecovery(storage.recovery(3, target = DeviceRegistrationState(DeviceRegistration(phone, key(2)), 2, now, null, rotationId(2)))),
        )
        storage.assertKey(4, epoch = 4, rotation = 4)
    }

    @Test
    fun epochNeverWraps() = runTest {
        val storage = registered()
        setAuthEpoch(storage, phone, Long.MAX_VALUE - 1)
        assertEquals(REPLACED, storage.devices.replaceForRotation(storage.rotation(2)))
        storage.assertKey(2, epoch = Long.MAX_VALUE, rotation = 2)

        assertEquals(EPOCH_EXHAUSTED, storage.devices.replaceForRotation(storage.rotation(3)))
        assertEquals(RecoveryReplacementResult.EPOCH_EXHAUSTED, storage.devices.replaceForRecovery(storage.recovery(3)))
        storage.assertKey(2, epoch = Long.MAX_VALUE, rotation = 2)
        assertTrue(storage.authenticationNonces.claim(phone, nonce(3).bytes, now, now), "no nonce was claimed")
        assertEquals(ALREADY_APPLIED, storage.devices.replaceForRotation(storage.rotation(2)), "the applied rotation is still recognized")
    }

    @Test
    fun concurrentIdenticalRotationsReplaceOnce() = runTest {
        repeat(10) {
            val storage = registered()
            val rotation = storage.rotation(2)
            val results = withContext(Dispatchers.Default) {
                List(32) { async { storage.devices.replaceForRotation(rotation) } }.awaitAll()
            }
            assertEquals(1, results.count { it == REPLACED })
            assertEquals(31, results.count { it == ALREADY_APPLIED })
            storage.assertKey(2, epoch = 2, rotation = 2)
        }
    }

    @Test
    fun concurrentDifferentRotationsHaveExactlyOneWinner() = runTest {
        repeat(10) {
            val storage = registered()
            val expected = storage.state()
            val results = withContext(Dispatchers.Default) {
                (2..33).map { seed -> async { seed to storage.devices.replaceForRotation(storage.rotation(seed, expected = expected)) } }.awaitAll()
            }
            val winners = results.filter { it.second == REPLACED }
            assertEquals(1, winners.size)
            assertEquals(31, results.count { it.second == CONFLICT })
            storage.assertKey(winners.single().first, epoch = 2, rotation = winners.single().first)
        }
    }

    @Test
    fun concurrentRotationAndRecoveryHaveExactlyOneWinner() = runTest {
        repeat(20) {
            val storage = registered()
            val expected = storage.state()
            val laptopState = storage.state(laptop)
            val results = withContext(Dispatchers.Default) {
                val rotations = (2..17).map { seed ->
                    async { storage.devices.replaceForRotation(storage.rotation(seed, expected = expected)) == REPLACED }
                }
                val recoveries = (40..55).map { seed ->
                    async {
                        val recovery = RecoveryReplacement(expected, laptopState, key(seed), recoveryId(seed), nonce(seed), now, now - 5.minutes, now)
                        storage.devices.replaceForRecovery(recovery) == RecoveryReplacementResult.REPLACED
                    }
                }
                (rotations + recoveries).awaitAll()
            }
            assertEquals(1, results.count { it }, "exactly one transition wins")
            val state = storage.state()
            assertEquals(2, state.authEpoch)
            assertTrue((state.rotationId == null) != (state.recoveryId == null), "the winner's ID, and only that one")
        }
    }

    @Test
    fun rotationLeavesPreKeysMailboxAndNoncesAlone() = runTest {
        val storage = registered()
        val signed = PublicSignedPreKey(SignedPreKeyId(1), ByteArray(64) { 5 }, ByteArray(64) { 6 })
        val oneTime = listOf(1, 2, 3).map { PublicOneTimePreKey(OneTimePreKeyId(it), ByteArray(64) { _ -> it.toByte() }) }
        val publication = PreKeyPublication(phone, ByteArray(64) { 4 }, signed, oneTime)
        storage.preKeys.publish(publication)
        assertEquals(OneTimePreKeyId(1), assertNotNull(storage.preKeys.consumePreKeyBundle(phone)).oneTimePreKey?.id)
        val envelope = EncryptedEnvelope(MessageId("m1"), bob, phone, payload = byteArrayOf(1, 2, 3))
        storage.mailboxes.enqueue(envelope)
        assertTrue(storage.authenticationNonces.claim(phone, nonce(50).bytes, now, now))

        assertEquals(REPLACED, storage.devices.replaceForRotation(storage.rotation(2)))

        assertFalse(storage.authenticationNonces.claim(phone, nonce(50).bytes, now, now), "old-key nonces stay claimed")
        assertEquals(2, storage.preKeys.oneTimePreKeyCount(phone))
        storage.preKeys.publish(publication) // re-upload: the consumed one stays consumed
        assertEquals(2, storage.preKeys.oneTimePreKeyCount(phone))
        val bundle = assertNotNull(storage.preKeys.consumePreKeyBundle(phone))
        assertContentEquals(publication.identityKey, bundle.identityKey)
        assertEquals(OneTimePreKeyId(2), bundle.oneTimePreKey?.id)
        val drained = storage.mailboxes.drain(phone).single()
        assertEquals(envelope.id, drained.id)
        assertContentEquals(envelope.payload, drained.payload)
    }

    @Test
    fun keysAreCopied() = runTest {
        val storage = registered()
        val replacementKey = key(2)
        val rotation = RotationReplacement(storage.state(), replacementKey, rotationId(2), nonce(2), now, now, now)
        replacementKey.fill(0)
        assertEquals(REPLACED, storage.devices.replaceForRotation(rotation))
        storage.state().registration.publicKey.fill(0)
        storage.assertKey(2, epoch = 2, rotation = 2)
    }
}
