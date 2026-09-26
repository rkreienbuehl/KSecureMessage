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
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecoveryId
import dev.kreienbuehl.ksecuremessage.protocol.RequestNonce
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationState
import dev.kreienbuehl.ksecuremessage.storage.RecoveryReplacement
import dev.kreienbuehl.ksecuremessage.storage.RecoveryReplacementResult.ALREADY_APPLIED
import dev.kreienbuehl.ksecuremessage.storage.RecoveryReplacementResult.CONFLICT
import dev.kreienbuehl.ksecuremessage.storage.RecoveryReplacementResult.REPLACED
import dev.kreienbuehl.ksecuremessage.storage.RecoveryReplacementResult.REPLAY
import dev.kreienbuehl.ksecuremessage.storage.RecoveryReplacementResult.TARGET_NOT_REGISTERED
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
 * Device recovery behavior every server storage must have
 * (docs/device-recovery.md): [dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationRepository.replaceForRecovery]
 * is a compare-and-set on the target's and the authorizer's key and epoch,
 * joined with the nonce claim, idempotent for the recovery that installed the
 * current key, and leaves everything else alone.
 *
 * Signatures are the service's job and not checked here.
 */
abstract class DeviceRecoveryRepositoryContractTest {
    /** Returns a new, empty storage. */
    protected abstract suspend fun newStorage(): ServerStorage

    private val laptop = DeviceAddress(UserId("alice"), DeviceId("laptop"))
    private val phone = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val tablet = DeviceAddress(UserId("alice"), DeviceId("tablet"))
    private val bob = DeviceAddress(UserId("bob"), DeviceId("phone"))
    private val now = Instant.fromEpochMilliseconds(1_767_225_600_000)

    private fun key(seed: Int) = ByteArray(32) { (seed * 7 + it).toByte() }
    private fun id(seed: Int) = DeviceRecoveryId(ByteArray(32) { (seed * 13 + it).toByte() })
    private fun nonce(seed: Int) = RequestNonce(ByteArray(16) { (seed * 3 + it).toByte() })

    /** laptop (target) with key 1 and phone (authorizer) with key 100, both at epoch 1. */
    private suspend fun registered(): ServerStorage = newStorage().apply {
        assertTrue(devices.register(DeviceRegistration(laptop, key(1)), now))
        assertTrue(devices.register(DeviceRegistration(phone, key(100)), now))
    }

    private suspend fun ServerStorage.state(address: DeviceAddress): DeviceRegistrationState = assertNotNull(devices.registrationState(address))

    private suspend fun ServerStorage.replacement(
        replacementKey: Int,
        recovery: Int = replacementKey,
        nonce: Int = replacementKey,
        target: DeviceRegistrationState? = null,
        authorizer: DeviceRegistrationState? = null,
        installedAt: Instant = now,
    ) = RecoveryReplacement(
        expectedTarget = target ?: state(laptop),
        expectedAuthorizer = authorizer ?: state(phone),
        replacementPublicKey = key(replacementKey),
        recoveryId = id(recovery),
        nonce = nonce(nonce),
        timestamp = now,
        pruneBefore = now - 5.minutes,
        installedAt = installedAt,
    )

    private suspend fun ServerStorage.assertKey(expected: Int, epoch: Long, recovery: Int?) {
        val state = state(laptop)
        assertContentEquals(key(expected), state.registration.publicKey)
        assertContentEquals(key(expected), devices.registration(laptop)?.publicKey)
        assertEquals(epoch, state.authEpoch)
        assertEquals(recovery?.let(::id), state.recoveryId)
    }

    @Test
    fun firstRegistrationHasEpochOneAndNoRecovery() = runTest {
        val storage = registered()
        storage.assertKey(1, epoch = 1, recovery = null)
        assertNull(storage.devices.registrationState(bob))
    }

    @Test
    fun replacementInstallsTheNewKeyAndIncrementsTheEpoch() = runTest {
        val storage = registered()
        assertEquals(REPLACED, storage.devices.replaceForRecovery(storage.replacement(2)))
        storage.assertKey(2, epoch = 2, recovery = 2)
        // The old key is gone: registration of it conflicts, of the new one is idempotent.
        assertFalse(storage.devices.register(DeviceRegistration(laptop, key(2)), now))
        // The authorizer is not changed.
        assertContentEquals(key(100), storage.state(phone).registration.publicKey)
        assertEquals(1, storage.state(phone).authEpoch)
    }

    @Test
    fun recoveryInstallsItsServerTimeAndNothingElseChangesIt() = runTest {
        val storage = registered()
        assertEquals(now, storage.state(laptop).authKeyInstalledAt)
        val t3 = now + 100.days
        val replacement = storage.replacement(2, installedAt = t3)
        assertEquals(REPLACED, storage.devices.replaceForRecovery(replacement))
        // The recovered key's age starts at the recovery, not at the lost key's registration.
        assertEquals(t3, storage.state(laptop).authKeyInstalledAt)
        assertEquals(now, storage.state(phone).authKeyInstalledAt, "the authorizer is not changed")

        // Retries, conflicts, replays and registration probes keep the committed time.
        assertEquals(ALREADY_APPLIED, storage.devices.replaceForRecovery(storage.replacement(2, installedAt = t3 + 1.days)))
        assertEquals(CONFLICT, storage.devices.replaceForRecovery(storage.replacement(2, recovery = 7, nonce = 7, installedAt = t3 + 2.days)))
        assertTrue(storage.authenticationNonces.claim(laptop, nonce(8).bytes, now, now))
        assertEquals(REPLAY, storage.devices.replaceForRecovery(storage.replacement(3, recovery = 8, nonce = 8, installedAt = t3 + 3.days)))
        assertFalse(storage.devices.register(DeviceRegistration(laptop, key(2)), t3 + 4.days))
        assertEquals(t3, storage.state(laptop).authKeyInstalledAt)
        storage.assertKey(2, epoch = 2, recovery = 2)
    }

    @Test
    fun retryOfTheAppliedRecoveryChangesNothing() = runTest {
        val storage = registered()
        val replacement = storage.replacement(2)
        assertEquals(REPLACED, storage.devices.replaceForRecovery(replacement))
        assertEquals(ALREADY_APPLIED, storage.devices.replaceForRecovery(replacement))
        assertEquals(ALREADY_APPLIED, storage.devices.replaceForRecovery(storage.replacement(2)), "also against the new state")
        storage.assertKey(2, epoch = 2, recovery = 2)
    }

    @Test
    fun unexpectedTargetStateConflictsAndChangesNothing() = runTest {
        val storage = registered()
        val stale = DeviceRegistrationState(DeviceRegistration(laptop, key(9)), 1, now, null)
        assertEquals(CONFLICT, storage.devices.replaceForRecovery(storage.replacement(2, target = stale)), "other key")
        val oldEpoch = DeviceRegistrationState(DeviceRegistration(laptop, key(1)), 2, now, null)
        assertEquals(CONFLICT, storage.devices.replaceForRecovery(storage.replacement(2, target = oldEpoch)), "other epoch")
        storage.assertKey(1, epoch = 1, recovery = null)
        // No nonce was claimed.
        assertTrue(storage.authenticationNonces.claim(laptop, nonce(2).bytes, now, now))
    }

    @Test
    fun unexpectedAuthorizerStateConflictsAndChangesNothing() = runTest {
        val storage = registered()
        val otherKey = DeviceRegistrationState(DeviceRegistration(phone, key(101)), 1, now, null)
        assertEquals(CONFLICT, storage.devices.replaceForRecovery(storage.replacement(2, authorizer = otherKey)))
        val otherEpoch = DeviceRegistrationState(DeviceRegistration(phone, key(100)), 2, now, null)
        assertEquals(CONFLICT, storage.devices.replaceForRecovery(storage.replacement(2, authorizer = otherEpoch)))
        val unregistered = DeviceRegistrationState(DeviceRegistration(tablet, key(100)), 1, now, null)
        assertEquals(CONFLICT, storage.devices.replaceForRecovery(storage.replacement(2, authorizer = unregistered)))
        storage.assertKey(1, epoch = 1, recovery = null)
        assertTrue(storage.authenticationNonces.claim(laptop, nonce(2).bytes, now, now))
    }

    @Test
    fun missingTargetIsReported() = runTest {
        val storage = newStorage()
        storage.devices.register(DeviceRegistration(phone, key(100)), now)
        val target = DeviceRegistrationState(DeviceRegistration(laptop, key(1)), 1, now, null)
        assertEquals(TARGET_NOT_REGISTERED, storage.devices.replaceForRecovery(storage.replacement(2, target = target)))
        assertNull(storage.devices.registration(laptop), "recovery never registers")
    }

    @Test
    fun replacementWithTheCurrentKeyConflicts() = runTest {
        val storage = registered()
        assertEquals(CONFLICT, storage.devices.replaceForRecovery(storage.replacement(1)))
        storage.assertKey(1, epoch = 1, recovery = null)
        // The same key installed by another recovery is a conflict too, not a success.
        assertEquals(REPLACED, storage.devices.replaceForRecovery(storage.replacement(2)))
        assertEquals(CONFLICT, storage.devices.replaceForRecovery(storage.replacement(2, recovery = 3, nonce = 3)))
        storage.assertKey(2, epoch = 2, recovery = 2)
    }

    @Test
    fun claimedNonceIsAReplayAndTheRecoveryNonceIsClaimed() = runTest {
        val storage = registered()
        assertTrue(storage.authenticationNonces.claim(laptop, nonce(2).bytes, now, now))
        assertEquals(REPLAY, storage.devices.replaceForRecovery(storage.replacement(2)))
        storage.assertKey(1, epoch = 1, recovery = null)

        assertEquals(REPLACED, storage.devices.replaceForRecovery(storage.replacement(3)))
        assertFalse(storage.authenticationNonces.claim(laptop, nonce(3).bytes, now, now), "the recovery claimed its nonce")
        assertTrue(storage.authenticationNonces.claim(phone, nonce(3).bytes, now, now), "under the target's address only")
    }

    @Test
    fun staleRecoveryCannotRestoreAnOlderKey() = runTest {
        val storage = registered()
        val first = storage.replacement(2)
        assertEquals(REPLACED, storage.devices.replaceForRecovery(first))
        assertEquals(REPLACED, storage.devices.replaceForRecovery(storage.replacement(3)))
        storage.assertKey(3, epoch = 3, recovery = 3)

        // The K1 -> K2 recovery again, verified against its original state or against the current one.
        assertEquals(CONFLICT, storage.devices.replaceForRecovery(first))
        assertEquals(REPLAY, storage.devices.replaceForRecovery(storage.replacement(2)))
        storage.assertKey(3, epoch = 3, recovery = 3)
    }

    @Test
    fun epochsOnlyGrow() = runTest {
        val storage = registered()
        for (next in 2..5) {
            assertEquals(REPLACED, storage.devices.replaceForRecovery(storage.replacement(next)))
            storage.assertKey(next, epoch = next.toLong(), recovery = next)
        }
        // Back to a key used before: a new recovery, a new epoch.
        assertEquals(REPLACED, storage.devices.replaceForRecovery(storage.replacement(2, recovery = 6, nonce = 6)))
        storage.assertKey(2, epoch = 6, recovery = 6)
    }

    @Test
    fun concurrentDifferentRecoveriesHaveExactlyOneWinner() = runTest {
        repeat(10) {
            val storage = registered()
            val target = storage.state(laptop)
            val authorizer = storage.state(phone)
            val results = withContext(Dispatchers.Default) {
                (2..33).map { seed ->
                    async { seed to storage.devices.replaceForRecovery(storage.replacement(seed, target = target, authorizer = authorizer)) }
                }.awaitAll()
            }
            val winners = results.filter { it.second == REPLACED }
            assertEquals(1, winners.size)
            assertEquals(31, results.count { it.second == CONFLICT })
            storage.assertKey(winners.single().first, epoch = 2, recovery = winners.single().first)
        }
    }

    @Test
    fun concurrentIdenticalRecoveriesReplaceOnce() = runTest {
        repeat(10) {
            val storage = registered()
            val replacement = storage.replacement(2)
            val results = withContext(Dispatchers.Default) {
                List(32) { async { storage.devices.replaceForRecovery(replacement) } }.awaitAll()
            }
            assertEquals(1, results.count { it == REPLACED })
            assertEquals(31, results.count { it == ALREADY_APPLIED })
            storage.assertKey(2, epoch = 2, recovery = 2)
        }
    }

    @Test
    fun recoveryLeavesPreKeysMailboxAndNoncesAlone() = runTest {
        val storage = registered()
        val signed = PublicSignedPreKey(SignedPreKeyId(1), ByteArray(64) { 5 }, ByteArray(64) { 6 })
        val oneTime = listOf(1, 2, 3).map { PublicOneTimePreKey(OneTimePreKeyId(it), ByteArray(64) { _ -> it.toByte() }) }
        val publication = PreKeyPublication(laptop, ByteArray(64) { 4 }, signed, oneTime)
        storage.preKeys.publish(publication)
        val consumed = assertNotNull(storage.preKeys.consumePreKeyBundle(laptop)).oneTimePreKey
        val envelope = EncryptedEnvelope(MessageId("m1"), bob, laptop, payload = byteArrayOf(1, 2, 3))
        storage.mailboxes.enqueue(envelope)
        assertTrue(storage.authenticationNonces.claim(laptop, nonce(50).bytes, now, now))

        assertEquals(REPLACED, storage.devices.replaceForRecovery(storage.replacement(2)))

        assertFalse(storage.authenticationNonces.claim(laptop, nonce(50).bytes, now, now), "old-key nonces stay claimed")
        assertEquals(2, storage.preKeys.oneTimePreKeyCount(laptop))
        storage.preKeys.publish(publication) // re-upload: the consumed one stays consumed
        assertEquals(2, storage.preKeys.oneTimePreKeyCount(laptop))
        val bundle = assertNotNull(storage.preKeys.consumePreKeyBundle(laptop))
        assertContentEquals(publication.identityKey, bundle.identityKey)
        assertContentEquals(signed.publicKey, bundle.signedPreKey.publicKey)
        assertEquals(OneTimePreKeyId(2), bundle.oneTimePreKey?.id)
        assertEquals(OneTimePreKeyId(1), consumed?.id)
        val drained = storage.mailboxes.drain(laptop).single()
        assertEquals(envelope.id, drained.id)
        assertContentEquals(envelope.payload, drained.payload)
    }

    @Test
    fun keysAreCopied() = runTest {
        val storage = registered()
        val replacementKey = key(2)
        val replacement = RecoveryReplacement(
            storage.state(laptop), storage.state(phone), replacementKey, id(2), nonce(2), now, now, now,
        )
        replacementKey.fill(0)
        assertEquals(REPLACED, storage.devices.replaceForRecovery(replacement))
        storage.state(laptop).registration.publicKey.fill(0)
        storage.assertKey(2, epoch = 2, recovery = 2)
    }
}
