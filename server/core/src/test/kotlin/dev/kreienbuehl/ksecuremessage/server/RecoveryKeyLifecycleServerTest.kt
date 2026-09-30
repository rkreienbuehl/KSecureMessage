package dev.kreienbuehl.ksecuremessage.server

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.DeviceRegistration
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.LastDeviceRecoveryKeyStatus
import dev.kreienbuehl.ksecuremessage.model.MessageId
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication
import dev.kreienbuehl.ksecuremessage.model.PublicOneTimePreKey
import dev.kreienbuehl.ksecuremessage.model.PublicSignedPreKey
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecovery
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryKey
import dev.kreienbuehl.ksecuremessage.protocol.PreKeyFormat
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRevocation
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRevocationAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRotation
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRotationAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.RequestNonce
import dev.kreienbuehl.ksecuremessage.protocol.ServerApiPaths
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequest
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequestAuthentication
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationRepository
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationState
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryRepository
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryReplacement
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryReplacementResult
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyRevocationResult
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyRevocationTransition
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyRotationResult
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyRotationTransition
import dev.kreienbuehl.ksecuremessage.storage.ServerStorage
import dev.kreienbuehl.ksecuremessage.storage.server.inmemory.InMemoryServerStorage
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/**
 * Offline recovery key rotation and revocation through [SecureMessageServer]
 * (docs/recovery-key-lifecycle.md): both authorities (ServerAuth device and
 * current recovery key), the new key's proof of possession, the check
 * order, exact retry, stale transitions, the status, re-registration after
 * revocation, the effect on last-device recovery challenges, what stays
 * untouched, and races with last-device recovery and with each other.
 */
class RecoveryKeyLifecycleServerTest {
    private class ManualClock(var now: Instant) : Clock {
        override fun now(): Instant = now
    }

    private val phone = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val laptop = DeviceAddress(UserId("alice"), DeviceId("laptop"))
    private val bob = DeviceAddress(UserId("bob"), DeviceId("phone"))
    private val t0 = Instant.fromEpochMilliseconds(1_767_225_600_000)
    private val clock = ManualClock(t0)
    private val engine = KodiumProtocolEngine()

    private fun newKey(): DeviceAuthenticationKeyPair = runBlocking { engine.createDeviceAuthenticationKey() }
    private fun newRecoveryKey(): LastDeviceRecoveryKey = runBlocking { engine.createLastDeviceRecoveryKey() }

    private val phoneKey = newKey()
    private val laptopKey = newKey()
    private val bobKey = newKey()
    private val r1 = newRecoveryKey()
    private val r2 = newRecoveryKey()
    private val r3 = newRecoveryKey()

    private val keys = mapOf(phone to phoneKey, laptop to laptopKey, bob to bobKey)

    private suspend fun setUp(storage: ServerStorage = InMemoryServerStorage()): Pair<ServerStorage, SecureMessageServer<TestRegistrationPrincipal>> {
        val server = SecureMessageServer(storage, clock, TestDeviceRegistrationAuthorizer.allowAll())
        for ((address, key) in keys) {
            val body = key.publicKey
            val request = ServerRequest(address, "PUT", ServerApiPaths.device(address, ServerApiPaths.REGISTRATION), body)
            server.registerDeviceAsUserOwner(DeviceRegistration(address, key.publicKey), body, ServerRequestAuthentication.sign(key, request, clock.now()))
        }
        assertTrue(server.registerLastDeviceRecoveryKey(server.signed(laptop, ProtectedEndpoint.REGISTER_LAST_DEVICE_RECOVERY_KEY), LastDeviceRecovery.registerKey(r1, phone.userId)))
        return storage to server
    }

    private suspend fun SecureMessageServer<TestRegistrationPrincipal>.signed(
        address: DeviceAddress,
        endpoint: ProtectedEndpoint,
        key: DeviceAuthenticationKeyPair = keys.getValue(address),
    ): AuthenticatedDevice {
        val request = ServerRequest(address, endpoint.method, ServerApiPaths.device(address, endpoint.endpoint), ByteArray(0))
        return authenticate(address, endpoint, ByteArray(0), ServerRequestAuthentication.sign(key, request, clock.now()))
    }

    private fun rotation(
        current: LastDeviceRecoveryKey = r1,
        new: LastDeviceRecoveryKey = r2,
        epoch: Long = 1,
        authorizer: DeviceAddress = phone,
        nonce: RequestNonce = RequestNonce.random(),
    ) = RecoveryKeyRotation.authorize(current, new, authorizer, epoch, clock.now(), nonce)

    private fun revocation(current: LastDeviceRecoveryKey = r1, epoch: Long = 1, authorizer: DeviceAddress = phone) =
        RecoveryKeyRevocation.authorize(current, authorizer, epoch, clock.now())

    private suspend fun SecureMessageServer<TestRegistrationPrincipal>.rotate(authorization: RecoveryKeyRotationAuthorization, by: DeviceAddress = authorization.statement.authorizer) =
        rotateLastDeviceRecoveryKey(signed(by, ProtectedEndpoint.ROTATE_LAST_DEVICE_RECOVERY_KEY), authorization)

    private suspend fun SecureMessageServer<TestRegistrationPrincipal>.revoke(authorization: RecoveryKeyRevocationAuthorization, by: DeviceAddress = authorization.statement.authorizer) =
        revokeLastDeviceRecoveryKey(signed(by, ProtectedEndpoint.REVOKE_LAST_DEVICE_RECOVERY_KEY), authorization)

    /** The status as the laptop sees it (its key never changes in these tests). */
    private suspend fun SecureMessageServer<TestRegistrationPrincipal>.status(by: DeviceAddress = laptop) =
        lastDeviceRecoveryKeyStatus(signed(by, ProtectedEndpoint.READ_LAST_DEVICE_RECOVERY_KEY))

    private suspend fun SecureMessageServer<TestRegistrationPrincipal>.assertActive(key: LastDeviceRecoveryKey, epoch: Long) {
        val status = assertIs<LastDeviceRecoveryKeyStatus.Active>(status())
        assertEquals(epoch, status.epoch)
        assertTrue(status.isKey(key.publicKey))
    }

    private suspend fun ServerStorage.state(address: DeviceAddress = phone): DeviceRegistrationState = assertNotNull(devices.registrationState(address))

    /** [authorization] with its proof of possession replaced. */
    private fun RecoveryKeyRotationAuthorization.withPoP(pop: ByteArray) = RecoveryKeyRotationAuthorization(statement, currentKeySignature, pop)

    @Test
    fun statusFollowsTheLifecycle() = runTest {
        val (_, server) = setUp()
        assertEquals(LastDeviceRecoveryKeyStatus.Unconfigured, server.status(bob))
        val active = assertIs<LastDeviceRecoveryKeyStatus.Active>(server.status())
        assertEquals(1, active.epoch)
        assertEquals(t0, active.installedAt)
        assertContentEquals(r1.publicKey, active.publicKey)
        assertEquals(active, server.status(phone), "every device of the user sees the same")

        clock.now = t0 + 1.minutes
        assertEquals(RecoveryKeyRotationOutcome.ROTATED, server.rotate(rotation()))
        val rotated = assertIs<LastDeviceRecoveryKeyStatus.Active>(server.status())
        assertEquals(2, rotated.epoch)
        assertEquals(t0 + 1.minutes, rotated.installedAt, "server time")
        assertTrue(rotated.isKey(r2.publicKey))

        clock.now = t0 + 2.minutes
        assertEquals(RecoveryKeyRevocationOutcome.REVOKED, server.revoke(revocation(r2, epoch = 2)))
        assertEquals(LastDeviceRecoveryKeyStatus.Revoked(3, t0 + 2.minutes), server.status())

        clock.now = t0 + 3.minutes
        assertTrue(server.registerLastDeviceRecoveryKey(server.signed(phone, ProtectedEndpoint.REGISTER_LAST_DEVICE_RECOVERY_KEY), LastDeviceRecovery.registerKey(r3, phone.userId)))
        server.assertActive(r3, epoch = 4)

        assertFailsWith<IllegalArgumentException>("needs the status endpoint") {
            server.lastDeviceRecoveryKeyStatus(server.signed(phone, ProtectedEndpoint.DRAIN_MAILBOX))
        }
    }

    @Test
    fun rotationNeedsTheDeviceAndTheCurrentRecoveryKey() = runTest {
        val (_, server) = setUp()
        // Device only: the statement is signed by some other key than the registered R1.
        val intruder = newRecoveryKey()
        assertFailsWith<RecoveryKeyLifecycleException.Conflict> { server.rotate(rotation(current = intruder)) }
        val forged = rotation()
        assertFailsWith<RecoveryKeyLifecycleException.InvalidProof> {
            server.rotate(RecoveryKeyRotationAuthorization(forged.statement, rotation(current = r1, new = r3).currentKeySignature, forged.newKeyProofOfPossession))
        }
        // Recovery key only: no ServerAuth request, or one for another endpoint.
        assertFailsWith<DeviceAuthenticationException.MissingAuthentication> {
            server.authenticate(phone, ProtectedEndpoint.ROTATE_LAST_DEVICE_RECOVERY_KEY, ByteArray(0), null)
        }
        assertFailsWith<DeviceAuthenticationException.InvalidAuthentication>("signed by a key that is not registered") {
            server.signed(phone, ProtectedEndpoint.ROTATE_LAST_DEVICE_RECOVERY_KEY, key = newKey())
        }
        assertFailsWith<IllegalArgumentException> {
            server.rotateLastDeviceRecoveryKey(server.signed(phone, ProtectedEndpoint.REVOKE_LAST_DEVICE_RECOVERY_KEY), rotation())
        }
        // Another device than the one the statement names, of the same or another user.
        assertFailsWith<RecoveryKeyLifecycleException.InvalidRequest> { server.rotate(rotation(), by = laptop) }
        assertFailsWith<RecoveryKeyLifecycleException.InvalidRequest> { server.rotate(rotation(), by = bob) }
        // The new key must prove possession.
        val authorization = rotation()
        assertFailsWith<RecoveryKeyLifecycleException.InvalidProof> { server.rotate(authorization.withPoP(authorization.currentKeySignature)) }
        assertFailsWith<RecoveryKeyLifecycleException.InvalidProof> { server.rotate(authorization.withPoP(rotation(new = r3).newKeyProofOfPossession)) }
        server.assertActive(r1, epoch = 1)

        assertEquals(RecoveryKeyRotationOutcome.ROTATED, server.rotate(rotation(), by = phone))
        server.assertActive(r2, epoch = 2)
    }

    @Test
    fun rotationRejectionsInCheckOrder() = runTest {
        val (_, server) = setUp()
        // A user without a recovery key.
        val bobs = RecoveryKeyRotation.authorize(r1, r2, bob, 1, clock.now())
        assertFailsWith<RecoveryKeyLifecycleException.NotConfigured> { server.rotate(bobs) }
        // Window: bounds included. The server clock only moves forward here:
        // the nonce prune watermark (S1, F8) refuses requests from before a
        // time the server has already passed by more than the window.
        val early = rotation()
        clock.now = t0 + 5.minutes + 1.milliseconds
        val future = rotation()
        clock.now = t0 - 1.milliseconds
        val stale = rotation()
        clock.now = t0
        assertFailsWith<RecoveryKeyLifecycleException.Expired> { server.rotate(future) }
        // Wrong epoch or key before any signature is checked.
        assertFailsWith<RecoveryKeyLifecycleException.Conflict> { server.rotate(rotation(epoch = 2)) }
        assertFailsWith<RecoveryKeyLifecycleException.Conflict> { server.rotate(rotation(current = r3)) }
        server.assertActive(r1, epoch = 1)
        clock.now = t0 + 5.minutes
        assertFailsWith<RecoveryKeyLifecycleException.Expired> { server.rotate(stale) }
        assertEquals(RecoveryKeyRotationOutcome.ROTATED, server.rotate(early), "the window bound is inclusive")

        // A statement nonce is single-use under the authorizing device.
        val nonce = RequestNonce.random()
        clock.now = t0 + 6.minutes
        assertEquals(RecoveryKeyRotationOutcome.ROTATED, server.rotate(rotation(r2, r3, epoch = 2, nonce = nonce)))
        assertFailsWith<RecoveryKeyLifecycleException.Replay> { server.rotate(rotation(r3, r1, epoch = 3, nonce = nonce)) }
        server.assertActive(r3, epoch = 3)
    }

    @Test
    fun exactRetryIsIdempotentAndStaleRotationsAreRejected() = runTest {
        val (storage, server) = setUp()
        val first = rotation()
        clock.now = t0 + 1.minutes
        assertEquals(RecoveryKeyRotationOutcome.ROTATED, server.rotate(first))
        // The response was lost; the same request again, also long after the window.
        assertEquals(RecoveryKeyRotationOutcome.ALREADY_APPLIED, server.rotate(first))
        clock.now = t0 + 1.days
        assertEquals(RecoveryKeyRotationOutcome.ALREADY_APPLIED, server.rotate(first))
        val status = assertIs<LastDeviceRecoveryKeyStatus.Active>(server.status())
        assertEquals(2, status.epoch)
        assertEquals(t0 + 1.minutes, status.installedAt, "a retry never refreshes the installation time")
        // A retry still needs both valid proofs.
        assertFailsWith<RecoveryKeyLifecycleException.InvalidProof> { server.rotate(first.withPoP(first.currentKeySignature)) }

        // R2 -> R3, then the R1 -> R2 replay: rejected, R3 stays.
        assertEquals(RecoveryKeyRotationOutcome.ROTATED, server.rotate(rotation(r2, r3, epoch = 2)))
        assertFailsWith<RecoveryKeyLifecycleException.Expired> { server.rotate(first) }
        server.assertActive(r3, epoch = 3)
        assertEquals(1, storage.state().authEpoch, "the device registration is untouched")
    }

    @Test
    fun staleRotationReplayedInsideTheWindowIsAConflict() = runTest {
        val (_, server) = setUp()
        val first = rotation()
        clock.now = t0 + 1.minutes
        assertEquals(RecoveryKeyRotationOutcome.ROTATED, server.rotate(first))
        assertEquals(RecoveryKeyRotationOutcome.ROTATED, server.rotate(rotation(r2, r3, epoch = 2)))
        // Still inside its window, but R2 -> R3 followed: no exact retry any more.
        assertFailsWith<RecoveryKeyLifecycleException.Conflict> { server.rotate(first) }
        server.assertActive(r3, epoch = 3)
    }

    @Test
    fun revocationNeedsTheDeviceAndTheCurrentRecoveryKey() = runTest {
        val (_, server) = setUp()
        assertFailsWith<RecoveryKeyLifecycleException.Conflict> { server.revoke(revocation(current = r2)) }
        val genuine = revocation()
        assertFailsWith<RecoveryKeyLifecycleException.InvalidProof> {
            server.revoke(RecoveryKeyRevocationAuthorization(genuine.statement, revocation(current = r2).signature))
        }
        assertFailsWith<RecoveryKeyLifecycleException.InvalidRequest> { server.revoke(genuine, by = laptop) }
        assertFailsWith<IllegalArgumentException> {
            server.revokeLastDeviceRecoveryKey(server.signed(phone, ProtectedEndpoint.ROTATE_LAST_DEVICE_RECOVERY_KEY), genuine)
        }
        assertFailsWith<RecoveryKeyLifecycleException.Conflict> { server.revoke(revocation(epoch = 2)) }
        server.assertActive(r1, epoch = 1)

        assertEquals(RecoveryKeyRevocationOutcome.REVOKED, server.revoke(genuine))
        assertEquals(RecoveryKeyRevocationOutcome.ALREADY_APPLIED, server.revoke(genuine))
        clock.now = t0 + 1.days
        assertEquals(RecoveryKeyRevocationOutcome.ALREADY_APPLIED, server.revoke(genuine))
        assertEquals(LastDeviceRecoveryKeyStatus.Revoked(2, t0), server.status())
        // Nothing but registration works on a revoked key.
        assertFailsWith<RecoveryKeyLifecycleException.NotConfigured> { server.revoke(revocation(epoch = 2)) }
        assertFailsWith<RecoveryKeyLifecycleException.NotConfigured> { server.rotate(rotation(epoch = 2)) }
    }

    @Test
    fun lastDeviceRecoveryAfterRotation() = runTest {
        val (storage, server) = setUp()
        val oldChallenge = server.lastDeviceRecoveryChallenge(phone)
        val oldAuthorization = LastDeviceRecovery.authorize(r1, newKey(), oldChallenge)
        assertEquals(RecoveryKeyRotationOutcome.ROTATED, server.rotate(rotation(authorizer = laptop)))

        // R1 recovers nothing any more, and the challenge issued under R1 is gone.
        assertFailsWith<LastDeviceRecoveryException.InvalidProof> { server.recoverLastDevice(phone, oldAuthorization) }
        assertFailsWith<LastDeviceRecoveryException.ChallengeInvalid> {
            server.recoverLastDevice(phone, LastDeviceRecovery.authorize(r2, newKey(), oldChallenge))
        }
        assertEquals(1, storage.state().authEpoch)

        // A new challenge with R2 recovers the device.
        val k2 = newKey()
        val challenge = server.lastDeviceRecoveryChallenge(phone)
        assertTrue(challenge.id != oldChallenge.id)
        assertEquals(LastDeviceRecoveryOutcome.REPLACED, server.recoverLastDevice(phone, LastDeviceRecovery.authorize(r2, k2, challenge)))
        assertContentEquals(k2.publicKey, storage.state().registration.publicKey)
        server.assertActive(r2, epoch = 2)
    }

    @Test
    fun revocationEndsLastDeviceRecoveryUntilANewKeyIsRegistered() = runTest {
        val (storage, server) = setUp()
        val outstanding = LastDeviceRecovery.authorize(r1, newKey(), server.lastDeviceRecoveryChallenge(phone))
        assertEquals(RecoveryKeyRevocationOutcome.REVOKED, server.revoke(revocation(authorizer = laptop)))

        assertFailsWith<LastDeviceRecoveryException.NotConfigured> { server.lastDeviceRecoveryChallenge(phone) }
        assertFailsWith<LastDeviceRecoveryException.NotConfigured> { server.recoverLastDevice(phone, outstanding) }
        assertNull(storage.lastDeviceRecovery.challenge(phone), "removed with the revocation, not left to expire")

        // Registration after the revocation: explicit, authenticated, the epoch continues.
        assertTrue(server.registerLastDeviceRecoveryKey(server.signed(laptop, ProtectedEndpoint.REGISTER_LAST_DEVICE_RECOVERY_KEY), LastDeviceRecovery.registerKey(r3, phone.userId)))
        server.assertActive(r3, epoch = 3)
        assertFailsWith<LastDeviceRecoveryException.InvalidProof> { server.recoverLastDevice(phone, outstanding) }
        assertFailsWith<LastDeviceRecoveryException.InvalidProof> {
            server.recoverLastDevice(phone, LastDeviceRecovery.authorize(r1, newKey(), server.lastDeviceRecoveryChallenge(phone)))
        }
        val k2 = newKey()
        assertEquals(LastDeviceRecoveryOutcome.REPLACED, server.recoverLastDevice(phone, LastDeviceRecovery.authorize(r3, k2, server.lastDeviceRecoveryChallenge(phone))))
        assertContentEquals(k2.publicKey, storage.state().registration.publicKey)
    }

    @Test
    fun transitionsLeaveMessagingAndDeviceStateAlone() = runTest {
        val (storage, server) = setUp()
        val publication = PreKeyPublication(
            phone,
            ByteArray(PreKeyFormat.PUBLIC_KEY_SIZE) { 1 },
            PublicSignedPreKey(SignedPreKeyId(0), ByteArray(PreKeyFormat.PUBLIC_KEY_SIZE) { 2 }, ByteArray(PreKeyFormat.SIGNATURE_SIZE) { 3 }),
            (0..2).map { PublicOneTimePreKey(OneTimePreKeyId(it), ByteArray(PreKeyFormat.PUBLIC_KEY_SIZE) { _ -> (10 + it).toByte() }) },
        )
        server.publishPreKeys(server.signed(phone, ProtectedEndpoint.PUBLISH_PRE_KEYS), publication)
        assertEquals(OneTimePreKeyId(0), server.fetchPreKeyBundle(phone)?.oneTimePreKey?.id)
        storage.mailboxes.enqueue(EncryptedEnvelope(MessageId("m1"), bob, phone, payload = byteArrayOf(7)))
        val before = keys.keys.map { storage.state(it) }

        assertEquals(RecoveryKeyRotationOutcome.ROTATED, server.rotate(rotation()))
        assertEquals(RecoveryKeyRevocationOutcome.REVOKED, server.revoke(revocation(r2, epoch = 2)))

        for ((old, address) in before.zip(keys.keys)) {
            val now = storage.state(address)
            assertContentEquals(old.registration.publicKey, now.registration.publicKey)
            assertEquals(old.authEpoch, now.authEpoch)
            assertEquals(old.authKeyInstalledAt, now.authKeyInstalledAt)
        }
        assertEquals(2, storage.preKeys.oneTimePreKeyCount(phone))
        assertEquals(OneTimePreKeyId(1), server.fetchPreKeyBundle(phone)?.oneTimePreKey?.id)
        assertEquals(listOf("m1"), server.receive(server.signed(phone, ProtectedEndpoint.DRAIN_MAILBOX)).map { it.id.value })
    }

    @Test
    fun concurrentIdenticalRotationsRotateOnce() = runTest {
        val (_, server) = setUp()
        val authorization = rotation()
        val outcomes = withContext(Dispatchers.Default) {
            // Every submission is its own ServerAuth request (fresh nonce) carrying the same statement.
            List(32) { async { server.rotate(authorization) } }.awaitAll()
        }
        assertEquals(1, outcomes.count { it == RecoveryKeyRotationOutcome.ROTATED })
        assertEquals(31, outcomes.count { it == RecoveryKeyRotationOutcome.ALREADY_APPLIED })
        server.assertActive(r2, epoch = 2)
    }

    @Test
    fun concurrentCompetingRotationsHaveOneWinner() = runTest {
        val (_, server) = setUp()
        val targets = List(32) { newRecoveryKey() }
        val outcomes = withContext(Dispatchers.Default) {
            targets.map { target -> async { runCatching { server.rotate(rotation(new = target)) } } }.awaitAll()
        }
        val winners = outcomes.withIndex().filter { it.value.isSuccess }
        assertEquals(1, winners.size)
        assertTrue(outcomes.filter { it.isFailure }.all { it.exceptionOrNull() is RecoveryKeyLifecycleException.Conflict })
        server.assertActive(targets[winners.single().index], epoch = 2)
    }

    @Test
    fun rotationAndRevocationVerifiedAgainstTheSameStateHaveOneWinner() = runTest {
        for (rotationFirst in listOf(true, false)) {
            val gated = GatedStorage(InMemoryServerStorage(), "rotate", "revoke")
            val (_, server) = setUp(gated)
            val (rotated, revoked) = gated.race(
                rotationFirst,
                { server.rotate(rotation()) },
                { server.revoke(revocation(authorizer = laptop)) },
            )
            if (rotationFirst) {
                assertEquals(RecoveryKeyRotationOutcome.ROTATED, rotated.getOrThrow())
                assertIs<RecoveryKeyLifecycleException.Conflict>(revoked.exceptionOrNull())
                server.assertActive(r2, epoch = 2)
            } else {
                assertEquals(RecoveryKeyRevocationOutcome.REVOKED, revoked.getOrThrow())
                assertIs<RecoveryKeyLifecycleException.Conflict>(rotated.exceptionOrNull())
                assertIs<LastDeviceRecoveryKeyStatus.Revoked>(server.status())
            }
        }
    }

    @Test
    fun rotationAndLastDeviceRecoveryInBothOrders() = runTest {
        for (rotationFirst in listOf(true, false)) {
            val gated = GatedStorage(InMemoryServerStorage(), "rotate", "lastDevice")
            val (storage, server) = setUp(gated)
            val k2 = newKey()
            val recovery = LastDeviceRecovery.authorize(r1, k2, server.lastDeviceRecoveryChallenge(phone))
            // The laptop authorizes the rotation; the phone is recovered.
            val (rotated, recovered) = gated.race(
                rotationFirst,
                { server.rotate(rotation(authorizer = laptop)) },
                { server.recoverLastDevice(phone, recovery) },
            )
            assertEquals(RecoveryKeyRotationOutcome.ROTATED, rotated.getOrThrow(), "a device transition never changes the recovery key state")
            server.assertActive(r2, epoch = 2)
            if (rotationFirst) {
                assertIs<LastDeviceRecoveryException.NotConfigured>(recovered.exceptionOrNull(), "R1 no longer authorizes")
                assertEquals(1, storage.state().authEpoch)
            } else {
                assertEquals(LastDeviceRecoveryOutcome.REPLACED, recovered.getOrThrow())
                assertContentEquals(k2.publicKey, storage.state().registration.publicKey)
            }
            assertNull(storage.lastDeviceRecovery.challenge(phone))
        }
    }

    @Test
    fun rotationByTheRecoveredDeviceAndItsLastDeviceRecoveryHaveOneWinner() = runTest {
        for (rotationFirst in listOf(true, false)) {
            val gated = GatedStorage(InMemoryServerStorage(), "rotate", "lastDevice")
            val (storage, server) = setUp(gated)
            val k2 = newKey()
            val recovery = LastDeviceRecovery.authorize(r1, k2, server.lastDeviceRecoveryChallenge(phone))
            val (rotated, recovered) = gated.race(
                rotationFirst,
                { server.rotate(rotation(authorizer = phone)) },
                { server.recoverLastDevice(phone, recovery) },
            )
            if (rotationFirst) {
                assertEquals(RecoveryKeyRotationOutcome.ROTATED, rotated.getOrThrow())
                assertIs<LastDeviceRecoveryException.NotConfigured>(recovered.exceptionOrNull())
                assertEquals(1, storage.state().authEpoch)
            } else {
                assertEquals(LastDeviceRecoveryOutcome.REPLACED, recovered.getOrThrow())
                // The phone's authentication was replaced before the rotation committed.
                assertIs<RecoveryKeyLifecycleException.Conflict>(rotated.exceptionOrNull())
                server.assertActive(r1, epoch = 1)
            }
        }
    }

    @Test
    fun revocationAndLastDeviceRecoveryInBothOrders() = runTest {
        for (revocationFirst in listOf(true, false)) {
            val gated = GatedStorage(InMemoryServerStorage(), "revoke", "lastDevice")
            val (storage, server) = setUp(gated)
            val k2 = newKey()
            val recovery = LastDeviceRecovery.authorize(r1, k2, server.lastDeviceRecoveryChallenge(phone))
            val (revoked, recovered) = gated.race(
                revocationFirst,
                { server.revoke(revocation(authorizer = laptop)) },
                { server.recoverLastDevice(phone, recovery) },
            )
            assertEquals(RecoveryKeyRevocationOutcome.REVOKED, revoked.getOrThrow())
            assertIs<LastDeviceRecoveryKeyStatus.Revoked>(server.status(laptop))
            if (revocationFirst) {
                assertIs<LastDeviceRecoveryException.NotConfigured>(recovered.exceptionOrNull())
                assertEquals(1, storage.state().authEpoch)
            } else {
                assertEquals(LastDeviceRecoveryOutcome.REPLACED, recovered.getOrThrow())
                assertContentEquals(k2.publicKey, storage.state().registration.publicKey)
            }
            assertFailsWith<LastDeviceRecoveryException.NotConfigured> { server.lastDeviceRecoveryChallenge(phone) }
        }
    }

    /**
     * Delegates to [delegate]; while armed (by [race]), holds the first
     * storage call of kind [first] and of kind [second] (`rotate`,
     * `revoke`, `lastDevice`) until the race releases them in the chosen
     * order, after both passed the service's checks against the same state.
     */
    private class GatedStorage(private val delegate: ServerStorage, private val first: String, private val second: String) :
        ServerStorage by delegate {
        private var armed = false
        private val arrived = mapOf(first to CompletableDeferred<Unit>(), second to CompletableDeferred<Unit>())
        private val gates = mapOf(first to CompletableDeferred<Unit>(), second to CompletableDeferred<Unit>())

        private suspend fun arrive(kind: String) {
            if (!armed || kind !in gates) return
            arrived.getValue(kind).complete(Unit)
            gates.getValue(kind).await()
        }

        suspend fun <A, B> race(firstWins: Boolean, a: suspend () -> A, b: suspend () -> B): Pair<Result<A>, Result<B>> {
            armed = true
            return withContext(Dispatchers.Default) {
                val left = async { runCatching { a() } }
                val right = async { runCatching { b() } }
                arrived.values.awaitAll()
                val order = if (firstWins) listOf(first, second) else listOf(second, first)
                gates.getValue(order[0]).complete(Unit)
                if (order[0] == first) left.join() else right.join()
                gates.getValue(order[1]).complete(Unit)
                left.await() to right.await()
            }
        }

        override val devices: DeviceRegistrationRepository = object : DeviceRegistrationRepository by delegate.devices {
            override suspend fun replaceForLastDeviceRecovery(replacement: LastDeviceRecoveryReplacement): LastDeviceRecoveryReplacementResult {
                arrive("lastDevice")
                return delegate.devices.replaceForLastDeviceRecovery(replacement)
            }
        }

        override val lastDeviceRecovery: LastDeviceRecoveryRepository = object : LastDeviceRecoveryRepository by delegate.lastDeviceRecovery {
            override suspend fun rotateRecoveryKey(transition: RecoveryKeyRotationTransition): RecoveryKeyRotationResult {
                arrive("rotate")
                return delegate.lastDeviceRecovery.rotateRecoveryKey(transition)
            }

            override suspend fun revokeRecoveryKey(transition: RecoveryKeyRevocationTransition): RecoveryKeyRevocationResult {
                arrive("revoke")
                return delegate.lastDeviceRecovery.revokeRecoveryKey(transition)
            }
        }
    }
}
