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
import dev.kreienbuehl.ksecuremessage.model.RecoveryKeyResetId
import dev.kreienbuehl.ksecuremessage.model.RecoveryKeyResetStatus
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecovery
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryKey
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyReset
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyResetCompletionAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyResetCompletionStatement
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyResetStatusQuery
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRevocation
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRotation
import dev.kreienbuehl.ksecuremessage.protocol.ServerApiPaths
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequest
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequestAuthentication
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationRepository
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationState
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryReplacement
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryReplacementResult
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryRepository
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyResetCancellation
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyResetCancellationResult
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyResetCompletionResult
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyResetCompletionTransition
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
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.nanoseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant

/**
 * Delayed recovery key reset through [SecureMessageServer]
 * (docs/recovery-key-reset.md): the host policy (and none), server-only
 * timing, one pending reset per user that repeated requests never restart,
 * visibility to every device of the user and to the current recovery key
 * only, the completion check order and eligibility boundary, the new key's
 * proof of possession, exact retry, both cancellation authorities, the
 * interaction with rotation, revocation and last-device recovery (gated
 * races in both orders), and what stays untouched.
 */
class RecoveryKeyResetServerTest {
    private class ManualClock(var now: Instant) : Clock {
        override fun now(): Instant = now
    }

    private val phone = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val laptop = DeviceAddress(UserId("alice"), DeviceId("laptop"))
    private val bob = DeviceAddress(UserId("bob"), DeviceId("phone"))
    private val t0 = Instant.fromEpochMilliseconds(1_767_225_600_000)
    private val delay = 3.days
    private val eligible = t0 + delay
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
    private val bobRecovery = newRecoveryKey()

    private val keys = mutableMapOf(phone to phoneKey, laptop to laptopKey, bob to bobKey)

    private suspend fun setUp(
        storage: ServerStorage = InMemoryServerStorage(),
        policy: RecoveryKeyResetPolicy? = RecoveryKeyResetPolicy(delay),
    ): Pair<ServerStorage, SecureMessageServer> {
        val server = SecureMessageServer(storage, clock, policy)
        for ((address, key) in keys) {
            val body = key.publicKey
            val request = ServerRequest(address, "PUT", ServerApiPaths.device(address, ServerApiPaths.REGISTRATION), body)
            server.registerDevice(DeviceRegistration(address, key.publicKey), body, ServerRequestAuthentication.sign(key, request, clock.now()))
        }
        assertTrue(server.registerLastDeviceRecoveryKey(server.signed(laptop, ProtectedEndpoint.REGISTER_LAST_DEVICE_RECOVERY_KEY), LastDeviceRecovery.registerKey(r1, phone.userId)))
        assertTrue(server.registerLastDeviceRecoveryKey(server.signed(bob, ProtectedEndpoint.REGISTER_LAST_DEVICE_RECOVERY_KEY), LastDeviceRecovery.registerKey(bobRecovery, bob.userId)))
        return storage to server
    }

    private suspend fun SecureMessageServer.signed(
        address: DeviceAddress,
        endpoint: ProtectedEndpoint,
        key: DeviceAuthenticationKeyPair = keys.getValue(address),
    ): AuthenticatedDevice {
        val request = ServerRequest(address, endpoint.method, ServerApiPaths.device(address, endpoint.endpoint), ByteArray(0))
        return authenticate(address, endpoint, ByteArray(0), ServerRequestAuthentication.sign(key, request, clock.now()))
    }

    private suspend fun SecureMessageServer.request(by: DeviceAddress = phone) =
        requestLastDeviceRecoveryKeyReset(signed(by, ProtectedEndpoint.REQUEST_LAST_DEVICE_RECOVERY_KEY_RESET))

    private suspend fun SecureMessageServer.pending(by: DeviceAddress = phone): RecoveryKeyResetStatus.Pending = request(by).reset

    private suspend fun SecureMessageServer.resetStatus(by: DeviceAddress = laptop) =
        lastDeviceRecoveryKeyResetStatus(signed(by, ProtectedEndpoint.READ_LAST_DEVICE_RECOVERY_KEY_RESET))

    private suspend fun SecureMessageServer.complete(
        reset: RecoveryKeyResetStatus.Pending,
        new: LastDeviceRecoveryKey = r2,
        by: DeviceAddress = laptop,
    ) = complete(RecoveryKeyReset.complete(new, reset, by), by)

    private suspend fun SecureMessageServer.complete(authorization: RecoveryKeyResetCompletionAuthorization, by: DeviceAddress = authorization.statement.completer) =
        completeLastDeviceRecoveryKeyReset(signed(by, ProtectedEndpoint.COMPLETE_LAST_DEVICE_RECOVERY_KEY_RESET), authorization)

    private suspend fun SecureMessageServer.cancel(reset: RecoveryKeyResetStatus.Pending, by: DeviceAddress = laptop) =
        cancelLastDeviceRecoveryKeyReset(signed(by, ProtectedEndpoint.CANCEL_LAST_DEVICE_RECOVERY_KEY_RESET), reset.resetId)

    private suspend fun SecureMessageServer.keyStatus(by: DeviceAddress = laptop) =
        lastDeviceRecoveryKeyStatus(signed(by, ProtectedEndpoint.READ_LAST_DEVICE_RECOVERY_KEY))

    private suspend fun SecureMessageServer.assertActive(key: LastDeviceRecoveryKey, epoch: Long) {
        val status = assertIs<LastDeviceRecoveryKeyStatus.Active>(keyStatus())
        assertEquals(epoch, status.epoch)
        assertTrue(status.isKey(key.publicKey))
    }

    private suspend fun ServerStorage.state(address: DeviceAddress = phone): DeviceRegistrationState = assertNotNull(devices.registrationState(address))

    @Test
    fun aRequestIsTimedByTheServerOnly() = runTest {
        val (_, server) = setUp()
        clock.now = t0 + 123.milliseconds + 456.nanoseconds
        val outcome = server.request()
        assertTrue(outcome.created)
        val reset = outcome.reset
        assertEquals(t0 + 123.milliseconds, reset.requestedAt, "server time, whole milliseconds")
        assertEquals(t0 + 123.milliseconds + delay, reset.eligibleAt)
        assertEquals(phone, reset.requestedBy)
        assertEquals(1, reset.recoveryKeyEpoch)
        assertContentEquals(r1.publicKey, reset.recoveryPublicKey)
        server.assertActive(r1, epoch = 1)
    }

    @Test
    fun theDelayIsRoundedUpToWholeMilliseconds() {
        assertEquals(t0 + 2.milliseconds, RecoveryKeyResetPolicy(1.milliseconds + 1.nanoseconds).eligibleAt(t0))
        assertEquals(t0 + 1.seconds, RecoveryKeyResetPolicy(1.seconds).eligibleAt(t0))
        assertFailsWith<IllegalArgumentException> { RecoveryKeyResetPolicy(0.seconds) }
        assertFailsWith<IllegalArgumentException> { RecoveryKeyResetPolicy((-1).seconds) }
        assertFailsWith<IllegalArgumentException> { RecoveryKeyResetPolicy(kotlin.time.Duration.INFINITE) }
        assertFailsWith<IllegalStateException> { RecoveryKeyResetPolicy(1.days).eligibleAt(Instant.fromEpochMilliseconds(Long.MAX_VALUE - 10)) }
    }

    @Test
    fun withoutAPolicyRequestsAreRefused() = runTest {
        val (storage, server) = setUp(policy = null)
        assertFailsWith<RecoveryKeyResetException.NotAvailable> { server.request() }
        assertSame(RecoveryKeyResetStatus.None, server.resetStatus())
        assertNull(storage.lastDeviceRecovery.pendingRecoveryKeyReset(phone.userId))
    }

    @Test
    fun aRepeatedRequestNeverRestartsTheDelay() = runTest {
        val (_, server) = setUp()
        val reset = server.pending()
        for (step in listOf(1.hours, delay, 2.days)) {
            clock.now = t0 + step
            val again = server.request(laptop)
            assertFalse(again.created)
            assertEquals(reset, again.reset)
        }
        assertEquals(reset, server.resetStatus(phone))
    }

    @Test
    fun onlyAnActiveKeyCanBeReset() = runTest {
        val (_, server) = setUp()
        assertIs<RecoveryKeyRevocationOutcome>(
            server.revokeLastDeviceRecoveryKey(
                server.signed(phone, ProtectedEndpoint.REVOKE_LAST_DEVICE_RECOVERY_KEY), RecoveryKeyRevocation.authorize(r1, phone, 1, clock.now()),
            ),
        )
        assertFailsWith<RecoveryKeyResetException.NotConfigured> { server.request() }
        val carol = DeviceAddress(UserId("carol"), DeviceId("phone"))
        keys[carol] = newKey()
        val (_, other) = setUp()
        assertFailsWith<RecoveryKeyResetException.NotConfigured> { other.request(carol) }
    }

    @Test
    fun theResetIsVisibleToEveryDeviceOfTheUserAndNoOneElse() = runTest {
        val (_, server) = setUp()
        val reset = server.pending(phone)
        assertEquals(reset, server.resetStatus(phone))
        assertEquals(reset, server.resetStatus(laptop))
        assertSame(RecoveryKeyResetStatus.None, server.resetStatus(bob), "another user sees only its own state")
        // Authentication is the device's own: bob cannot read alice's by signing for alice's address.
        assertFailsWith<DeviceAuthenticationException.InvalidAuthentication> {
            server.lastDeviceRecoveryKeyResetStatus(server.signed(phone, ProtectedEndpoint.READ_LAST_DEVICE_RECOVERY_KEY_RESET, key = bobKey))
        }
        // An endpoint's authentication does not serve another one.
        assertFailsWith<IllegalArgumentException> { server.lastDeviceRecoveryKeyResetStatus(server.signed(phone, ProtectedEndpoint.READ_LAST_DEVICE_RECOVERY_KEY)) }
    }

    @Test
    fun theCurrentRecoveryKeyQueriesTheStatus() = runTest {
        val (_, server) = setUp()
        assertSame(RecoveryKeyResetStatus.None, server.lastDeviceRecoveryKeyResetStatusByRecoveryKey(RecoveryKeyReset.statusQuery(r1, phone.userId, clock.now())))
        val reset = server.pending()
        assertEquals(reset, server.lastDeviceRecoveryKeyResetStatusByRecoveryKey(RecoveryKeyReset.statusQuery(r1, phone.userId, clock.now())))
        // Window bounds included.
        assertEquals(reset, server.lastDeviceRecoveryKeyResetStatusByRecoveryKey(RecoveryKeyReset.statusQuery(r1, phone.userId, t0 - 5.minutes)))
        assertEquals(reset, server.lastDeviceRecoveryKeyResetStatusByRecoveryKey(RecoveryKeyReset.statusQuery(r1, phone.userId, t0 + 5.minutes)))
        assertFailsWith<RecoveryKeyResetException.Expired> {
            server.lastDeviceRecoveryKeyResetStatusByRecoveryKey(RecoveryKeyReset.statusQuery(r1, phone.userId, t0 - 5.minutes - 1.milliseconds))
        }
        // Another key, another user's key, or a forged signature learn nothing.
        assertFailsWith<RecoveryKeyResetException.InvalidProof> {
            server.lastDeviceRecoveryKeyResetStatusByRecoveryKey(RecoveryKeyReset.statusQuery(r2, phone.userId, clock.now()))
        }
        assertFailsWith<RecoveryKeyResetException.InvalidProof> {
            server.lastDeviceRecoveryKeyResetStatusByRecoveryKey(RecoveryKeyReset.statusQuery(bobRecovery, phone.userId, clock.now()))
        }
        val genuine = RecoveryKeyReset.statusQuery(r1, phone.userId, clock.now())
        assertFailsWith<RecoveryKeyResetException.InvalidProof> {
            server.lastDeviceRecoveryKeyResetStatusByRecoveryKey(RecoveryKeyResetStatusQuery(genuine.statement, ByteArray(64)))
        }
        assertSame(RecoveryKeyResetStatus.None, server.lastDeviceRecoveryKeyResetStatusByRecoveryKey(RecoveryKeyReset.statusQuery(bobRecovery, bob.userId, clock.now())))
    }

    @Test
    fun completionOnlyFromTheEligibilityTime() = runTest {
        val (storage, server) = setUp()
        val reset = server.pending()
        clock.now = eligible - 1.milliseconds
        assertFailsWith<RecoveryKeyResetException.NotYetEligible> { server.complete(reset) }
        server.assertActive(r1, epoch = 1)
        assertEquals(reset, server.resetStatus())

        clock.now = eligible
        val challenge = server.lastDeviceRecoveryChallenge(phone)
        assertEquals(RecoveryKeyResetCompletionOutcome.COMPLETED, server.complete(reset))
        server.assertActive(r2, epoch = 2)
        assertEquals(eligible, assertIs<LastDeviceRecoveryKeyStatus.Active>(server.keyStatus()).installedAt, "completion server time")
        assertSame(RecoveryKeyResetStatus.None, server.resetStatus())
        assertNull(storage.lastDeviceRecovery.challenge(phone), "old challenges are gone")
        assertFailsWith<LastDeviceRecoveryException.InvalidProof> {
            server.recoverLastDevice(phone, LastDeviceRecovery.authorize(r1, newKey(), challenge))
        }
        // A new challenge works with R2 only.
        val k2 = newKey()
        assertEquals(LastDeviceRecoveryOutcome.REPLACED, server.recoverLastDevice(phone, LastDeviceRecovery.authorize(r2, k2, server.lastDeviceRecoveryChallenge(phone))))
    }

    @Test
    fun completionInstallsTheCompletionTimeNotTheRequestOrEligibilityTime() = runTest {
        val (_, server) = setUp()
        val reset = server.pending()
        clock.now = eligible + 2.days + 7.milliseconds
        assertEquals(RecoveryKeyResetCompletionOutcome.COMPLETED, server.complete(reset))
        assertEquals(eligible + 2.days + 7.milliseconds, assertIs<LastDeviceRecoveryKeyStatus.Active>(server.keyStatus()).installedAt)
    }

    @Test
    fun completionCheckOrder() = runTest {
        val (_, server) = setUp()
        val reset = server.pending()
        clock.now = eligible
        // The statement names another device than the authenticated one.
        assertFailsWith<RecoveryKeyResetException.InvalidRequest> { server.complete(RecoveryKeyReset.complete(r2, reset, phone), by = laptop) }
        // Another reset ID.
        val other = RecoveryKeyResetStatus.Pending(RecoveryKeyResetId(ByteArray(16) { 9 }), reset.requestedBy, reset.requestedAt, reset.eligibleAt, 1, r1.publicKey)
        assertFailsWith<RecoveryKeyResetException.NotPending> { server.complete(other) }
        // A statement with other times or another key than the pending reset.
        for (changed in listOf(
            RecoveryKeyResetStatus.Pending(reset.resetId, reset.requestedBy, reset.requestedAt - 1.milliseconds, reset.eligibleAt, 1, r1.publicKey),
            RecoveryKeyResetStatus.Pending(reset.resetId, reset.requestedBy, reset.requestedAt, reset.eligibleAt - 1.days, 1, r1.publicKey),
            RecoveryKeyResetStatus.Pending(reset.resetId, reset.requestedBy, reset.requestedAt, reset.eligibleAt, 2, r1.publicKey),
            RecoveryKeyResetStatus.Pending(reset.resetId, reset.requestedBy, reset.requestedAt, reset.eligibleAt, 1, r3.publicKey),
        )) {
            assertFailsWith<RecoveryKeyResetException.Conflict>(changed.toString()) { server.complete(changed) }
        }
        // The proof of possession must be the new key's.
        val genuine = RecoveryKeyReset.complete(r2, reset, laptop)
        assertFailsWith<RecoveryKeyResetException.InvalidProof> {
            server.complete(RecoveryKeyResetCompletionAuthorization(genuine.statement, RecoveryKeyReset.complete(r3, reset, laptop).newKeyProofOfPossession))
        }
        val s = genuine.statement
        // A statement for R2 = R1 is unrepresentable.
        assertFailsWith<IllegalArgumentException> {
            RecoveryKeyResetCompletionStatement(s.userId, s.resetId, s.expectedEpoch, s.currentPublicKey, r1.publicKey, s.requestedAt, s.eligibleAt, s.completer)
        }
        server.assertActive(r1, epoch = 1)
        assertEquals(reset, server.resetStatus())
        assertEquals(RecoveryKeyResetCompletionOutcome.COMPLETED, server.complete(genuine))
    }

    @Test
    fun anotherUsersDeviceCannotCompleteOrCancel() = runTest {
        val (_, server) = setUp()
        val reset = server.pending()
        clock.now = eligible
        assertFailsWith<IllegalArgumentException> { RecoveryKeyReset.complete(r2, reset, bob) }
        // Bob's device completing its own user's (non-existent) reset with alice's reset ID.
        val forBob = RecoveryKeyResetStatus.Pending(reset.resetId, bob, reset.requestedAt, reset.eligibleAt, 1, bobRecovery.publicKey)
        assertFailsWith<RecoveryKeyResetException.NotPending> { server.complete(forBob, by = bob) }
        assertFailsWith<RecoveryKeyResetException.NotPending> { server.cancel(reset, by = bob) }
        assertEquals(reset, server.resetStatus())
    }

    @Test
    fun exactRetriesAreIdempotentAfterTheWindowAndAcrossDevices() = runTest {
        val (_, server) = setUp()
        val reset = server.pending()
        clock.now = eligible
        val completion = RecoveryKeyReset.complete(r2, reset, laptop)
        assertEquals(RecoveryKeyResetCompletionOutcome.COMPLETED, server.complete(completion))
        clock.now = eligible + 30.days
        assertEquals(RecoveryKeyResetCompletionOutcome.ALREADY_APPLIED, server.complete(completion))
        server.assertActive(r2, epoch = 2)
        assertEquals(eligible, assertIs<LastDeviceRecoveryKeyStatus.Active>(server.keyStatus()).installedAt, "retry never refreshes")
        // The same reset completed by another device is not an exact retry.
        assertFailsWith<RecoveryKeyResetException.NotPending> { server.complete(reset, by = phone) }
        // A retry whose proof is broken is refused even though the ID matches.
        assertFailsWith<RecoveryKeyResetException.InvalidProof> {
            server.complete(RecoveryKeyResetCompletionAuthorization(completion.statement, ByteArray(64)))
        }
    }

    @Test
    fun anyDeviceOfTheUserCancels() = runTest {
        val (storage, server) = setUp()
        val challenge = server.lastDeviceRecoveryChallenge(phone)
        val reset = server.pending(phone)
        clock.now = eligible + 1.days // still pending after eligibility: nothing completes on its own
        server.cancel(reset, by = laptop)
        assertSame(RecoveryKeyResetStatus.None, server.resetStatus())
        server.assertActive(r1, epoch = 1)
        assertEquals(challenge.id, storage.lastDeviceRecovery.challenge(phone)?.challenge?.id, "challenges stay")
        assertFailsWith<RecoveryKeyResetException.NotPending> { server.cancel(reset, by = phone) }
        assertFailsWith<RecoveryKeyResetException.NotPending> { server.complete(reset) }
        // A new request after the cancellation gets a new ID and a full delay.
        val next = server.pending(laptop)
        assertFalse(next.resetId == reset.resetId)
        assertEquals(clock.now + delay, next.eligibleAt)
    }

    @Test
    fun theCurrentRecoveryKeyCancelsWithoutADevice() = runTest {
        val (storage, server) = setUp()
        val challenge = server.lastDeviceRecoveryChallenge(phone)
        val reset = server.pending()
        // A key that is not the reset one cannot even build the cancellation; a forged signature is refused.
        assertFailsWith<IllegalArgumentException> { RecoveryKeyReset.cancel(r2, reset) }
        val genuine = RecoveryKeyReset.cancel(r1, reset)
        assertFailsWith<RecoveryKeyResetException.InvalidProof> {
            server.cancelLastDeviceRecoveryKeyResetByRecoveryKey(dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyResetCancellationAuthorization(genuine.statement, ByteArray(64)))
        }
        val mismatch = RecoveryKeyResetStatus.Pending(reset.resetId, reset.requestedBy, reset.requestedAt, reset.eligibleAt + 1.milliseconds, 1, r1.publicKey)
        assertFailsWith<RecoveryKeyResetException.Conflict> { server.cancelLastDeviceRecoveryKeyResetByRecoveryKey(RecoveryKeyReset.cancel(r1, mismatch)) }
        assertEquals(reset, server.resetStatus())
        server.cancelLastDeviceRecoveryKeyResetByRecoveryKey(genuine)
        assertSame(RecoveryKeyResetStatus.None, server.resetStatus())
        server.assertActive(r1, epoch = 1)
        assertEquals(challenge.id, storage.lastDeviceRecovery.challenge(phone)?.challenge?.id)
        assertFailsWith<RecoveryKeyResetException.NotPending> { server.cancelLastDeviceRecoveryKeyResetByRecoveryKey(genuine) }
    }

    @Test
    fun aCompletedResetIsNeverRolledBack() = runTest {
        val (_, server) = setUp()
        val reset = server.pending()
        val cancellation = RecoveryKeyReset.cancel(r1, reset)
        clock.now = eligible
        assertEquals(RecoveryKeyResetCompletionOutcome.COMPLETED, server.complete(reset))
        assertFailsWith<RecoveryKeyResetException.NotPending> { server.cancelLastDeviceRecoveryKeyResetByRecoveryKey(cancellation) }
        assertFailsWith<RecoveryKeyResetException.NotPending> { server.cancel(reset) }
        server.assertActive(r2, epoch = 2)
        // A later reset of R2 starts a new full delay.
        val next = server.pending()
        assertEquals(2, next.recoveryKeyEpoch)
        assertContentEquals(r2.publicKey, next.recoveryPublicKey)
        assertEquals(eligible + delay, next.eligibleAt)
    }

    @Test
    fun rotationAndRevocationRemoveAStaleReset() = runTest {
        val (_, server) = setUp()
        val reset = server.pending()
        // R1 turns up again: the normal rotation wins and the reset is gone.
        assertEquals(
            RecoveryKeyRotationOutcome.ROTATED,
            server.rotateLastDeviceRecoveryKey(server.signed(phone, ProtectedEndpoint.ROTATE_LAST_DEVICE_RECOVERY_KEY), RecoveryKeyRotation.authorize(r1, r3, phone, 1, clock.now())),
        )
        assertSame(RecoveryKeyResetStatus.None, server.resetStatus())
        clock.now = eligible
        assertFailsWith<RecoveryKeyResetException.NotPending> { server.complete(reset) }
        server.assertActive(r3, epoch = 2)

        val (_, revoking) = setUp()
        val revokedReset = revoking.pending()
        revoking.revokeLastDeviceRecoveryKey(revoking.signed(phone, ProtectedEndpoint.REVOKE_LAST_DEVICE_RECOVERY_KEY), RecoveryKeyRevocation.authorize(r1, phone, 1, clock.now()))
        assertSame(RecoveryKeyResetStatus.None, revoking.resetStatus())
        assertFailsWith<RecoveryKeyResetException.NotConfigured> { revoking.complete(revokedReset) }
        assertFailsWith<RecoveryKeyResetException.NotPending> { revoking.cancelLastDeviceRecoveryKeyResetByRecoveryKey(RecoveryKeyReset.cancel(r1, revokedReset)) }
    }

    @Test
    fun theCurrentKeyStaysAuthoritativeDuringTheDelay() = runTest {
        val (storage, server) = setUp()
        val challenge = server.lastDeviceRecoveryChallenge(phone)
        server.pending()
        assertEquals(challenge.id, storage.lastDeviceRecovery.challenge(phone)?.challenge?.id, "a request keeps the challenges")
        val k2 = newKey()
        assertEquals(LastDeviceRecoveryOutcome.REPLACED, server.recoverLastDevice(phone, LastDeviceRecovery.authorize(r1, k2, challenge)))
        assertIs<RecoveryKeyResetStatus.Pending>(server.resetStatus())
    }

    @Test
    fun resetsLeaveDevicesPreKeysMailboxAndOtherUsersAlone() = runTest {
        val (storage, server) = setUp()
        val signed = PublicSignedPreKey(SignedPreKeyId(1), ByteArray(64) { 5 }, ByteArray(64) { 6 })
        storage.preKeys.publish(PreKeyPublication(phone, ByteArray(64) { 4 }, signed, listOf(PublicOneTimePreKey(OneTimePreKeyId(1), ByteArray(64) { 1 }))))
        storage.mailboxes.enqueue(EncryptedEnvelope(MessageId("m1"), bob, phone, payload = byteArrayOf(1)))
        val before = listOf(phone, laptop, bob).map { storage.state(it) }

        val cancelled = server.pending()
        server.cancel(cancelled)
        val reset = server.pending()
        clock.now = eligible
        server.complete(reset)

        for ((b, a) in before.zip(listOf(phone, laptop, bob).map { storage.state(it) })) {
            assertContentEquals(b.registration.publicKey, a.registration.publicKey)
            assertEquals(b.authEpoch, a.authEpoch)
            assertEquals(b.authKeyInstalledAt, a.authKeyInstalledAt)
            assertEquals(b.lastDeviceRecoveryId, a.lastDeviceRecoveryId)
        }
        assertEquals(1, storage.preKeys.oneTimePreKeyCount(phone))
        assertEquals(listOf("m1"), storage.mailboxes.drain(phone).map { it.id.value })
        assertContentEquals(bobRecovery.publicKey, storage.lastDeviceRecovery.recoveryKey(bob.userId))
        assertEquals(1, storage.lastDeviceRecovery.recoveryKeyState(bob.userId)?.epoch)
    }

    @Test
    fun concurrentIdenticalRequestsCreateOneReset() = runTest {
        val (_, server) = setUp()
        val devices = List(32) { server.signed(if (it % 2 == 0) phone else laptop, ProtectedEndpoint.REQUEST_LAST_DEVICE_RECOVERY_KEY_RESET) }
        val outcomes = withContext(Dispatchers.Default) { devices.map { async { server.requestLastDeviceRecoveryKeyReset(it) } }.awaitAll() }
        assertEquals(1, outcomes.count { it.created })
        assertEquals(1, outcomes.map { it.reset }.toSet().size)
        assertEquals(outcomes.first().reset, server.resetStatus())
    }

    @Test
    fun completionAndCancellationHaveOneWinnerInBothOrders() = runTest {
        for (byRecoveryKey in listOf(false, true)) {
            for (completionFirst in listOf(true, false)) {
                val gated = GatedStorage(InMemoryServerStorage(), "complete", "cancel")
                val (_, server) = setUp(gated)
                val reset = server.pending()
                clock.now = eligible
                val completer = server.signed(laptop, ProtectedEndpoint.COMPLETE_LAST_DEVICE_RECOVERY_KEY_RESET)
                val canceller = server.signed(phone, ProtectedEndpoint.CANCEL_LAST_DEVICE_RECOVERY_KEY_RESET)
                val (completed, cancelled) = gated.race(
                    completionFirst,
                    { server.completeLastDeviceRecoveryKeyReset(completer, RecoveryKeyReset.complete(r2, reset, laptop)) },
                    {
                        if (byRecoveryKey) server.cancelLastDeviceRecoveryKeyResetByRecoveryKey(RecoveryKeyReset.cancel(r1, reset))
                        else server.cancelLastDeviceRecoveryKeyReset(canceller, reset.resetId)
                    },
                )
                if (completionFirst) {
                    assertEquals(RecoveryKeyResetCompletionOutcome.COMPLETED, completed.getOrThrow())
                    assertIs<RecoveryKeyResetException.NotPending>(cancelled.exceptionOrNull())
                    server.assertActive(r2, epoch = 2)
                } else {
                    cancelled.getOrThrow()
                    assertIs<RecoveryKeyResetException.NotPending>(completed.exceptionOrNull())
                    server.assertActive(r1, epoch = 1)
                }
                assertSame(RecoveryKeyResetStatus.None, server.resetStatus())
                clock.now = t0
            }
        }
    }

    @Test
    fun completionAndRotationOrRevocationHaveOneWinnerInBothOrders() = runTest {
        for (other in listOf("rotate", "revoke")) {
            for (completionFirst in listOf(true, false)) {
                val gated = GatedStorage(InMemoryServerStorage(), "complete", other)
                val (_, server) = setUp(gated)
                val reset = server.pending()
                clock.now = eligible
                val completer = server.signed(laptop, ProtectedEndpoint.COMPLETE_LAST_DEVICE_RECOVERY_KEY_RESET)
                val (completed, transitioned) = gated.race(
                    completionFirst,
                    { server.completeLastDeviceRecoveryKeyReset(completer, RecoveryKeyReset.complete(r2, reset, laptop)) },
                    {
                        if (other == "rotate") {
                            server.rotateLastDeviceRecoveryKey(
                                server.signed(phone, ProtectedEndpoint.ROTATE_LAST_DEVICE_RECOVERY_KEY), RecoveryKeyRotation.authorize(r1, r3, phone, 1, clock.now()),
                            )
                        } else {
                            server.revokeLastDeviceRecoveryKey(
                                server.signed(phone, ProtectedEndpoint.REVOKE_LAST_DEVICE_RECOVERY_KEY), RecoveryKeyRevocation.authorize(r1, phone, 1, clock.now()),
                            )
                        }
                    },
                )
                if (completionFirst) {
                    assertEquals(RecoveryKeyResetCompletionOutcome.COMPLETED, completed.getOrThrow())
                    assertIs<RecoveryKeyLifecycleException.Conflict>(transitioned.exceptionOrNull())
                    server.assertActive(r2, epoch = 2)
                } else {
                    transitioned.getOrThrow()
                    assertIs<RecoveryKeyResetException>(completed.exceptionOrNull())
                    if (other == "rotate") server.assertActive(r3, epoch = 2) else assertIs<LastDeviceRecoveryKeyStatus.Revoked>(server.keyStatus())
                }
                assertSame(RecoveryKeyResetStatus.None, server.resetStatus())
                clock.now = t0
            }
        }
    }

    @Test
    fun completionAndLastDeviceRecoveryInBothOrders() = runTest {
        for (sameDevice in listOf(false, true)) {
            for (completionFirst in listOf(true, false)) {
                val gated = GatedStorage(InMemoryServerStorage(), "complete", "lastDevice")
                val (storage, server) = setUp(gated)
                val reset = server.pending()
                clock.now = eligible
                val target = if (sameDevice) laptop else phone
                val k2 = newKey()
                val recovery = LastDeviceRecovery.authorize(r1, k2, server.lastDeviceRecoveryChallenge(target))
                val completer = server.signed(laptop, ProtectedEndpoint.COMPLETE_LAST_DEVICE_RECOVERY_KEY_RESET)
                val (completed, recovered) = gated.race(
                    completionFirst,
                    { server.completeLastDeviceRecoveryKeyReset(completer, RecoveryKeyReset.complete(r2, reset, laptop)) },
                    { server.recoverLastDevice(target, recovery) },
                )
                if (completionFirst) {
                    assertEquals(RecoveryKeyResetCompletionOutcome.COMPLETED, completed.getOrThrow())
                    assertIs<LastDeviceRecoveryException.NotConfigured>(recovered.exceptionOrNull(), "R1 no longer authorizes")
                    server.assertActive(r2, epoch = 2)
                } else {
                    assertEquals(LastDeviceRecoveryOutcome.REPLACED, recovered.getOrThrow())
                    if (sameDevice) {
                        // The completing device's authentication changed before the completion committed.
                        assertIs<RecoveryKeyResetException.Conflict>(completed.exceptionOrNull())
                        assertIs<RecoveryKeyResetStatus.Pending>(storage.lastDeviceRecovery.pendingRecoveryKeyReset(phone.userId))
                    } else {
                        assertEquals(RecoveryKeyResetCompletionOutcome.COMPLETED, completed.getOrThrow())
                    }
                    assertContentEquals(k2.publicKey, storage.state(target).registration.publicKey)
                }
                clock.now = t0
            }
        }
    }

    @Test
    fun theServerStoresOnlyPublicKeys() = runTest {
        // Structural: no server API takes a recovery key seed; only public keys and signatures reach it.
        val (storage, server) = setUp()
        val reset = server.pending()
        clock.now = eligible
        server.complete(reset)
        val state = assertNotNull(storage.lastDeviceRecovery.recoveryKeyState(phone.userId))
        assertContentEquals(r2.publicKey, state.publicKey)
        assertFalse(state.toString().contains(r2.encode()))
    }

    /**
     * Delegates to [delegate]; while armed (by [race]), holds the first
     * call of each of [first] and [second] until both arrived, then lets
     * them commit in the chosen order.
     */
    private class GatedStorage(private val delegate: ServerStorage, private val first: String, private val second: String) :
        ServerStorage by delegate {
        private var armed = false
        private val arrived = mapOf(first to CompletableDeferred<Unit>(), second to CompletableDeferred<Unit>())
        private val gates = mapOf(first to CompletableDeferred<Unit>(), second to CompletableDeferred<Unit>())

        private suspend fun arrive(kind: String) {
            if (!armed || kind !in gates || arrived.getValue(kind).isCompleted) return
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
                (left.await() to right.await()).also { armed = false }
            }
        }

        override val devices: DeviceRegistrationRepository = object : DeviceRegistrationRepository by delegate.devices {
            override suspend fun replaceForLastDeviceRecovery(replacement: LastDeviceRecoveryReplacement): LastDeviceRecoveryReplacementResult {
                arrive("lastDevice")
                return delegate.devices.replaceForLastDeviceRecovery(replacement)
            }
        }

        override val lastDeviceRecovery: LastDeviceRecoveryRepository = object : LastDeviceRecoveryRepository by delegate.lastDeviceRecovery {
            override suspend fun completeRecoveryKeyReset(transition: RecoveryKeyResetCompletionTransition): RecoveryKeyResetCompletionResult {
                arrive("complete")
                return delegate.lastDeviceRecovery.completeRecoveryKeyReset(transition)
            }

            override suspend fun cancelRecoveryKeyReset(cancellation: RecoveryKeyResetCancellation): RecoveryKeyResetCancellationResult {
                arrive("cancel")
                return delegate.lastDeviceRecovery.cancelRecoveryKeyReset(cancellation)
            }

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
