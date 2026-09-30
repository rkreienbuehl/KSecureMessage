package dev.kreienbuehl.ksecuremessage.server

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
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationRotation
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationRotationAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationRotationStatement
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecovery
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.PreKeyFormat
import dev.kreienbuehl.ksecuremessage.protocol.RequestNonce
import dev.kreienbuehl.ksecuremessage.protocol.ServerApiPaths
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequest
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequestAuthentication
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationRepository
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationState
import dev.kreienbuehl.ksecuremessage.storage.RecoveryReplacement
import dev.kreienbuehl.ksecuremessage.storage.RecoveryReplacementResult
import dev.kreienbuehl.ksecuremessage.storage.RotationReplacement
import dev.kreienbuehl.ksecuremessage.storage.RotationReplacementResult
import dev.kreienbuehl.ksecuremessage.storage.ServerStorage
import dev.kreienbuehl.ksecuremessage.storage.server.inmemory.InMemoryServerStorage
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
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
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Instant

/**
 * Routine device authentication key rotation through
 * [SecureMessageServer.rotateDeviceAuthenticationKey]
 * (docs/device-authentication-rotation.md): both proofs, epoch binding,
 * freshness, replay, exact retry, the check order, what K1 and K2 can do
 * afterwards, and composition with device recovery.
 */
class DeviceAuthenticationRotationServerTest {
    private class ManualClock(var now: Instant) : Clock {
        override fun now(): Instant = now
    }

    private val phone = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val laptop = DeviceAddress(UserId("alice"), DeviceId("laptop"))
    private val bob = DeviceAddress(UserId("bob"), DeviceId("phone"))
    private val clock = ManualClock(Instant.fromEpochMilliseconds(1_767_225_600_000))

    private fun newKey(): DeviceAuthenticationKeyPair = runBlocking { KodiumProtocolEngine().createDeviceAuthenticationKey() }

    private val phoneKey = newKey()
    private val laptopKey = newKey()
    private val bobKey = newKey()

    private suspend fun setUp(storage: ServerStorage = InMemoryServerStorage()): Pair<ServerStorage, SecureMessageServer<TestRegistrationPrincipal>> {
        val server = SecureMessageServer(storage, clock, TestDeviceRegistrationAuthorizer.allowAll())
        for ((address, key) in listOf(phone to phoneKey, laptop to laptopKey, bob to bobKey)) {
            val body = key.publicKey
            val request = ServerRequest(address, "PUT", ServerApiPaths.device(address, ServerApiPaths.REGISTRATION), body)
            server.registerDeviceAsUserOwner(DeviceRegistration(address, key.publicKey), body, ServerRequestAuthentication.sign(key, request, clock.now()))
        }
        return storage to server
    }

    private fun rotation(
        replacement: DeviceAuthenticationKeyPair = newKey(),
        current: DeviceAuthenticationKeyPair = phoneKey,
        epoch: Long = 1,
        address: DeviceAddress = phone,
        offset: Duration = Duration.ZERO,
        nonce: RequestNonce = RequestNonce.random(),
    ): DeviceAuthenticationRotationAuthorization =
        DeviceAuthenticationRotation.create(current, replacement, address, epoch, clock.now + offset, nonce)

    private suspend fun SecureMessageServer<TestRegistrationPrincipal>.signed(
        address: DeviceAddress,
        key: DeviceAuthenticationKeyPair,
        endpoint: ProtectedEndpoint,
        nonce: RequestNonce = RequestNonce.random(),
    ): AuthenticatedDevice {
        val request = ServerRequest(address, endpoint.method, ServerApiPaths.device(address, endpoint.endpoint), ByteArray(0))
        return authenticate(address, endpoint, ByteArray(0), ServerRequestAuthentication.sign(key, request, clock.now(), nonce))
    }

    private suspend fun SecureMessageServer<TestRegistrationPrincipal>.drain(address: DeviceAddress, key: DeviceAuthenticationKeyPair): List<EncryptedEnvelope> =
        receive(signed(address, key, ProtectedEndpoint.DRAIN_MAILBOX))

    private suspend fun SecureMessageServer<TestRegistrationPrincipal>.epoch(address: DeviceAddress, key: DeviceAuthenticationKeyPair): Long =
        registrationStatus(signed(address, key, ProtectedEndpoint.READ_REGISTRATION)).authEpoch

    private suspend fun ServerStorage.state(address: DeviceAddress = phone): DeviceRegistrationState = assertNotNull(devices.registrationState(address))

    private suspend fun ServerStorage.assertUnchanged() {
        assertContentEquals(phoneKey.publicKey, state().registration.publicKey)
        assertEquals(1, state().authEpoch)
        assertNull(state().rotationId)
    }

    private fun preKeyPublication(address: DeviceAddress = phone) = PreKeyPublication(
        address,
        ByteArray(PreKeyFormat.PUBLIC_KEY_SIZE) { 1 },
        PublicSignedPreKey(SignedPreKeyId(0), ByteArray(PreKeyFormat.PUBLIC_KEY_SIZE) { 2 }, ByteArray(PreKeyFormat.SIGNATURE_SIZE) { 3 }),
        (0..2).map { PublicOneTimePreKey(OneTimePreKeyId(it), ByteArray(PreKeyFormat.PUBLIC_KEY_SIZE) { _ -> (10 + it).toByte() }) },
    )

    @Test
    fun rotationReplacesTheKeyAndOnlyTheNewKeyWorks() = runTest {
        val (storage, server) = setUp()
        storage.preKeys.publish(preKeyPublication())
        server.fetchPreKeyBundle(phone)
        storage.mailboxes.enqueue(EncryptedEnvelope(MessageId("m1"), bob, phone, payload = byteArrayOf(1)))
        assertEquals(1, server.epoch(phone, phoneKey))
        val k2 = newKey()

        val authorization = rotation(k2)
        assertEquals(DeviceAuthenticationRotationOutcome.ROTATED, server.rotateDeviceAuthenticationKey(phone, authorization))

        val state = storage.state()
        assertContentEquals(k2.publicKey, state.registration.publicKey)
        assertEquals(2, state.authEpoch)
        assertEquals(DeviceAuthenticationRotation.rotationId(authorization.statement), state.rotationId)
        assertNull(state.recoveryId)
        // K1 is rejected at once on every protected endpoint; K2 works at once.
        assertFailsWith<DeviceAuthenticationException.InvalidAuthentication> { server.drain(phone, phoneKey) }
        assertFailsWith<DeviceAuthenticationException.InvalidAuthentication> { server.signed(phone, phoneKey, ProtectedEndpoint.PUBLISH_PRE_KEYS) }
        assertFailsWith<DeviceAuthenticationException.InvalidAuthentication> { server.epoch(phone, phoneKey) }
        assertEquals(2, server.epoch(phone, k2))
        assertEquals(listOf("m1"), server.drain(phone, k2).map { it.id.value }, "mailbox kept")
        server.publishPreKeys(server.signed(phone, k2, ProtectedEndpoint.PUBLISH_PRE_KEYS), preKeyPublication())
        assertEquals(2, storage.preKeys.oneTimePreKeyCount(phone), "prekeys and tombstone kept")
        // Registration semantics are unchanged: K2 is idempotent, K1 conflicts.
        val k1Body = phoneKey.publicKey
        val k1Request = ServerRequest(phone, "PUT", ServerApiPaths.device(phone, ServerApiPaths.REGISTRATION), k1Body)
        assertFailsWith<dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationException.Conflict> {
            server.registerDeviceAsUserOwner(DeviceRegistration(phone, phoneKey.publicKey), k1Body, ServerRequestAuthentication.sign(phoneKey, k1Request, clock.now()))
        }
        // Other devices are not touched.
        assertEquals(1, storage.state(laptop).authEpoch)
    }

    @Test
    fun exactRetryAfterALostResponseIsIdempotent() = runTest {
        val (storage, server) = setUp()
        val authorization = rotation()
        assertEquals(DeviceAuthenticationRotationOutcome.ROTATED, server.rotateDeviceAuthenticationKey(phone, authorization))
        // K1 is no longer registered, yet the identical retry is recognized.
        repeat(3) {
            assertEquals(DeviceAuthenticationRotationOutcome.ALREADY_APPLIED, server.rotateDeviceAuthenticationKey(phone, authorization))
        }
        assertEquals(2, storage.state().authEpoch, "no second increment")
        // Still within the window only.
        clock.now += DeviceAuthenticationRotation.VALIDITY_WINDOW + 1.milliseconds
        assertFailsWith<DeviceAuthenticationRotationException.Expired> { server.rotateDeviceAuthenticationKey(phone, authorization) }
    }

    @Test
    fun exactRetryStillNeedsBothProofs() = runTest {
        val (storage, server) = setUp()
        val authorization = rotation()
        server.rotateDeviceAuthenticationKey(phone, authorization)
        val forgedAuthorization = DeviceAuthenticationRotationAuthorization(authorization.statement, ByteArray(64) { 1 }, authorization.proofOfPossession)
        val forgedPop = DeviceAuthenticationRotationAuthorization(authorization.statement, authorization.authorizationSignature, ByteArray(64) { 1 })
        assertFailsWith<DeviceAuthenticationRotationException.InvalidProof> { server.rotateDeviceAuthenticationKey(phone, forgedAuthorization) }
        assertFailsWith<DeviceAuthenticationRotationException.InvalidProof> { server.rotateDeviceAuthenticationKey(phone, forgedPop) }
        assertEquals(2, storage.state().authEpoch)
    }

    @Test
    fun staleEpochIsAConflict() = runTest {
        val (storage, server) = setUp()
        assertFailsWith<DeviceAuthenticationRotationException.Conflict> { server.rotateDeviceAuthenticationKey(phone, rotation(epoch = 2)) }
        assertFailsWith<DeviceAuthenticationRotationException.Conflict> { server.rotateDeviceAuthenticationKey(phone, rotation(epoch = 7)) }
        storage.assertUnchanged()
        // After one rotation the epoch-1 statement of a new key is stale.
        val k2 = newKey()
        server.rotateDeviceAuthenticationKey(phone, rotation(k2))
        assertFailsWith<DeviceAuthenticationRotationException.Conflict> { server.rotateDeviceAuthenticationKey(phone, rotation(current = k2, epoch = 1)) }
        assertEquals(DeviceAuthenticationRotationOutcome.ROTATED, server.rotateDeviceAuthenticationKey(phone, rotation(current = k2, epoch = 2)))
        assertEquals(3, storage.state().authEpoch)
    }

    @Test
    fun wrongCurrentKeyIsAConflict() = runTest {
        val (storage, server) = setUp()
        // Signed by K4, naming K4 as current key: not the registered key.
        assertFailsWith<DeviceAuthenticationRotationException.Conflict> { server.rotateDeviceAuthenticationKey(phone, rotation(current = newKey())) }
        // Another device's registered key cannot rotate this device.
        assertFailsWith<DeviceAuthenticationRotationException.Conflict> { server.rotateDeviceAuthenticationKey(phone, rotation(current = laptopKey)) }
        storage.assertUnchanged()
    }

    @Test
    fun badAuthorizationOrProofOfPossessionIsRejected() = runTest {
        val (storage, server) = setUp()
        val valid = rotation()
        val statement = valid.statement
        // Names K1 but is signed by another key.
        val otherSigner = DeviceAuthenticationRotation.create(newKey(), newKey(), phone, 1, clock.now())
        val wrongK1 = DeviceAuthenticationRotationAuthorization(statement, otherSigner.authorizationSignature, valid.proofOfPossession)
        val wrongK2 = DeviceAuthenticationRotationAuthorization(statement, valid.authorizationSignature, otherSigner.proofOfPossession)
        val malformed = DeviceAuthenticationRotationAuthorization(statement, ByteArray(64), ByteArray(64))
        for (authorization in listOf(wrongK1, wrongK2, malformed)) {
            assertFailsWith<DeviceAuthenticationRotationException.InvalidProof> { server.rotateDeviceAuthenticationKey(phone, authorization) }
        }
        storage.assertUnchanged()
        assertEquals(DeviceAuthenticationRotationOutcome.ROTATED, server.rotateDeviceAuthenticationKey(phone, valid), "no nonce was claimed")
    }

    @Test
    fun recoverySignaturesDoNotAuthorizeARotation() = runTest {
        val (storage, server) = setUp()
        val k2 = newKey()
        val nonce = RequestNonce.random()
        val recovery = DeviceRecovery.authorize(laptopKey, DeviceRecovery.prepare(k2, phone, laptop, clock.now(), nonce))
        val statement = DeviceAuthenticationRotationStatement(phone, phoneKey.publicKey, k2.publicKey, 1, clock.now(), nonce)
        val crossed = DeviceAuthenticationRotationAuthorization(statement, recovery.authorizerSignature, recovery.request.proofOfPossession)
        assertFailsWith<DeviceAuthenticationRotationException.InvalidProof> { server.rotateDeviceAuthenticationKey(phone, crossed) }
        storage.assertUnchanged()
    }

    @Test
    fun statementForAnotherDeviceIsInvalid() = runTest {
        val (storage, server) = setUp()
        assertFailsWith<DeviceAuthenticationRotationException.InvalidRotation> {
            server.rotateDeviceAuthenticationKey(laptop, rotation())
        }
        storage.assertUnchanged()
        assertEquals(1, storage.state(laptop).authEpoch)
    }

    @Test
    fun unregisteredDeviceCannotRotate() = runTest {
        val (_, server) = setUp()
        val carol = DeviceAddress(UserId("carol"), DeviceId("tablet"))
        assertFailsWith<DeviceAuthenticationRotationException.NotRegistered> {
            server.rotateDeviceAuthenticationKey(carol, rotation(current = newKey(), address = carol))
        }
    }

    @Test
    fun freshnessWindowIsInclusive() = runTest {
        val window = DeviceAuthenticationRotation.VALIDITY_WINDOW
        for (offset in listOf(-window - 1.milliseconds, window + 1.milliseconds)) {
            val (storage, server) = setUp()
            assertFailsWith<DeviceAuthenticationRotationException.Expired> { server.rotateDeviceAuthenticationKey(phone, rotation(offset = offset)) }
            storage.assertUnchanged()
        }
        for (offset in listOf(-window, window)) {
            val (storage, server) = setUp()
            assertEquals(DeviceAuthenticationRotationOutcome.ROTATED, server.rotateDeviceAuthenticationKey(phone, rotation(offset = offset)))
            assertEquals(2, storage.state().authEpoch)
        }
    }

    @Test
    fun usedNonceIsAReplay() = runTest {
        val (storage, server) = setUp()
        // The nonce was claimed by an ordinary request of the same device: one nonce namespace per device.
        val nonce = RequestNonce.random()
        server.signed(phone, phoneKey, ProtectedEndpoint.DRAIN_MAILBOX, nonce)
        assertFailsWith<DeviceAuthenticationRotationException.Replay> { server.rotateDeviceAuthenticationKey(phone, rotation(nonce = nonce)) }
        storage.assertUnchanged()
    }

    @Test
    fun staleRotationCannotOverwriteALaterKey() = runTest {
        val (storage, server) = setUp()
        val k2 = newKey()
        val k3 = newKey()
        val first = rotation(k2)
        server.rotateDeviceAuthenticationKey(phone, first)
        server.rotateDeviceAuthenticationKey(phone, rotation(k3, current = k2, epoch = 2))
        assertFailsWith<DeviceAuthenticationRotationException.Conflict> { server.rotateDeviceAuthenticationKey(phone, first) }
        val state = storage.state()
        assertContentEquals(k3.publicKey, state.registration.publicKey)
        assertEquals(3, state.authEpoch)
        assertEquals(emptyList(), server.drain(phone, k3), "K3 still works")
    }

    @Test
    fun checkOrderRejectsEarlierFailuresFirst() = runTest {
        val (storage, server) = setUp()
        val expired = -DeviceAuthenticationRotation.VALIDITY_WINDOW - 1.milliseconds
        val carol = DeviceAddress(UserId("carol"), DeviceId("tablet"))
        // Wrong device before anything else.
        assertFailsWith<DeviceAuthenticationRotationException.InvalidRotation> { server.rotateDeviceAuthenticationKey(carol, rotation(offset = expired)) }
        // Not registered before the window.
        assertFailsWith<DeviceAuthenticationRotationException.NotRegistered> {
            server.rotateDeviceAuthenticationKey(carol, rotation(current = newKey(), address = carol, offset = expired))
        }
        // The window before the state and the proofs.
        assertFailsWith<DeviceAuthenticationRotationException.Expired> { server.rotateDeviceAuthenticationKey(phone, rotation(epoch = 9, offset = expired)) }
        // The state before the proofs.
        val bad = rotation(epoch = 9)
        assertFailsWith<DeviceAuthenticationRotationException.Conflict> {
            server.rotateDeviceAuthenticationKey(phone, DeviceAuthenticationRotationAuthorization(bad.statement, ByteArray(64), ByteArray(64)))
        }
        storage.assertUnchanged()
    }

    @Test
    fun rotationThenRecoveryCompose() = runTest {
        val (storage, server) = setUp()
        val k2 = newKey()
        server.rotateDeviceAuthenticationKey(phone, rotation(k2))
        // K2 is lost: the laptop recovers the phone with K3.
        val k3 = newKey()
        val recovery = DeviceRecovery.authorize(laptopKey, DeviceRecovery.prepare(k3, phone, laptop, clock.now()))
        assertEquals(DeviceRecoveryOutcome.REPLACED, server.recoverDevice(recovery))
        val state = storage.state()
        assertContentEquals(k3.publicKey, state.registration.publicKey)
        assertEquals(3, state.authEpoch)
        assertNull(state.rotationId)
        assertEquals(DeviceRecovery.recoveryId(recovery.request), state.recoveryId)
        assertFailsWith<DeviceAuthenticationException.InvalidAuthentication> { server.drain(phone, k2) }
        assertEquals(3, server.epoch(phone, k3))
    }

    @Test
    fun recoveryThenRotationCompose() = runTest {
        val (storage, server) = setUp()
        val k2 = newKey()
        server.recoverDevice(DeviceRecovery.authorize(laptopKey, DeviceRecovery.prepare(k2, phone, laptop, clock.now())))
        val k3 = newKey()
        assertEquals(DeviceAuthenticationRotationOutcome.ROTATED, server.rotateDeviceAuthenticationKey(phone, rotation(k3, current = k2, epoch = 2)))
        val state = storage.state()
        assertContentEquals(k3.publicKey, state.registration.publicKey)
        assertEquals(3, state.authEpoch)
        assertNull(state.recoveryId)
        assertTrue(state.rotationId != null)
        // The rotated device may authorize a recovery of another device in turn.
        val laptopReplacement = newKey()
        assertEquals(
            DeviceRecoveryOutcome.REPLACED,
            server.recoverDevice(DeviceRecovery.authorize(k3, DeviceRecovery.prepare(laptopReplacement, laptop, phone, clock.now()))),
        )
    }

    @Test
    fun rotationAndRecoveryVerifiedAgainstTheSameStateHaveOneWinner() = runTest {
        for (rotationFirst in listOf(true, false)) {
            val gated = GatedStorage(InMemoryServerStorage())
            val (storage, server) = setUp(gated)
            val k2 = newKey()
            val k3 = newKey()
            gated.armed = true
            val results = withContext(Dispatchers.Default) {
                val rotating = async { runCatching { server.rotateDeviceAuthenticationKey(phone, rotation(k2)) } }
                val recovering = async {
                    runCatching { server.recoverDevice(DeviceRecovery.authorize(laptopKey, DeviceRecovery.prepare(k3, phone, laptop, clock.now()))) }
                }
                // Both passed every check against (K1, epoch 1); now let one of them commit first.
                gated.bothArrived.await()
                (if (rotationFirst) gated.rotation else gated.recovery).complete(Unit)
                (if (rotationFirst) rotating else recovering).await()
                (if (rotationFirst) gated.recovery else gated.rotation).complete(Unit)
                rotating.await() to recovering.await()
            }
            val (rotationResult, recoveryResult) = results
            val state = storage.state()
            assertEquals(2, state.authEpoch, "exactly one transition")
            if (rotationFirst) {
                assertEquals(DeviceAuthenticationRotationOutcome.ROTATED, rotationResult.getOrThrow())
                assertIs<DeviceRecoveryException.Conflict>(recoveryResult.exceptionOrNull())
                assertContentEquals(k2.publicKey, state.registration.publicKey)
            } else {
                assertEquals(DeviceRecoveryOutcome.REPLACED, recoveryResult.getOrThrow())
                assertIs<DeviceAuthenticationRotationException.Conflict>(rotationResult.exceptionOrNull())
                assertContentEquals(k3.publicKey, state.registration.publicKey)
            }
        }
    }

    @Test
    fun competingRotationsHaveOneWinner() = runTest {
        repeat(5) {
            val (storage, server) = setUp()
            val keys = List(32) { newKey() }
            val results = withContext(Dispatchers.Default) {
                keys.map { key -> async { runCatching { server.rotateDeviceAuthenticationKey(phone, rotation(key)) } } }.map { it.await() }
            }
            assertEquals(1, results.count { it.isSuccess })
            assertTrue(results.filter { it.isFailure }.all { it.exceptionOrNull() is DeviceAuthenticationRotationException.Conflict })
            assertEquals(2, storage.state().authEpoch)
            val winner = keys[results.indexOfFirst { it.isSuccess }]
            assertContentEquals(winner.publicKey, storage.state().registration.publicKey)
        }
    }

    @Test
    fun identicalConcurrentSubmissionsRotateOnce() = runTest {
        repeat(5) {
            val (storage, server) = setUp()
            val authorization = rotation()
            val results = withContext(Dispatchers.Default) {
                List(32) { async { runCatching { server.rotateDeviceAuthenticationKey(phone, authorization) } } }.map { it.await() }
            }
            val outcomes = results.map { it.getOrThrow() }
            assertEquals(1, outcomes.count { it == DeviceAuthenticationRotationOutcome.ROTATED })
            assertEquals(31, outcomes.count { it == DeviceAuthenticationRotationOutcome.ALREADY_APPLIED })
            assertEquals(2, storage.state().authEpoch)
        }
    }

    /**
     * Delegates to [delegate]; while [armed], holds the first rotation and the
     * first recovery replacement until the test completes [rotation] or
     * [recovery]. [bothArrived] completes once both are waiting, that is,
     * once both passed the service's checks against the same state.
     */
    private class GatedStorage(private val delegate: ServerStorage) : ServerStorage by delegate {
        var armed = false
        val rotation = CompletableDeferred<Unit>()
        val recovery = CompletableDeferred<Unit>()
        val bothArrived = CompletableDeferred<Unit>()
        private val rotationArrived = CompletableDeferred<Unit>()
        private val recoveryArrived = CompletableDeferred<Unit>()

        override val devices: DeviceRegistrationRepository = object : DeviceRegistrationRepository by delegate.devices {
            override suspend fun replaceForRotation(replacement: RotationReplacement): RotationReplacementResult {
                if (armed) {
                    rotationArrived.complete(Unit)
                    if (recoveryArrived.isCompleted) bothArrived.complete(Unit)
                    rotation.await()
                }
                return delegate.devices.replaceForRotation(replacement)
            }

            override suspend fun replaceForRecovery(replacement: RecoveryReplacement): RecoveryReplacementResult {
                if (armed) {
                    recoveryArrived.complete(Unit)
                    if (rotationArrived.isCompleted) bothArrived.complete(Unit)
                    recovery.await()
                }
                return delegate.devices.replaceForRecovery(replacement)
            }
        }
    }
}
