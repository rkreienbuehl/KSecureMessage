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
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecovery
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecoveryAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecoveryRequest
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.PreKeyFormat
import dev.kreienbuehl.ksecuremessage.protocol.RequestNonce
import dev.kreienbuehl.ksecuremessage.protocol.ServerApiPaths
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequest
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequestAuthentication
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationRepository
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationState
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
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/**
 * Device recovery through [SecureMessageServer.recoverDevice]
 * (docs/device-recovery.md): who may recover whom, both proofs, freshness,
 * replay, atomic replacement, and what the old and new keys can do
 * afterwards.
 */
class DeviceRecoveryServerTest {
    private class ManualClock(var now: Instant) : Clock {
        override fun now(): Instant = now
    }

    private val laptop = DeviceAddress(UserId("alice"), DeviceId("laptop"))
    private val phone = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val tablet = DeviceAddress(UserId("alice"), DeviceId("tablet"))
    private val bob = DeviceAddress(UserId("bob"), DeviceId("phone"))
    private val clock = ManualClock(Instant.fromEpochMilliseconds(1_767_225_600_000))

    private fun newKey(): DeviceAuthenticationKeyPair = runBlocking { KodiumProtocolEngine().createDeviceAuthenticationKey() }

    private val laptopKey = newKey()
    private val phoneKey = newKey()
    private val tabletKey = newKey()
    private val bobKey = newKey()

    private suspend fun setUp(storage: ServerStorage = InMemoryServerStorage()): Pair<ServerStorage, SecureMessageServer> {
        val server = SecureMessageServer(storage, clock, TestDeviceRegistrationAuthorizer.allowAll())
        for ((address, key) in listOf(laptop to laptopKey, phone to phoneKey, tablet to tabletKey, bob to bobKey)) {
            val body = key.publicKey
            val request = ServerRequest(address, "PUT", ServerApiPaths.device(address, ServerApiPaths.REGISTRATION), body)
            server.registerDevice(DeviceRegistration(address, key.publicKey), body, ServerRequestAuthentication.sign(key, request, clock.now()))
        }
        return storage to server
    }

    private fun authorization(
        replacement: DeviceAuthenticationKeyPair = newKey(),
        target: DeviceAddress = laptop,
        authorizer: DeviceAddress = phone,
        authorizerKey: DeviceAuthenticationKeyPair = phoneKey,
        offset: Duration = Duration.ZERO,
        nonce: RequestNonce = RequestNonce.random(),
    ): DeviceRecoveryAuthorization =
        DeviceRecovery.authorize(authorizerKey, DeviceRecovery.prepare(replacement, target, authorizer, clock.now + offset, nonce))

    private suspend fun SecureMessageServer.drain(address: DeviceAddress, key: DeviceAuthenticationKeyPair): List<EncryptedEnvelope> {
        val request = ServerRequest(address, "GET", ServerApiPaths.device(address, ServerApiPaths.MESSAGES), ByteArray(0))
        return receive(authenticate(address, ProtectedEndpoint.DRAIN_MAILBOX, ByteArray(0), ServerRequestAuthentication.sign(key, request, clock.now())))
    }

    private suspend fun ServerStorage.state(address: DeviceAddress): DeviceRegistrationState = assertNotNull(devices.registrationState(address))

    private suspend fun ServerStorage.assertUnchanged() {
        assertContentEquals(laptopKey.publicKey, state(laptop).registration.publicKey)
        assertEquals(1, state(laptop).authEpoch)
    }

    private fun preKeyPublication() = PreKeyPublication(
        laptop,
        ByteArray(PreKeyFormat.PUBLIC_KEY_SIZE) { 1 },
        PublicSignedPreKey(SignedPreKeyId(0), ByteArray(PreKeyFormat.PUBLIC_KEY_SIZE) { 2 }, ByteArray(PreKeyFormat.SIGNATURE_SIZE) { 3 }),
        (0..2).map { PublicOneTimePreKey(OneTimePreKeyId(it), ByteArray(PreKeyFormat.PUBLIC_KEY_SIZE) { _ -> (10 + it).toByte() }) },
    )

    @Test
    fun sameUserDeviceRecoversTheKeyAndTheOldKeyStopsWorking() = runTest {
        val (storage, server) = setUp()
        val replacement = newKey()
        // State that recovery must keep: prekeys, a consumed one-time prekey and queued envelopes.
        storage.preKeys.publish(preKeyPublication())
        server.fetchPreKeyBundle(laptop)
        storage.mailboxes.enqueue(EncryptedEnvelope(MessageId("m1"), bob, laptop, payload = byteArrayOf(1)))

        assertEquals(DeviceRecoveryOutcome.REPLACED, server.recoverDevice(authorization(replacement)))

        assertContentEquals(replacement.publicKey, storage.state(laptop).registration.publicKey)
        assertEquals(2, storage.state(laptop).authEpoch)
        assertFailsWith<DeviceAuthenticationException.InvalidAuthentication> { server.drain(laptop, laptopKey) }
        assertEquals(listOf("m1"), server.drain(laptop, replacement).map { it.id.value }, "mailbox kept, new key works at once")
        assertEquals(2, storage.preKeys.oneTimePreKeyCount(laptop), "prekeys and tombstone kept")
        assertContentEquals(preKeyPublication().identityKey, server.fetchPreKeyBundle(laptop)?.identityKey)
        // The authorizer is unchanged, and the recovered device may authorize in turn.
        assertEquals(1, storage.state(phone).authEpoch)
        assertEquals(
            DeviceRecoveryOutcome.REPLACED,
            server.recoverDevice(authorization(target = tablet, authorizer = laptop, authorizerKey = replacement)),
        )
    }

    @Test
    fun anyOtherRegisteredDeviceOfTheUserMayAuthorize() = runTest {
        val (storage, server) = setUp()
        assertEquals(DeviceRecoveryOutcome.REPLACED, server.recoverDevice(authorization(authorizer = tablet, authorizerKey = tabletKey)))
        assertEquals(2, storage.state(laptop).authEpoch)
    }

    @Test
    fun anotherUsersDeviceCannotAuthorize() = runTest {
        val (storage, server) = setUp()
        assertFailsWith<DeviceRecoveryException.CrossUser> { server.recoverDevice(authorization(authorizer = bob, authorizerKey = bobKey)) }
        // Also not for its own user ID spelled differently: user IDs compare exactly.
        val lookalike = DeviceAddress(UserId("Alice"), DeviceId("phone"))
        assertFailsWith<DeviceRecoveryException.CrossUser> { server.recoverDevice(authorization(authorizer = lookalike)) }
        storage.assertUnchanged()
    }

    @Test
    fun aDeviceCannotAuthorizeItself() = runTest {
        val (storage, server) = setUp()
        assertFailsWith<DeviceRecoveryException.SelfAuthorization> {
            server.recoverDevice(authorization(authorizer = laptop, authorizerKey = laptopKey))
        }
        storage.assertUnchanged()
    }

    @Test
    fun authorizerAndTargetMustBeRegistered() = runTest {
        val (storage, server) = setUp()
        val desktop = DeviceAddress(UserId("alice"), DeviceId("desktop"))
        assertFailsWith<DeviceRecoveryException.AuthorizerNotRegistered> {
            server.recoverDevice(authorization(authorizer = desktop, authorizerKey = newKey()))
        }
        assertFailsWith<DeviceRecoveryException.TargetNotRegistered> { server.recoverDevice(authorization(target = desktop)) }
        assertNull(storage.devices.registration(desktop), "recovery is no registration bootstrap")
        storage.assertUnchanged()
    }

    @Test
    fun bothProofsAreRequired() = runTest {
        val (storage, server) = setUp()
        // Authorizer signature by another key than the authorizer's registered one (here: the target's old key).
        assertFailsWith<DeviceRecoveryException.InvalidProof> { server.recoverDevice(authorization(authorizerKey = laptopKey)) }
        assertFailsWith<DeviceRecoveryException.InvalidProof> { server.recoverDevice(authorization(authorizerKey = tabletKey)) }
        // Proof of possession by another key than the replacement key.
        val replacement = newKey()
        val forged = DeviceRecovery.prepare(newKey(), laptop, phone, clock.now())
        val request = DeviceRecoveryRequest(laptop, phone, replacement.publicKey, forged.timestamp, forged.nonce, forged.proofOfPossession)
        assertFailsWith<DeviceRecoveryException.InvalidProof> { server.recoverDevice(DeviceRecovery.authorize(phoneKey, request)) }
        // The authorizer's signature does not stand in for the proof of possession.
        val valid = authorization(replacement)
        val swapped = DeviceRecoveryRequest(laptop, phone, replacement.publicKey, valid.request.timestamp, valid.request.nonce, valid.authorizerSignature)
        assertFailsWith<DeviceRecoveryException.InvalidProof> { server.recoverDevice(DeviceRecoveryAuthorization(swapped, valid.authorizerSignature)) }
        // A signed field changed after authorization.
        val tampered = DeviceRecoveryRequest(tablet, phone, replacement.publicKey, valid.request.timestamp, valid.request.nonce, valid.request.proofOfPossession)
        assertFailsWith<DeviceRecoveryException.InvalidProof> { server.recoverDevice(DeviceRecoveryAuthorization(tampered, valid.authorizerSignature)) }
        storage.assertUnchanged()
        assertEquals(1, storage.state(tablet).authEpoch)
        // Failed proofs claim no nonce: the valid one still works.
        assertEquals(DeviceRecoveryOutcome.REPLACED, server.recoverDevice(valid))
    }

    @Test
    fun timestampWindowIsInclusive() = runTest {
        val (storage, server) = setUp()
        for (offset in listOf(-5.minutes - 1.milliseconds, 5.minutes + 1.milliseconds, -1_000.minutes)) {
            assertFailsWith<DeviceRecoveryException.Expired>("$offset") { server.recoverDevice(authorization(offset = offset)) }
        }
        storage.assertUnchanged()
        assertEquals(DeviceRecoveryOutcome.REPLACED, server.recoverDevice(authorization(offset = 5.minutes)))
        assertEquals(
            DeviceRecoveryOutcome.REPLACED,
            server.recoverDevice(authorization(offset = -5.minutes, authorizer = tablet, authorizerKey = tabletKey)),
        )
    }

    @Test
    fun retryOfAnAppliedRecoveryIsIdempotent() = runTest {
        val (storage, server) = setUp()
        val authorization = authorization()
        assertEquals(DeviceRecoveryOutcome.REPLACED, server.recoverDevice(authorization))
        assertEquals(DeviceRecoveryOutcome.ALREADY_APPLIED, server.recoverDevice(authorization))
        assertEquals(2, storage.state(laptop).authEpoch)
        // Only inside the validity window, like every request.
        clock.now += 6.minutes
        assertFailsWith<DeviceRecoveryException.Expired> { server.recoverDevice(authorization) }
    }

    @Test
    fun staleRecoveryCannotRestoreAnOlderKey() = runTest {
        val (storage, server) = setUp()
        val k2 = newKey()
        val k3 = newKey()
        val first = authorization(k2)
        server.recoverDevice(first)
        server.recoverDevice(authorization(k3, authorizer = tablet, authorizerKey = tabletKey))
        assertFailsWith<DeviceRecoveryException.Replay> { server.recoverDevice(first) }
        assertContentEquals(k3.publicKey, storage.state(laptop).registration.publicKey)
        assertEquals(3, storage.state(laptop).authEpoch)
    }

    @Test
    fun usedNonceIsAReplay() = runTest {
        val (storage, server) = setUp()
        val nonce = RequestNonce.random()
        // A normal request of the target (with its old key) used the nonce first.
        val request = ServerRequest(laptop, "GET", ServerApiPaths.device(laptop, ServerApiPaths.MESSAGES), ByteArray(0))
        server.authenticate(laptop, ProtectedEndpoint.DRAIN_MAILBOX, ByteArray(0), ServerRequestAuthentication.sign(laptopKey, request, clock.now(), nonce))
        assertFailsWith<DeviceRecoveryException.Replay> { server.recoverDevice(authorization(nonce = nonce)) }
        storage.assertUnchanged()
    }

    @Test
    fun concurrentRecoveriesVerifiedAgainstTheSameStateHaveOneWinner() = runTest {
        val gated = GatedStorage(InMemoryServerStorage(), laptop, parties = 2)
        val (storage, server) = setUp(gated)
        gated.armed = true
        val k2 = newKey()
        val k3 = newKey()
        // Both requests load the target's state (K1, epoch 1) before either replaces it.
        val results = listOf(
            async { runCatching { server.recoverDevice(authorization(k2)) } },
            async { runCatching { server.recoverDevice(authorization(k3, authorizer = tablet, authorizerKey = tabletKey)) } },
        ).awaitAll()
        assertEquals(1, results.count { it.getOrNull() == DeviceRecoveryOutcome.REPLACED })
        assertIs<DeviceRecoveryException.Conflict>(results.single { it.isFailure }.exceptionOrNull())
        val winner = if (results[0].isSuccess) k2 else k3
        assertContentEquals(winner.publicKey, storage.state(laptop).registration.publicKey)
        assertEquals(2, storage.state(laptop).authEpoch)
    }

    @Test
    fun concurrentIdenticalSubmissionsReplaceOnce() = runTest {
        repeat(10) {
            val (storage, server) = setUp()
            val authorization = authorization()
            val outcomes = withContext(Dispatchers.Default) {
                List(32) { async { server.recoverDevice(authorization) } }.awaitAll()
            }
            assertEquals(1, outcomes.count { it == DeviceRecoveryOutcome.REPLACED })
            assertEquals(31, outcomes.count { it == DeviceRecoveryOutcome.ALREADY_APPLIED })
            assertEquals(2, storage.state(laptop).authEpoch)
        }
    }

    @Test
    fun authorizerRecoveredMeanwhileIsAConflict() = runTest {
        val gated = GatedStorage(InMemoryServerStorage(), laptop, parties = 1)
        val (storage, server) = setUp(gated)
        gated.armed = true
        val pending = async { runCatching { server.recoverDevice(authorization()) } }
        gated.reached.await()
        // While the laptop's recovery waits, the phone's own key is recovered by the tablet.
        gated.armed = false
        server.recoverDevice(authorization(target = phone, authorizer = tablet, authorizerKey = tabletKey))
        gated.release.complete(Unit)
        assertIs<DeviceRecoveryException.Conflict>(pending.await().exceptionOrNull(), "verified with a key that is no longer registered")
        storage.assertUnchanged()
    }

    /**
     * Delegates to [delegate]; while [armed], suspends every lookup of
     * [target]'s registration until [parties] lookups arrived (or [release]
     * is completed by the test when [parties] is 1).
     */
    private class GatedStorage(private val delegate: ServerStorage, private val target: DeviceAddress, private val parties: Int) :
        ServerStorage by delegate {
        var armed = false
        val reached = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        private var arrivals = 0

        override val devices: DeviceRegistrationRepository = object : DeviceRegistrationRepository by delegate.devices {
            override suspend fun registrationState(address: DeviceAddress): DeviceRegistrationState? {
                val state = delegate.devices.registrationState(address)
                if (armed && address == target) {
                    arrivals++
                    reached.complete(Unit)
                    if (arrivals == parties && parties > 1) release.complete(Unit)
                    release.await()
                }
                return state
            }
        }
    }
}
