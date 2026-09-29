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
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecovery
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecovery
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryChallenge
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryChallengeId
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryKey
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryKeyRegistration
import dev.kreienbuehl.ksecuremessage.protocol.PreKeyFormat
import dev.kreienbuehl.ksecuremessage.protocol.RequestNonce
import dev.kreienbuehl.ksecuremessage.protocol.ServerApiPaths
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequest
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequestAuthentication
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationException
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationRepository
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationState
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryKeyException
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryRepository
import dev.kreienbuehl.ksecuremessage.storage.StoredLastDeviceRecoveryChallenge
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryReplacement
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryReplacementResult
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
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/**
 * Last-device recovery through [SecureMessageServer]
 * (docs/last-device-recovery.md): recovery key registration by an
 * authenticated device, challenges, both proofs, the check order, exact
 * retry, stale recoveries, what the old and the new key can do afterwards,
 * and races with device recovery and routine rotation.
 */
class LastDeviceRecoveryServerTest {
    private class ManualClock(var now: Instant) : Clock {
        override fun now(): Instant = now
    }

    private val phone = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val laptop = DeviceAddress(UserId("alice"), DeviceId("laptop"))
    private val bob = DeviceAddress(UserId("bob"), DeviceId("phone"))
    private val clock = ManualClock(Instant.fromEpochMilliseconds(1_767_225_600_000))
    private val engine = KodiumProtocolEngine()

    private fun newKey(): DeviceAuthenticationKeyPair = runBlocking { engine.createDeviceAuthenticationKey() }
    private fun newRecoveryKey(): LastDeviceRecoveryKey = runBlocking { engine.createLastDeviceRecoveryKey() }

    private val phoneKey = newKey()
    private val laptopKey = newKey()
    private val bobKey = newKey()
    private val recoveryKey = newRecoveryKey()

    private suspend fun setUp(
        storage: ServerStorage = InMemoryServerStorage(),
        withRecoveryKey: Boolean = true,
    ): Pair<ServerStorage, SecureMessageServer> {
        val server = SecureMessageServer(storage, clock, TestDeviceRegistrationAuthorizer.allowAll())
        for ((address, key) in listOf(phone to phoneKey, laptop to laptopKey, bob to bobKey)) {
            val body = key.publicKey
            val request = ServerRequest(address, "PUT", ServerApiPaths.device(address, ServerApiPaths.REGISTRATION), body)
            server.registerDevice(DeviceRegistration(address, key.publicKey), body, ServerRequestAuthentication.sign(key, request, clock.now()))
        }
        if (withRecoveryKey) {
            assertTrue(server.registerLastDeviceRecoveryKey(server.signed(laptop, laptopKey, ProtectedEndpoint.REGISTER_LAST_DEVICE_RECOVERY_KEY), LastDeviceRecovery.registerKey(recoveryKey, phone.userId)))
        }
        return storage to server
    }

    private suspend fun SecureMessageServer.signed(
        address: DeviceAddress,
        key: DeviceAuthenticationKeyPair,
        endpoint: ProtectedEndpoint,
    ): AuthenticatedDevice {
        val request = ServerRequest(address, endpoint.method, ServerApiPaths.device(address, endpoint.endpoint), ByteArray(0))
        return authenticate(address, endpoint, ByteArray(0), ServerRequestAuthentication.sign(key, request, clock.now()))
    }

    private suspend fun SecureMessageServer.drain(address: DeviceAddress, key: DeviceAuthenticationKeyPair): List<EncryptedEnvelope> =
        receive(signed(address, key, ProtectedEndpoint.DRAIN_MAILBOX))

    private suspend fun SecureMessageServer.recovery(
        replacement: DeviceAuthenticationKeyPair = newKey(),
        key: LastDeviceRecoveryKey = recoveryKey,
        target: DeviceAddress = phone,
    ): LastDeviceRecoveryAuthorization = LastDeviceRecovery.authorize(key, replacement, lastDeviceRecoveryChallenge(target))

    private suspend fun ServerStorage.state(address: DeviceAddress = phone): DeviceRegistrationState = assertNotNull(devices.registrationState(address))

    private suspend fun ServerStorage.assertUnchanged() {
        assertContentEquals(phoneKey.publicKey, state().registration.publicKey)
        assertEquals(1, state().authEpoch)
        assertNull(state().lastDeviceRecoveryId)
    }

    private fun preKeyPublication(address: DeviceAddress = phone) = PreKeyPublication(
        address,
        ByteArray(PreKeyFormat.PUBLIC_KEY_SIZE) { 1 },
        PublicSignedPreKey(SignedPreKeyId(0), ByteArray(PreKeyFormat.PUBLIC_KEY_SIZE) { 2 }, ByteArray(PreKeyFormat.SIGNATURE_SIZE) { 3 }),
        (0..2).map { PublicOneTimePreKey(OneTimePreKeyId(it), ByteArray(PreKeyFormat.PUBLIC_KEY_SIZE) { _ -> (10 + it).toByte() }) },
    )

    /** [authorization] with its statement's challenge fields replaced, signatures unchanged. */
    private fun LastDeviceRecoveryAuthorization.withChallenge(challenge: LastDeviceRecoveryChallenge) = LastDeviceRecoveryAuthorization(
        dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryStatement(challenge, statement.recoveryPublicKey, statement.replacementPublicKey),
        recoverySignature,
        proofOfPossession,
    )

    @Test
    fun recoveryKeyIsRegisteredOnlyByAnAuthenticatedDeviceOfTheUser() = runTest {
        val (storage, server) = setUp(withRecoveryKey = false)
        val registration = LastDeviceRecovery.registerKey(recoveryKey, phone.userId)
        // Only an AuthenticatedDevice for this endpoint may register; another endpoint's proof does not count.
        assertFailsWith<IllegalArgumentException> {
            server.registerLastDeviceRecoveryKey(server.signed(phone, phoneKey, ProtectedEndpoint.DRAIN_MAILBOX), registration)
        }
        assertFailsWith<DeviceAuthenticationException.InvalidAuthentication> {
            server.signed(phone, laptopKey, ProtectedEndpoint.REGISTER_LAST_DEVICE_RECOVERY_KEY)
        }
        // Bob's device cannot register a key for alice.
        assertFailsWith<LastDeviceRecoveryException.InvalidKeyRegistration> {
            server.registerLastDeviceRecoveryKey(server.signed(bob, bobKey, ProtectedEndpoint.REGISTER_LAST_DEVICE_RECOVERY_KEY), registration)
        }
        // A key nobody holds (no valid proof of possession) is refused.
        val other = newRecoveryKey()
        val forged = LastDeviceRecoveryKeyRegistration(phone.userId, other.publicKey, registration.proofOfPossession)
        assertFailsWith<LastDeviceRecoveryException.InvalidKeyRegistration> {
            server.registerLastDeviceRecoveryKey(server.signed(phone, phoneKey, ProtectedEndpoint.REGISTER_LAST_DEVICE_RECOVERY_KEY), forged)
        }
        assertNull(storage.lastDeviceRecovery.recoveryKey(phone.userId))

        assertTrue(server.registerLastDeviceRecoveryKey(server.signed(phone, phoneKey, ProtectedEndpoint.REGISTER_LAST_DEVICE_RECOVERY_KEY), registration))
        assertContentEquals(recoveryKey.publicKey, storage.lastDeviceRecovery.recoveryKey(phone.userId))
        // Idempotent from any device of the user; a different key conflicts and never replaces it.
        assertFalse(server.registerLastDeviceRecoveryKey(server.signed(laptop, laptopKey, ProtectedEndpoint.REGISTER_LAST_DEVICE_RECOVERY_KEY), registration))
        assertFailsWith<LastDeviceRecoveryKeyException.Conflict> {
            server.registerLastDeviceRecoveryKey(
                server.signed(phone, phoneKey, ProtectedEndpoint.REGISTER_LAST_DEVICE_RECOVERY_KEY),
                LastDeviceRecovery.registerKey(other, phone.userId),
            )
        }
        assertContentEquals(recoveryKey.publicKey, storage.lastDeviceRecovery.recoveryKey(phone.userId))
        assertNull(storage.lastDeviceRecovery.recoveryKey(bob.userId))
    }

    @Test
    fun challengeNeedsARegisteredDeviceAndARecoveryKey() = runTest {
        val (_, server) = setUp(withRecoveryKey = false)
        assertFailsWith<LastDeviceRecoveryException.NotConfigured> { server.lastDeviceRecoveryChallenge(phone) }
        assertFailsWith<LastDeviceRecoveryException.TargetNotRegistered> {
            server.lastDeviceRecoveryChallenge(DeviceAddress(UserId("alice"), DeviceId("watch")))
        }
        server.registerLastDeviceRecoveryKey(
            server.signed(phone, phoneKey, ProtectedEndpoint.REGISTER_LAST_DEVICE_RECOVERY_KEY),
            LastDeviceRecovery.registerKey(recoveryKey, phone.userId),
        )
        val challenge = server.lastDeviceRecoveryChallenge(phone)
        assertEquals(phone, challenge.target)
        assertEquals(1, challenge.authEpoch)
        assertEquals(clock.now + LastDeviceRecovery.CHALLENGE_LIFETIME, challenge.expiresAt)
        // While valid, the same challenge is returned; so nobody can invalidate another's challenge.
        clock.now += 1.minutes
        val again = server.lastDeviceRecoveryChallenge(phone)
        assertEquals(challenge.id, again.id)
        assertContentEquals(challenge.nonce, again.nonce)
        assertNotEquals(challenge.id, server.lastDeviceRecoveryChallenge(laptop).id, "per device")
        assertFailsWith<LastDeviceRecoveryException.NotConfigured> { server.lastDeviceRecoveryChallenge(bob) }
        clock.now += LastDeviceRecovery.CHALLENGE_LIFETIME
        assertNotEquals(challenge.id, server.lastDeviceRecoveryChallenge(phone).id, "a new one after expiry")
    }

    @Test
    fun recoveryReplacesTheKeyAndOnlyTheNewKeyWorks() = runTest {
        val (storage, server) = setUp()
        storage.preKeys.publish(preKeyPublication())
        server.fetchPreKeyBundle(phone)
        storage.mailboxes.enqueue(EncryptedEnvelope(MessageId("m1"), bob, phone, payload = byteArrayOf(1)))
        val k2 = newKey()
        val authorization = server.recovery(k2)
        clock.now += 1.minutes

        assertEquals(LastDeviceRecoveryOutcome.REPLACED, server.recoverLastDevice(phone, authorization))

        val state = storage.state()
        assertContentEquals(k2.publicKey, state.registration.publicKey)
        assertEquals(2, state.authEpoch)
        assertEquals(clock.now, state.authKeyInstalledAt, "installed at the server's time")
        assertEquals(LastDeviceRecovery.recoveryId(authorization.statement), state.lastDeviceRecoveryId)
        assertNull(state.recoveryId)
        assertNull(state.rotationId)
        assertNull(storage.lastDeviceRecovery.challenge(phone), "challenge consumed")
        // K1 is rejected at once on every protected endpoint; K2 works at once.
        assertFailsWith<DeviceAuthenticationException.InvalidAuthentication> { server.drain(phone, phoneKey) }
        assertFailsWith<DeviceAuthenticationException.InvalidAuthentication> { server.signed(phone, phoneKey, ProtectedEndpoint.READ_REGISTRATION) }
        assertEquals(2, server.registrationStatus(server.signed(phone, k2, ProtectedEndpoint.READ_REGISTRATION)).authEpoch)
        assertEquals(listOf("m1"), server.drain(phone, k2).map { it.id.value }, "mailbox kept")
        server.publishPreKeys(server.signed(phone, k2, ProtectedEndpoint.PUBLISH_PRE_KEYS), preKeyPublication())
        assertEquals(2, storage.preKeys.oneTimePreKeyCount(phone), "prekeys and tombstone kept")
        // Registration semantics are unchanged: K2 is idempotent, K1 conflicts.
        val k1Body = phoneKey.publicKey
        val k1Request = ServerRequest(phone, "PUT", ServerApiPaths.device(phone, ServerApiPaths.REGISTRATION), k1Body)
        assertFailsWith<DeviceRegistrationException.Conflict> {
            server.registerDevice(DeviceRegistration(phone, phoneKey.publicKey), k1Body, ServerRequestAuthentication.sign(phoneKey, k1Request, clock.now()))
        }
        // Other devices and the recovery key are not touched; the recovered device can rotate normally.
        assertEquals(1, storage.state(laptop).authEpoch)
        assertContentEquals(recoveryKey.publicKey, storage.lastDeviceRecovery.recoveryKey(phone.userId))
        val status = server.registrationStatus(server.signed(phone, k2, ProtectedEndpoint.READ_REGISTRATION))
        assertEquals(
            DeviceAuthenticationRotationOutcome.ROTATED,
            server.rotateDeviceAuthenticationKey(phone, DeviceAuthenticationRotation.create(k2, newKey(), phone, status.authEpoch, clock.now())),
        )
    }

    @Test
    fun lastRemainingDeviceOfAUserIsRecovered() = runTest {
        val storage = InMemoryServerStorage()
        val server = SecureMessageServer(storage, clock, TestDeviceRegistrationAuthorizer.allowAll())
        val body = phoneKey.publicKey
        val request = ServerRequest(phone, "PUT", ServerApiPaths.device(phone, ServerApiPaths.REGISTRATION), body)
        server.registerDevice(DeviceRegistration(phone, phoneKey.publicKey), body, ServerRequestAuthentication.sign(phoneKey, request, clock.now()))
        server.registerLastDeviceRecoveryKey(
            server.signed(phone, phoneKey, ProtectedEndpoint.REGISTER_LAST_DEVICE_RECOVERY_KEY),
            LastDeviceRecovery.registerKey(recoveryKey, phone.userId),
        )
        // The phone's key is lost; no other device exists. Only the recovery key helps.
        val k2 = newKey()
        assertEquals(LastDeviceRecoveryOutcome.REPLACED, server.recoverLastDevice(phone, server.recovery(k2)))
        assertEquals(emptyList(), server.drain(phone, k2))
    }

    @Test
    fun exactRetryAfterALostResponseIsIdempotent() = runTest {
        val (storage, server) = setUp()
        val authorization = server.recovery()
        assertEquals(LastDeviceRecoveryOutcome.REPLACED, server.recoverLastDevice(phone, authorization))
        // The challenge is consumed, yet the identical retry is recognized, also after the challenge expired.
        repeat(3) { assertEquals(LastDeviceRecoveryOutcome.ALREADY_APPLIED, server.recoverLastDevice(phone, authorization)) }
        clock.now += LastDeviceRecovery.CHALLENGE_LIFETIME + 1.minutes
        assertEquals(LastDeviceRecoveryOutcome.ALREADY_APPLIED, server.recoverLastDevice(phone, authorization))
        assertEquals(2, storage.state().authEpoch, "no second increment")
        // The retry still needs both proofs.
        val broken = LastDeviceRecoveryAuthorization(authorization.statement, authorization.recoverySignature, authorization.recoverySignature)
        assertFailsWith<LastDeviceRecoveryException.InvalidProof> { server.recoverLastDevice(phone, broken) }
    }

    @Test
    fun consumedChallengeCannotBeReused() = runTest {
        val (storage, server) = setUp()
        val challenge = server.lastDeviceRecoveryChallenge(phone)
        val k2 = newKey()
        assertEquals(LastDeviceRecoveryOutcome.REPLACED, server.recoverLastDevice(phone, LastDeviceRecovery.authorize(recoveryKey, k2, challenge)))
        // The same challenge, validly signed for another replacement key: rejected.
        assertFailsWith<LastDeviceRecoveryException.ChallengeInvalid> {
            server.recoverLastDevice(phone, LastDeviceRecovery.authorize(recoveryKey, newKey(), challenge))
        }
        assertContentEquals(k2.publicKey, storage.state().registration.publicKey)
        assertEquals(2, storage.state().authEpoch)
    }

    @Test
    fun expiredChallengeIsRejectedWithInclusiveBound() = runTest {
        val (storage, server) = setUp()
        val authorization = server.recovery()
        clock.now += LastDeviceRecovery.CHALLENGE_LIFETIME + 1.milliseconds
        assertFailsWith<LastDeviceRecoveryException.Expired> { server.recoverLastDevice(phone, authorization) }
        storage.assertUnchanged()

        val fresh = server.recovery()
        clock.now += LastDeviceRecovery.CHALLENGE_LIFETIME
        assertEquals(LastDeviceRecoveryOutcome.REPLACED, server.recoverLastDevice(phone, fresh))
    }

    @Test
    fun badSignaturesAreRejected() = runTest {
        val (storage, server) = setUp()
        val authorization = server.recovery()
        // Signed by another recovery key (not the registered one): rejected, even with a valid PoP.
        val otherKey = newRecoveryKey()
        val foreign = LastDeviceRecovery.authorize(otherKey, newKey(), server.lastDeviceRecoveryChallenge(phone))
        assertFailsWith<LastDeviceRecoveryException.InvalidProof> { server.recoverLastDevice(phone, foreign) }
        // The statement names the registered recovery key but the signature is not by it.
        val replaced = LastDeviceRecoveryAuthorization(authorization.statement, foreign.recoverySignature, authorization.proofOfPossession)
        assertFailsWith<LastDeviceRecoveryException.InvalidProof> { server.recoverLastDevice(phone, replaced) }
        // Missing proof of possession.
        val noPop = LastDeviceRecoveryAuthorization(authorization.statement, authorization.recoverySignature, authorization.recoverySignature)
        assertFailsWith<LastDeviceRecoveryException.InvalidProof> { server.recoverLastDevice(phone, noPop) }
        // Device authentication keys and other protocols' signatures do not authorize a recovery.
        val deviceRecovery = DeviceRecovery.authorize(laptopKey, DeviceRecovery.prepare(newKey(), phone, laptop, clock.now()))
        val crossProtocol = LastDeviceRecoveryAuthorization(authorization.statement, deviceRecovery.authorizerSignature, deviceRecovery.request.proofOfPossession)
        assertFailsWith<LastDeviceRecoveryException.InvalidProof> { server.recoverLastDevice(phone, crossProtocol) }
        storage.assertUnchanged()
        assertEquals(LastDeviceRecoveryOutcome.REPLACED, server.recoverLastDevice(phone, authorization), "the challenge survived the failures")
    }

    @Test
    fun alteredChallengeFieldsAreRejected() = runTest {
        val (storage, server) = setUp()
        val authorization = server.recovery()
        val challenge = authorization.statement.challenge
        val altered = listOf(
            LastDeviceRecoveryChallenge(phone, LastDeviceRecoveryChallengeId(ByteArray(16)), challenge.nonce, challenge.authEpoch, challenge.expiresAt),
            LastDeviceRecoveryChallenge(phone, challenge.id, ByteArray(32), challenge.authEpoch, challenge.expiresAt),
            LastDeviceRecoveryChallenge(phone, challenge.id, challenge.nonce, challenge.authEpoch + 1, challenge.expiresAt),
            LastDeviceRecoveryChallenge(phone, challenge.id, challenge.nonce, challenge.authEpoch, challenge.expiresAt + 1.minutes),
        )
        for (value in altered) {
            assertFailsWith<LastDeviceRecoveryException.ChallengeInvalid>(value.toString()) {
                server.recoverLastDevice(phone, authorization.withChallenge(value))
            }
        }
        // Another device's target in the route.
        assertFailsWith<LastDeviceRecoveryException.InvalidRequest> { server.recoverLastDevice(laptop, authorization) }
        // A recovery of laptop's challenge, re-labelled for phone, fails its signatures and challenge.
        val laptopRecovery = server.recovery(target = laptop)
        assertFailsWith<LastDeviceRecoveryException.ChallengeInvalid> {
            server.recoverLastDevice(
                phone,
                laptopRecovery.withChallenge(
                    LastDeviceRecoveryChallenge(phone, laptopRecovery.statement.challenge.id, laptopRecovery.statement.challenge.nonce, 1, laptopRecovery.statement.challenge.expiresAt),
                ),
            )
        }
        storage.assertUnchanged()
    }

    @Test
    fun crossUserRecoveryKeyCannotRecoverAnotherUser() = runTest {
        val (storage, server) = setUp()
        val bobRecoveryKey = newRecoveryKey()
        server.registerLastDeviceRecoveryKey(
            server.signed(bob, bobKey, ProtectedEndpoint.REGISTER_LAST_DEVICE_RECOVERY_KEY),
            LastDeviceRecovery.registerKey(bobRecoveryKey, bob.userId),
        )
        // Bob's recovery key signs alice's phone challenge: the statement names bob's key, not alice's.
        val attack = LastDeviceRecovery.authorize(bobRecoveryKey, newKey(), server.lastDeviceRecoveryChallenge(phone))
        assertFailsWith<LastDeviceRecoveryException.InvalidProof> { server.recoverLastDevice(phone, attack) }
        storage.assertUnchanged()
        // Alice's key cannot recover bob either.
        assertFailsWith<LastDeviceRecoveryException.InvalidProof> {
            server.recoverLastDevice(bob, LastDeviceRecovery.authorize(recoveryKey, newKey(), server.lastDeviceRecoveryChallenge(bob)))
        }
        assertContentEquals(bobKey.publicKey, storage.state(bob).registration.publicKey)
    }

    @Test
    fun notConfiguredOrUnregisteredTargetsAreRejected() = runTest {
        val (storage, server) = setUp(withRecoveryKey = false)
        val challenge = LastDeviceRecoveryChallenge(phone, LastDeviceRecoveryChallengeId(ByteArray(16)), ByteArray(32), 1, clock.now())
        assertFailsWith<LastDeviceRecoveryException.NotConfigured> {
            server.recoverLastDevice(phone, LastDeviceRecovery.authorize(recoveryKey, newKey(), challenge))
        }
        server.registerLastDeviceRecoveryKey(
            server.signed(phone, phoneKey, ProtectedEndpoint.REGISTER_LAST_DEVICE_RECOVERY_KEY),
            LastDeviceRecovery.registerKey(recoveryKey, phone.userId),
        )
        val watch = DeviceAddress(UserId("alice"), DeviceId("watch"))
        val watchChallenge = LastDeviceRecoveryChallenge(watch, LastDeviceRecoveryChallengeId(ByteArray(16)), ByteArray(32), 1, clock.now())
        assertFailsWith<LastDeviceRecoveryException.TargetNotRegistered> {
            server.recoverLastDevice(watch, LastDeviceRecovery.authorize(recoveryKey, newKey(), watchChallenge))
        }
        assertNull(storage.devices.registrationState(watch), "recovery never registers an address")
        assertFailsWith<LastDeviceRecoveryException.ChallengeInvalid>("no challenge was issued") {
            server.recoverLastDevice(phone, LastDeviceRecovery.authorize(recoveryKey, newKey(), challenge))
        }
    }

    @Test
    fun registrationChangedSinceTheChallengeIsAConflict() = runTest {
        val (storage, server) = setUp()
        val authorization = server.recovery()
        // A routine rotation lands after the challenge was issued.
        val k2 = newKey()
        server.rotateDeviceAuthenticationKey(phone, DeviceAuthenticationRotation.create(phoneKey, k2, phone, 1, clock.now()))
        assertFailsWith<LastDeviceRecoveryException.Conflict> { server.recoverLastDevice(phone, authorization) }
        assertContentEquals(k2.publicKey, storage.state().registration.publicKey)
        assertEquals(2, storage.state().authEpoch)
        // The next challenge is for the new state and works.
        val fresh = server.recovery()
        assertEquals(2, fresh.statement.challenge.authEpoch)
        assertEquals(LastDeviceRecoveryOutcome.REPLACED, server.recoverLastDevice(phone, fresh))
        assertEquals(3, storage.state().authEpoch)
    }

    @Test
    fun registeredKeyAsReplacementIsAConflict() = runTest {
        val (storage, server) = setUp()
        val k2 = newKey()
        assertEquals(LastDeviceRecoveryOutcome.REPLACED, server.recoverLastDevice(phone, server.recovery(k2)))
        assertFailsWith<LastDeviceRecoveryException.Conflict> { server.recoverLastDevice(phone, server.recovery(k2)) }
        assertEquals(2, storage.state().authEpoch)
        assertNotNull(storage.lastDeviceRecovery.challenge(phone), "nothing consumed")
    }

    @Test
    fun staleRecoveryCannotOverwriteALaterKey() = runTest {
        val (storage, server) = setUp()
        val k2 = newKey()
        val first = server.recovery(k2)
        assertEquals(LastDeviceRecoveryOutcome.REPLACED, server.recoverLastDevice(phone, first))
        // K2 -> K3 by rotation; then the old K1 -> K2 recovery is replayed.
        val k3 = newKey()
        server.rotateDeviceAuthenticationKey(phone, DeviceAuthenticationRotation.create(k2, k3, phone, 2, clock.now()))
        assertFailsWith<LastDeviceRecoveryException.ChallengeInvalid> { server.recoverLastDevice(phone, first) }
        // Even with a fresh outstanding challenge the old statement does not match it.
        server.lastDeviceRecoveryChallenge(phone)
        assertFailsWith<LastDeviceRecoveryException.ChallengeInvalid> { server.recoverLastDevice(phone, first) }
        assertContentEquals(k3.publicKey, storage.state().registration.publicKey)
        assertEquals(3, storage.state().authEpoch)
    }

    @Test
    fun checkOrderRejectsEarlierFailuresFirst() = runTest {
        val (_, server) = setUp()
        val authorization = server.recovery()
        // Wrong route beats everything; a foreign recovery key beats challenge problems.
        assertFailsWith<LastDeviceRecoveryException.InvalidRequest> { server.recoverLastDevice(bob, authorization) }
        val foreign = LastDeviceRecovery.authorize(newRecoveryKey(), newKey(), LastDeviceRecoveryChallenge(phone, LastDeviceRecoveryChallengeId(ByteArray(16)), ByteArray(32), 9, clock.now()))
        assertFailsWith<LastDeviceRecoveryException.InvalidProof> { server.recoverLastDevice(phone, foreign) }
        // An expired challenge is Expired before its (bad) signatures are looked at.
        clock.now += LastDeviceRecovery.CHALLENGE_LIFETIME + 1.milliseconds
        val badProof = LastDeviceRecoveryAuthorization(authorization.statement, authorization.proofOfPossession, authorization.proofOfPossession)
        assertFailsWith<LastDeviceRecoveryException.Expired> { server.recoverLastDevice(phone, badProof) }
    }

    @Test
    fun competingRecoveriesOfOneChallengeHaveOneWinner() = runTest {
        repeat(5) {
            val (storage, server) = setUp()
            val challenge = server.lastDeviceRecoveryChallenge(phone)
            val keys = List(32) { newKey() }
            val results = withContext(Dispatchers.Default) {
                keys.map { key -> async { runCatching { server.recoverLastDevice(phone, LastDeviceRecovery.authorize(recoveryKey, key, challenge)) } } }
                    .map { it.await() }
            }
            assertEquals(1, results.count { it.isSuccess })
            assertTrue(
                results.filter { it.isFailure }.all {
                    it.exceptionOrNull() is LastDeviceRecoveryException.ChallengeInvalid || it.exceptionOrNull() is LastDeviceRecoveryException.Conflict
                },
            )
            assertEquals(2, storage.state().authEpoch)
            assertContentEquals(keys[results.indexOfFirst { it.isSuccess }].publicKey, storage.state().registration.publicKey)
        }
    }

    @Test
    fun identicalConcurrentSubmissionsRecoverOnce() = runTest {
        repeat(5) {
            val (storage, server) = setUp()
            val authorization = server.recovery()
            val results = withContext(Dispatchers.Default) {
                List(32) { async { runCatching { server.recoverLastDevice(phone, authorization) } } }.map { it.await() }
            }
            val outcomes = results.map { it.getOrThrow() }
            assertEquals(1, outcomes.count { it == LastDeviceRecoveryOutcome.REPLACED })
            assertEquals(31, outcomes.count { it == LastDeviceRecoveryOutcome.ALREADY_APPLIED })
            assertEquals(2, storage.state().authEpoch)
        }
    }

    @Test
    fun identicalSubmissionCommittingBetweenTheStateAndTheChallengeReadIsAnExactRetry() = runTest {
        // Deterministic version of the race above: while one submission reads the challenge,
        // an identical one commits and consumes it.
        val delegate = InMemoryServerStorage()
        var beforeChallengeRead: suspend () -> Unit = {}
        val storage = object : ServerStorage by delegate {
            override val lastDeviceRecovery = object : LastDeviceRecoveryRepository by delegate.lastDeviceRecovery {
                override suspend fun challenge(target: DeviceAddress): StoredLastDeviceRecoveryChallenge? {
                    val hook = beforeChallengeRead
                    beforeChallengeRead = {}
                    hook()
                    return delegate.lastDeviceRecovery.challenge(target)
                }
            }
        }
        val (_, server) = setUp(storage)
        val authorization = server.recovery()
        beforeChallengeRead = { assertEquals(LastDeviceRecoveryOutcome.REPLACED, server.recoverLastDevice(phone, authorization)) }
        assertEquals(LastDeviceRecoveryOutcome.ALREADY_APPLIED, server.recoverLastDevice(phone, authorization))
        assertEquals(2, storage.state().authEpoch)
        // A different key over the consumed challenge is still rejected on that path.
        beforeChallengeRead = {}
        assertFailsWith<LastDeviceRecoveryException.ChallengeInvalid> {
            server.recoverLastDevice(phone, LastDeviceRecovery.authorize(recoveryKey, newKey(), authorization.statement.challenge))
        }
    }

    @Test
    fun lastDeviceRecoveryAndDeviceRecoveryVerifiedAgainstTheSameStateHaveOneWinner() = runTest {
        for (lastDeviceFirst in listOf(true, false)) {
            val gated = GatedStorage(InMemoryServerStorage())
            val (storage, server) = setUp(gated)
            val k2 = newKey()
            val k3 = newKey()
            val lastDevice = server.recovery(k2)
            gated.armed = true
            val (lastDeviceResult, otherResult) = withContext(Dispatchers.Default) {
                val a = async { runCatching { server.recoverLastDevice(phone, lastDevice) } }
                val b = async { runCatching { server.recoverDevice(DeviceRecovery.authorize(laptopKey, DeviceRecovery.prepare(k3, phone, laptop, clock.now()))) } }
                gated.bothArrived.await()
                (if (lastDeviceFirst) gated.lastDevice else gated.other).complete(Unit)
                (if (lastDeviceFirst) a else b).await()
                (if (lastDeviceFirst) gated.other else gated.lastDevice).complete(Unit)
                a.await() to b.await()
            }
            assertEquals(2, storage.state().authEpoch, "exactly one transition")
            if (lastDeviceFirst) {
                assertEquals(LastDeviceRecoveryOutcome.REPLACED, lastDeviceResult.getOrThrow())
                assertIs<DeviceRecoveryException.Conflict>(otherResult.exceptionOrNull())
                assertContentEquals(k2.publicKey, storage.state().registration.publicKey)
            } else {
                assertEquals(DeviceRecoveryOutcome.REPLACED, otherResult.getOrThrow())
                assertIs<LastDeviceRecoveryException.Conflict>(lastDeviceResult.exceptionOrNull())
                assertContentEquals(k3.publicKey, storage.state().registration.publicKey)
                assertNotNull(storage.lastDeviceRecovery.challenge(phone), "the losing recovery consumed nothing")
            }
        }
    }

    @Test
    fun lastDeviceRecoveryAndRotationVerifiedAgainstTheSameStateHaveOneWinner() = runTest {
        for (lastDeviceFirst in listOf(true, false)) {
            val gated = GatedStorage(InMemoryServerStorage())
            val (storage, server) = setUp(gated)
            val k2 = newKey()
            val k3 = newKey()
            val lastDevice = server.recovery(k2)
            gated.armed = true
            val (lastDeviceResult, otherResult) = withContext(Dispatchers.Default) {
                val a = async { runCatching { server.recoverLastDevice(phone, lastDevice) } }
                val b = async { runCatching { server.rotateDeviceAuthenticationKey(phone, DeviceAuthenticationRotation.create(phoneKey, k3, phone, 1, clock.now())) } }
                gated.bothArrived.await()
                (if (lastDeviceFirst) gated.lastDevice else gated.other).complete(Unit)
                (if (lastDeviceFirst) a else b).await()
                (if (lastDeviceFirst) gated.other else gated.lastDevice).complete(Unit)
                a.await() to b.await()
            }
            assertEquals(2, storage.state().authEpoch, "exactly one transition")
            if (lastDeviceFirst) {
                assertEquals(LastDeviceRecoveryOutcome.REPLACED, lastDeviceResult.getOrThrow())
                assertIs<DeviceAuthenticationRotationException.Conflict>(otherResult.exceptionOrNull())
                assertContentEquals(k2.publicKey, storage.state().registration.publicKey)
            } else {
                assertEquals(DeviceAuthenticationRotationOutcome.ROTATED, otherResult.getOrThrow())
                assertIs<LastDeviceRecoveryException.Conflict>(lastDeviceResult.exceptionOrNull())
                assertContentEquals(k3.publicKey, storage.state().registration.publicKey)
            }
        }
    }

    /**
     * Delegates to [delegate]; while [armed], holds the first last-device
     * recovery and the first other replacement (device recovery or rotation)
     * until the test completes [lastDevice] or [other]. [bothArrived]
     * completes once both passed the service's checks against the same state.
     */
    private class GatedStorage(private val delegate: ServerStorage) : ServerStorage by delegate {
        var armed = false
        val lastDevice = CompletableDeferred<Unit>()
        val other = CompletableDeferred<Unit>()
        val bothArrived = CompletableDeferred<Unit>()
        private val lastDeviceArrived = CompletableDeferred<Unit>()
        private val otherArrived = CompletableDeferred<Unit>()

        private suspend fun arrive(mine: CompletableDeferred<Unit>, theirs: CompletableDeferred<Unit>, gate: CompletableDeferred<Unit>) {
            if (!armed) return
            mine.complete(Unit)
            if (theirs.isCompleted) bothArrived.complete(Unit)
            gate.await()
        }

        override val devices: DeviceRegistrationRepository = object : DeviceRegistrationRepository by delegate.devices {
            override suspend fun replaceForLastDeviceRecovery(replacement: LastDeviceRecoveryReplacement): LastDeviceRecoveryReplacementResult {
                arrive(lastDeviceArrived, otherArrived, lastDevice)
                return delegate.devices.replaceForLastDeviceRecovery(replacement)
            }

            override suspend fun replaceForRecovery(replacement: RecoveryReplacement): RecoveryReplacementResult {
                arrive(otherArrived, lastDeviceArrived, other)
                return delegate.devices.replaceForRecovery(replacement)
            }

            override suspend fun replaceForRotation(replacement: RotationReplacement): RotationReplacementResult {
                arrive(otherArrived, lastDeviceArrived, other)
                return delegate.devices.replaceForRotation(replacement)
            }
        }
    }
}
