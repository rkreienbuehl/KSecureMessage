package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException.LastDeviceRecoveryFailure
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException.RecoveryKeyFailure
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationRotation
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecovery
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryKey
import dev.kreienbuehl.ksecuremessage.protocol.RequestNonce
import dev.kreienbuehl.ksecuremessage.protocol.VerificationState
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage
import dev.kreienbuehl.ksecuremessage.storage.DeviceAuthenticationKeyStore
import dev.kreienbuehl.ksecuremessage.storage.RotationReplacement
import dev.kreienbuehl.ksecuremessage.storage.RotationReplacementResult
import dev.kreienbuehl.ksecuremessage.storage.client.inmemory.InMemoryClientStorage
import kotlinx.coroutines.test.runTest
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

/**
 * Last-device recovery on the client (docs/last-device-recovery.md): the
 * user's only device registers an offline recovery key while it is healthy,
 * loses its device authentication key, and recovers it with the offline key
 * alone; against [ServerBackedNetwork], which applies the server's checks,
 * the challenge and the atomic replacement of
 * [dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationRepository.replaceForLastDeviceRecovery].
 */
class LastDeviceRecoveryTest {
    private val engine = KodiumProtocolEngine()
    private val clock = ManualClock()
    private var failNextNetworkCall = false
    private lateinit var tracking: TransactionTrackingStorage
    private val network = ServerBackedNetwork(clock) {
        if (::tracking.isInitialized) assertEquals(0, tracking.depth, "network call inside a storage transaction")
        if (failNextNetworkCall) {
            failNextNetworkCall = false
            throw SecureMessageTransportException.UnexpectedResponse(503)
        }
    }

    private val phoneStorage = LostKeyStorage(InMemoryClientStorage())
    private val failing = FailingClientStorage(phoneStorage)

    init {
        tracking = TransactionTrackingStorage(failing)
    }

    private fun client(address: DeviceAddress, storage: ClientStorage) =
        SecureMessageClient(address, storage, engine, network, PreKeyConfiguration(oneTimePreKeyTarget = 3), clock)

    /** Alice's only device; a new instance each time, like an application restart. */
    private val phone get() = client(ALICE, tracking)
    private val bob = client(BOB, InMemoryClientStorage())

    /** The offline recovery key, created by the healthy phone and "written down" as text. */
    private lateinit var recoveryText: String

    private val recoveryKey get() = LastDeviceRecoveryKey.decode(recoveryText)

    /**
     * Phone (alice's only device) and Bob registered; the phone registers its
     * recovery key; Bob and the phone talk; then the phone loses its
     * authentication key, and Bob sends one more message.
     */
    private suspend fun lostPhone(registerRecoveryKey: Boolean = true): DeviceAuthenticationKeyPair {
        for (device in listOf(phone, bob)) {
            device.initialize()
            device.registerDevice()
            device.publishPreKeys()
        }
        val phone = phone
        val key = phone.createLastDeviceRecoveryKey()
        recoveryText = key.encode()
        if (registerRecoveryKey) phone.registerLastDeviceRecoveryKey(key)
        bob.send(ALICE, "before".encodeToByteArray())
        assertEquals("before", phone.accept(phone.receive().single()).decodeToString())
        bob.decrypt(bob.receive().single()) // the ACK
        bob.send(ALICE, "while lost".encodeToByteArray())
        val lost = assertNotNull(phoneStorage.deviceAuthentication.keyPair())
        phoneStorage.lost = true
        return lost
    }

    private suspend fun registeredKey() = assertNotNull(network.server.devices.registration(ALICE)).publicKey

    private suspend fun pendingKey() = phoneStorage.deviceAuthentication.pendingLastDeviceRecoveryKeyPair()

    @Test
    fun lastDeviceIsRecoveredWithTheOfflineRecoveryKey() = runTest {
        val lost = lostPhone()
        val identity = assertNotNull(phoneStorage.identity.identity())
        val signedPreKey = assertNotNull(phoneStorage.preKeys.currentSignedPreKey())
        val oneTimePreKeys = phoneStorage.preKeys.publicOneTimePreKeys().map { it.id }
        val bobPin = phoneStorage.remoteIdentities.identityKey(BOB)
        val session = assertNotNull(phoneStorage.sessions.load(BOB)).state

        // The lost key fails closed; nothing regenerates it, and there is no other device.
        assertFailsWith<SecureMessageClientException.InconsistentStorage> { phone.initialize() }
        assertFailsWith<SecureMessageClientException.NotInitialized> { phone.receive() }

        phone.prepareLastDeviceRecovery()
        val pending = assertNotNull(pendingKey())
        assertContentEquals(lost.publicKey, registeredKey(), "preparing changes nothing on the server")
        clock.advanceBy(3.days)
        phone.completeLastDeviceRecovery(recoveryKey)

        assertContentEquals(pending.publicKey, registeredKey())
        assertContentEquals(pending.privateKey, phoneStorage.deviceAuthentication.keyPair()?.privateKey)
        assertNull(pendingKey())
        val state = assertNotNull(network.server.devices.registrationState(ALICE))
        assertEquals(2, state.authEpoch)
        assertEquals(clock.now, state.authKeyInstalledAt, "installed at the server's time")
        assertEquals(1, network.lastDeviceRecoveryAttempts.size)

        // Messaging state is untouched, and the queued message is readable with the recovered key.
        assertContentEquals(identity.privateKey, phoneStorage.identity.identity()?.privateKey)
        assertEquals(signedPreKey.id, phoneStorage.preKeys.currentSignedPreKey()?.id)
        assertEquals(oneTimePreKeys, phoneStorage.preKeys.publicOneTimePreKeys().map { it.id })
        assertContentEquals(bobPin, phoneStorage.remoteIdentities.identityKey(BOB))
        assertContentEquals(session, phoneStorage.sessions.load(BOB)?.state)
        val phone = phone
        phone.initialize()
        val message = phone.decrypt(phone.receive().single())
        assertEquals("while lost", message.delivery().plaintext.decodeToString())
        phone.publishPreKeys()
        // The recovered key rotates like any other key.
        phone.rotateDeviceAuthenticationKey()
        assertEquals(3, network.server.devices.registrationState(ALICE)?.authEpoch)
    }

    @Test
    fun recoveryLeavesIdentityVerificationAndSafetyNumbersUnchanged() = runTest {
        lostPhone()
        phoneStorage.lost = false
        bob.markRemoteIdentityVerified(bob.safetyNumber(ALICE))
        phone.markRemoteIdentityVerified(phone.safetyNumber(BOB))
        val bobsView = assertNotNull(bob.remoteIdentityTrust(ALICE))
        val bobsNumber = bob.safetyNumber(ALICE)
        val phonesView = assertNotNull(phone.remoteIdentityTrust(BOB))
        val phonesNumber = phone.safetyNumber(BOB)
        val messagingIdentity = assertNotNull(phoneStorage.identity.identity()).publicKey
        phoneStorage.lost = true

        phone.recoverLastDevice(recoveryKey)

        assertContentEquals(messagingIdentity, phoneStorage.identity.identity()?.publicKey)
        assertEquals(bobsView, bob.remoteIdentityTrust(ALICE))
        assertEquals(VerificationState.VERIFIED, bob.remoteIdentityTrust(ALICE)?.verification)
        assertEquals(bobsNumber, bob.safetyNumber(ALICE))
        assertEquals(phonesView, phone.remoteIdentityTrust(BOB))
        assertEquals(phonesNumber, phone.safetyNumber(BOB))
    }

    @Test
    fun onlyThePublicRecoveryKeyReachesTheServerAndItIsNeverReplaced() = runTest {
        lostPhone(registerRecoveryKey = false)
        phoneStorage.lost = false
        val phone = phone
        val key = recoveryKey
        phone.registerLastDeviceRecoveryKey(key)
        phone.registerLastDeviceRecoveryKey(key) // idempotent
        assertContentEquals(key.publicKey, network.server.lastDeviceRecovery.recoveryKey(ALICE.userId))
        val other = phone.createLastDeviceRecoveryKey()
        val conflict = assertFailsWith<SecureMessageTransportException.LastDeviceRecoveryKeyRejected> {
            phone.registerLastDeviceRecoveryKey(other)
        }
        assertEquals(RecoveryKeyFailure.CONFLICT, conflict.reason)
        assertContentEquals(key.publicKey, network.server.lastDeviceRecovery.recoveryKey(ALICE.userId))
        // The recovery key is none of the device's keys, and the client never stored it.
        assertFalse(key.publicKey.contentEquals(registeredKey()))
        assertFalse(key.publicKey.contentEquals(assertNotNull(phoneStorage.identity.identity()).publicKey))
        assertFalse(key.toString().contains(recoveryText))
    }

    @Test
    fun registeringTheRecoveryKeyNeedsTheActiveKey() = runTest {
        val fresh = client(ALICE, InMemoryClientStorage())
        val key = fresh.createLastDeviceRecoveryKey()
        assertFailsWith<SecureMessageClientException.NotInitialized> { fresh.registerLastDeviceRecoveryKey(key) }
        lostPhone(registerRecoveryKey = false)
        assertFailsWith<SecureMessageClientException.NotInitialized>("a lost key cannot register a recovery key") {
            phone.registerLastDeviceRecoveryKey(key)
        }
        assertNull(network.server.lastDeviceRecovery.recoveryKey(ALICE.userId))
    }

    @Test
    fun withoutARegisteredRecoveryKeyTheLastDeviceStaysLost() = runTest {
        val lost = lostPhone(registerRecoveryKey = false)
        phone.prepareLastDeviceRecovery()
        val e = assertFailsWith<SecureMessageTransportException.LastDeviceRecoveryRejected> { phone.completeLastDeviceRecovery(recoveryKey) }
        assertEquals(LastDeviceRecoveryFailure.NOT_CONFIGURED, e.reason)
        assertContentEquals(lost.publicKey, registeredKey())
        assertNotNull(pendingKey(), "the pending key stays")
        assertFailsWith<SecureMessageClientException.InconsistentStorage> { phone.initialize() }
    }

    @Test
    fun wrongRecoveryKeyIsRejectedAndKeepsThePendingKey() = runTest {
        val lost = lostPhone()
        phone.prepareLastDeviceRecovery()
        val pending = assertNotNull(pendingKey()).publicKey
        val e = assertFailsWith<SecureMessageTransportException.LastDeviceRecoveryRejected> {
            phone.completeLastDeviceRecovery(phone.createLastDeviceRecoveryKey())
        }
        assertEquals(LastDeviceRecoveryFailure.INVALID_PROOF, e.reason)
        assertContentEquals(lost.publicKey, registeredKey())
        assertContentEquals(pending, pendingKey()?.publicKey)
        phone.completeLastDeviceRecovery(recoveryKey)
        assertContentEquals(pending, registeredKey())
    }

    @Test
    fun pendingKeyIsCreatedOnceAndReusedAcrossRestartsUntilCancelled() = runTest {
        lostPhone()
        phone.prepareLastDeviceRecovery()
        val first = assertNotNull(pendingKey()).publicKey
        phone.prepareLastDeviceRecovery() // a restart: a new client instance
        assertContentEquals(first, pendingKey()?.publicKey)
        failNextNetworkCall = true
        assertFailsWith<SecureMessageTransportException.UnexpectedResponse> { phone.completeLastDeviceRecovery(recoveryKey) }
        assertContentEquals(first, pendingKey()?.publicKey, "a failure before submission keeps the pending key")
        assertTrue(network.lastDeviceRecoveryAttempts.isEmpty())

        phone.cancelLastDeviceRecovery()
        assertNull(pendingKey())
        assertFailsWith<SecureMessageClientException.NoPendingLastDeviceRecovery> { phone.completeLastDeviceRecovery(recoveryKey) }
        assertFailsWith<SecureMessageClientException.NoPendingLastDeviceRecovery> { phone.resolveLastDeviceRecovery() }
        phone.recoverLastDevice(recoveryKey)
        assertFalse(first.contentEquals(registeredKey()), "a new pending key after cancel")
    }

    @Test
    fun preparationNeedsTheIdentityAndExcludesOtherTransitions() = runTest {
        assertFailsWith<SecureMessageClientException.NotInitialized> { client(ALICE, InMemoryClientStorage()).prepareLastDeviceRecovery() }

        lostPhone()
        phoneStorage.lost = false
        phone.prepareDeviceAuthenticationRotation()
        assertFailsWith<SecureMessageClientException.DeviceAuthenticationRotationInProgress> { phone.prepareLastDeviceRecovery() }
        phone.cancelDeviceAuthenticationRotation()

        val laptop = DeviceAddress(UserId("alice"), DeviceId("laptop"))
        phone.prepareDeviceAuthenticationRecovery(laptop)
        assertFailsWith<SecureMessageClientException.DeviceAuthenticationRecoveryInProgress> { phone.prepareLastDeviceRecovery() }
        phone.cancelDeviceAuthenticationRecovery()

        phone.prepareLastDeviceRecovery()
        assertFailsWith<SecureMessageClientException.LastDeviceRecoveryInProgress> { phone.prepareDeviceAuthenticationRotation() }
        assertFailsWith<SecureMessageClientException.LastDeviceRecoveryInProgress> { phone.prepareDeviceAuthenticationRecovery(laptop) }
        assertIs<DeviceAuthenticationRotationResult.RecoveryInProgress>(
            phone.rotateDeviceAuthenticationKeyIfNeeded(DeviceAuthenticationRotationPolicy(1.milliseconds)),
        )
        assertTrue(phone.deviceAuthenticationRotationStatus().pendingRecovery)
        assertNull(phoneStorage.deviceAuthentication.pendingRotationKeyPair())
        assertNull(phoneStorage.deviceAuthentication.pendingRecoveryKeyPair())
    }

    @Test
    fun activeKeyStaysUntilPromotion() = runTest {
        val lost = lostPhone()
        phoneStorage.lost = false
        phone.prepareLastDeviceRecovery()
        // The still-present key keeps working until the server replaced it.
        phone.receive()
        phone.completeLastDeviceRecovery(recoveryKey)
        assertFalse(lost.publicKey.contentEquals(assertNotNull(phoneStorage.deviceAuthentication.keyPair()).publicKey))
        assertContentEquals(registeredKey(), phoneStorage.deviceAuthentication.keyPair()?.publicKey)
    }

    @Test
    fun lostResponseIsResolvedOnTheNextAttempt() = runTest {
        lostPhone()
        phone.prepareLastDeviceRecovery()
        val pending = assertNotNull(pendingKey()).publicKey
        var loseResponse = true
        network.afterLastDeviceRecovery = {
            if (loseResponse) {
                loseResponse = false
                throw SecureMessageTransportException.UnexpectedResponse(502)
            }
        }
        assertFailsWith<SecureMessageTransportException.UnexpectedResponse> { phone.completeLastDeviceRecovery(recoveryKey) }
        assertContentEquals(pending, registeredKey(), "the server committed")
        assertContentEquals(pending, pendingKey()?.publicKey, "not promoted yet")

        // The next attempt gets a challenge for the new state; the server calls it a conflict; the probe confirms the key.
        phone.completeLastDeviceRecovery(recoveryKey)
        assertNull(pendingKey())
        assertContentEquals(pending, phoneStorage.deviceAuthentication.keyPair()?.publicKey)
        assertEquals(2, network.server.devices.registrationState(ALICE)?.authEpoch, "the epoch grew once")
        phone.initialize()
        phone.receive()
    }

    @Test
    fun lostResponseIsResolvedByAnExplicitProbe() = runTest {
        lostPhone()
        phone.prepareLastDeviceRecovery()
        assertFalse(phone.resolveLastDeviceRecovery(), "nothing registered yet: the pending key stays")
        assertNotNull(pendingKey())
        network.afterLastDeviceRecovery = { throw SecureMessageTransportException.UnexpectedResponse(502) }
        assertFailsWith<SecureMessageTransportException.UnexpectedResponse> { phone.completeLastDeviceRecovery(recoveryKey) }
        network.afterLastDeviceRecovery = {}
        assertTrue(phone.resolveLastDeviceRecovery())
        assertNull(pendingKey())
        assertContentEquals(registeredKey(), phoneStorage.deviceAuthentication.keyPair()?.publicKey)
    }

    @Test
    fun promotionFailureIsResolvedAfterRestart() = runTest {
        lostPhone()
        phone.prepareLastDeviceRecovery()
        val pending = assertNotNull(pendingKey()).publicKey
        failing.failLastDeviceRecoveryKeyPromotion = true
        assertFailsWith<StorageFailure> { phone.completeLastDeviceRecovery(recoveryKey) }
        failing.failLastDeviceRecoveryKeyPromotion = false
        assertContentEquals(pending, registeredKey())
        assertContentEquals(pending, pendingKey()?.publicKey)
        assertFailsWith<SecureMessageClientException.InconsistentStorage>("still not promoted") { phone.initialize() }

        phone.completeLastDeviceRecovery(recoveryKey) // after a restart
        assertNull(pendingKey())
        phone.initialize()
        assertEquals(2, network.server.devices.registrationState(ALICE)?.authEpoch)
    }

    @Test
    fun failedPendingKeyPersistenceLeavesNothing() = runTest {
        lostPhone()
        failing.failPendingLastDeviceRecoveryKeyStore = true
        assertFailsWith<StorageFailure> { phone.prepareLastDeviceRecovery() }
        failing.failPendingLastDeviceRecoveryKeyStore = false
        assertNull(pendingKey())
        assertTrue(network.lastDeviceRecoveryChallenges.isEmpty(), "nothing was sent")
    }

    @Test
    fun competingTransitionAfterTheChallengeFailsCleanlyAndTheNextAttemptWorks() = runTest {
        val lost = lostPhone()
        phone.prepareLastDeviceRecovery()
        val pending = assertNotNull(pendingKey()).publicKey
        // Someone holding the old key rotates it right after the challenge was issued.
        val k3 = engine.createDeviceAuthenticationKey()
        var once = true
        network.afterLastDeviceRecoveryChallenge = {
            if (once) {
                once = false
                val state = assertNotNull(network.server.devices.registrationState(ALICE))
                val rotation = DeviceAuthenticationRotation.create(lost, k3, ALICE, state.authEpoch, clock.now())
                assertEquals(
                    RotationReplacementResult.REPLACED,
                    network.server.devices.replaceForRotation(
                        RotationReplacement(
                            state, k3.publicKey, DeviceAuthenticationRotation.rotationId(rotation.statement),
                            RequestNonce.random(), clock.now(), clock.now() - 5.minutes, clock.now(),
                        ),
                    ),
                )
            }
        }
        val e = assertFailsWith<SecureMessageTransportException.LastDeviceRecoveryRejected> { phone.completeLastDeviceRecovery(recoveryKey) }
        assertEquals(LastDeviceRecoveryFailure.CONFLICT, e.reason)
        assertContentEquals(k3.publicKey, registeredKey(), "the competing transition won")
        assertContentEquals(pending, pendingKey()?.publicKey, "the pending key stays")

        // The recovery key still takes the device back with a new challenge.
        phone.completeLastDeviceRecovery(recoveryKey)
        assertContentEquals(pending, registeredKey())
        assertEquals(3, network.server.devices.registrationState(ALICE)?.authEpoch)
    }

    @Test
    fun expiredChallengeFailsCleanlyAndTheNextAttemptWorks() = runTest {
        lostPhone()
        phone.prepareLastDeviceRecovery()
        var once = true
        network.afterLastDeviceRecoveryChallenge = {
            if (once) {
                once = false
                clock.advanceBy(LastDeviceRecovery.CHALLENGE_LIFETIME + 1.milliseconds)
            }
        }
        val e = assertFailsWith<SecureMessageTransportException.LastDeviceRecoveryRejected> { phone.completeLastDeviceRecovery(recoveryKey) }
        assertEquals(LastDeviceRecoveryFailure.EXPIRED, e.reason)
        assertNotNull(pendingKey())
        phone.completeLastDeviceRecovery(recoveryKey)
        assertNull(pendingKey())
        assertEquals(2, network.server.devices.registrationState(ALICE)?.authEpoch)
    }

    @Test
    fun recoveredDeviceCanBeRecoveredAgainWithTheSameKey() = runTest {
        lostPhone()
        phone.recoverLastDevice(recoveryKey)
        val first = registeredKey()
        phoneStorage.lost = true
        phone.recoverLastDevice(recoveryKey)
        assertFalse(first.contentEquals(registeredKey()))
        assertEquals(3, network.server.devices.registrationState(ALICE)?.authEpoch)
        assertEquals(2, network.lastDeviceRecoveryChallenges.map { it.id }.toSet().size, "a fresh challenge per recovery")
    }

    /**
     * In-memory storage whose active device authentication key can be
     * hidden, like an installation that lost it: [lost] makes
     * [DeviceAuthenticationKeyStore.keyPair] return `null` until a pending
     * last-device recovery key is promoted.
     */
    private class LostKeyStorage(private val delegate: ClientStorage) : ClientStorage by delegate {
        var lost = false

        override val deviceAuthentication: DeviceAuthenticationKeyStore get() = view(delegate)

        override suspend fun <T> transaction(block: suspend ClientStorage.() -> T): T = delegate.transaction {
            val tx = this
            object : ClientStorage by tx {
                override val deviceAuthentication: DeviceAuthenticationKeyStore = view(tx)
            }.block()
        }

        private fun view(storage: ClientStorage) = object : DeviceAuthenticationKeyStore by storage.deviceAuthentication {
            override suspend fun keyPair(): DeviceAuthenticationKeyPair? = if (lost) null else storage.deviceAuthentication.keyPair()

            override suspend fun promotePendingLastDeviceRecoveryKeyPair() {
                storage.deviceAuthentication.promotePendingLastDeviceRecoveryKeyPair()
                lost = false
            }
        }
    }
}
