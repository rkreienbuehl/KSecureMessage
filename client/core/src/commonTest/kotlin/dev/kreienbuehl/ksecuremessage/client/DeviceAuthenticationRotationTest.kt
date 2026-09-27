package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException.AuthenticationFailure
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException.RotationFailure
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationRotation
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequestAuthentication
import dev.kreienbuehl.ksecuremessage.protocol.VerificationState
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage
import dev.kreienbuehl.ksecuremessage.storage.DeviceAuthenticationKeyStore
import dev.kreienbuehl.ksecuremessage.storage.client.inmemory.InMemoryClientStorage
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.days

private val PHONE_LAPTOP = DeviceAddress(UserId("alice"), DeviceId("laptop"))

/**
 * Routine device authentication key rotation on the client
 * (docs/device-authentication-rotation.md): a pending K2 is prepared once and
 * reused, K1 authorizes it and K2 proves possession, the server replaces the
 * key, the client promotes K2. Against [ServerBackedNetwork], which applies
 * the server's checks and the atomic replacement of
 * [dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationRepository.replaceForRotation].
 * Every network call checks that no storage transaction is open.
 */
class DeviceAuthenticationRotationTest {
    private val engine = KodiumProtocolEngine()
    private val clock = ManualClock()

    /** Network calls so far; [failCall] makes the call with that number fail with [failure]. */
    private var calls = 0
    private var failCall: Int? = null
    private var failure: () -> Exception = { SecureMessageTransportException.UnexpectedResponse(503) }

    private val phoneStorage = LosableKeyStorage(InMemoryClientStorage())
    private val failing = FailingClientStorage(phoneStorage)
    private val tracking = TransactionTrackingStorage(failing)

    private val network = ServerBackedNetwork {
        assertEquals(0, tracking.depth, "network call inside a storage transaction")
        calls++
        if (calls == failCall) {
            failCall = null
            throw failure()
        }
    }

    private fun client(address: DeviceAddress, storage: ClientStorage) =
        SecureMessageClient(address, storage, engine, network, PreKeyConfiguration(oneTimePreKeyTarget = 3), clock)

    private val phone get() = client(ALICE, tracking) // a new instance each time, like an application restart
    private val laptop = client(PHONE_LAPTOP, InMemoryClientStorage())
    private val bob = client(BOB, InMemoryClientStorage())

    /** Makes the [n]-th network call from now fail. */
    private fun failNetworkCall(n: Int, exception: () -> Exception = { SecureMessageTransportException.UnexpectedResponse(503) }) {
        failCall = calls + n
        failure = exception
    }

    /** Phone, laptop and Bob registered with prekeys; the phone and Bob have a session and verified each other. */
    private suspend fun setUp(): DeviceAuthenticationKeyPair {
        for (device in listOf(phone, laptop, bob)) {
            device.initialize()
            device.registerDevice()
            device.publishPreKeys()
        }
        bob.send(ALICE, "before".encodeToByteArray())
        val phone = phone
        assertEquals("before", phone.accept(phone.receive().single()).decodeToString())
        bob.decrypt(bob.receive().single()) // the ACK
        phone.markRemoteIdentityVerified(phone.safetyNumber(BOB))
        bob.markRemoteIdentityVerified(bob.safetyNumber(ALICE))
        return assertNotNull(phoneStorage.deviceAuthentication.keyPair())
    }

    private suspend fun registered() = assertNotNull(network.server.devices.registrationState(ALICE))

    private suspend fun activeKey() = assertNotNull(phoneStorage.deviceAuthentication.keyPair())

    private suspend fun pendingKey() = phoneStorage.deviceAuthentication.pendingRotationKeyPair()

    private fun signerFor(key: DeviceAuthenticationKeyPair) = ServerRequestSigner { ServerRequestAuthentication.sign(key, it, clock.now()) }

    @Test
    fun rotationReplacesTheKeyAndLeavesMessagingAlone() = runTest {
        val k1 = setUp()
        // Messaging state the rotation must not touch.
        bob.send(ALICE, "queued".encodeToByteArray())
        phone.send(BOB, "pending at the phone".encodeToByteArray())
        network.receive(BOB) // lost: stays pending at the phone
        val identity = assertNotNull(phoneStorage.identity.identity())
        val signedPreKey = assertNotNull(phoneStorage.preKeys.currentSignedPreKey())
        val oneTimePreKeys = phoneStorage.preKeys.publicOneTimePreKeys().map { it.id }
        val pin = assertNotNull(phoneStorage.remoteIdentities.record(BOB))
        val session = assertNotNull(phoneStorage.sessions.load(BOB))
        val pending = phone.pendingMessages(limit = 100, recipient = BOB).messages.map { it.id }
        val retired = phoneStorage.sessionInitiations.retiredSignedPreKeyIds()

        phone.prepareDeviceAuthenticationRotation()
        val k2 = assertNotNull(pendingKey())
        assertContentEquals(k1.privateKey, activeKey().privateKey, "K1 stays active until the server accepted K2")
        assertContentEquals(k1.publicKey, registered().registration.publicKey, "preparing changes nothing on the server")
        assertTrue(network.rotationAttempts.isEmpty(), "preparing does no network I/O")

        phone.completeDeviceAuthenticationRotation()

        assertContentEquals(k2.privateKey, activeKey().privateKey)
        assertNull(pendingKey())
        assertContentEquals(k2.publicKey, registered().registration.publicKey)
        assertEquals(2, registered().authEpoch)
        assertEquals(DeviceAuthenticationRotation.rotationId(network.rotationAttempts.single().statement), registered().rotationId)
        assertEquals(1, network.rotationAttempts.single().statement.expectedAuthEpoch)
        // K1 is rejected at once; K2 signs everything now.
        val rejected = assertFailsWith<SecureMessageTransportException.AuthenticationFailed> { network.receive(ALICE, signerFor(k1)) }
        assertEquals(AuthenticationFailure.INVALID, rejected.failure)

        assertContentEquals(identity.privateKey, phoneStorage.identity.identity()?.privateKey)
        assertEquals(signedPreKey.id, phoneStorage.preKeys.currentSignedPreKey()?.id)
        assertEquals(oneTimePreKeys, phoneStorage.preKeys.publicOneTimePreKeys().map { it.id })
        val pinAfter = assertNotNull(phoneStorage.remoteIdentities.record(BOB))
        assertContentEquals(pin.identityKey, pinAfter.identityKey)
        assertEquals(pin.verification, pinAfter.verification)
        assertContentEquals(session.state, phoneStorage.sessions.load(BOB)?.state)
        assertEquals(pending, phone.pendingMessages(limit = 100, recipient = BOB).messages.map { it.id })
        assertEquals(retired, phoneStorage.sessionInitiations.retiredSignedPreKeyIds())
        val phone = phone
        assertEquals("queued", phone.accept(phone.receive().single()).decodeToString())
        phone.publishPreKeys()
    }

    @Test
    fun rotationLeavesMessagingIdentityVerificationUnchanged() = runTest {
        setUp()
        val phonesView = assertNotNull(phone.remoteIdentityTrust(BOB))
        val phonesNumber = phone.safetyNumber(BOB)
        val bobsView = assertNotNull(bob.remoteIdentityTrust(ALICE))
        val bobsNumber = bob.safetyNumber(ALICE)
        val messagingIdentity = assertNotNull(phoneStorage.identity.identity()).publicKey

        phone.rotateDeviceAuthenticationKey()
        phone.rotateDeviceAuthenticationKey()
        assertEquals(3, registered().authEpoch)

        assertContentEquals(messagingIdentity, phoneStorage.identity.identity()?.publicKey)
        assertEquals(phonesView, phone.remoteIdentityTrust(BOB))
        assertEquals(VerificationState.VERIFIED, phone.remoteIdentityTrust(BOB)?.verification)
        assertEquals(phonesNumber, phone.safetyNumber(BOB))
        assertEquals(bobsView, bob.remoteIdentityTrust(ALICE))
        assertEquals(VerificationState.VERIFIED, bob.remoteIdentityTrust(ALICE)?.verification)
        assertEquals(bobsNumber, bob.safetyNumber(ALICE))
        assertEquals(phone.safetyNumber(BOB), bob.safetyNumber(ALICE))
        // Bob's session with the phone goes on without a new initiation.
        bob.send(ALICE, "after".encodeToByteArray())
        val phone = phone
        assertEquals("after", phone.accept(phone.receive().single()).decodeToString())
    }

    @Test
    fun pendingKeyIsCreatedOnceAndReusedAcrossRestarts() = runTest {
        setUp()
        phone.prepareDeviceAuthenticationRotation()
        val k2 = assertNotNull(pendingKey())
        phone.prepareDeviceAuthenticationRotation() // new client instance
        phone.prepareDeviceAuthenticationRotation()
        assertContentEquals(k2.privateKey, assertNotNull(pendingKey()).privateKey)

        phone.rotateDeviceAuthenticationKey() // resumes with the existing K2
        assertContentEquals(k2.publicKey, activeKey().publicKey)
        assertContentEquals(k2.publicKey, registered().registration.publicKey)
    }

    @Test
    fun nothingRotatesImplicitly() = runTest {
        val k1 = setUp()
        val phone = phone
        repeat(3) {
            clock.advanceBy(400.days)
            phone.initialize()
            phone.publishPreKeys()
            bob.send(ALICE, "hi".encodeToByteArray())
            phone.decrypt(phone.receive().single())
            phone.send(BOB, "hello".encodeToByteArray())
        }
        assertContentEquals(k1.privateKey, activeKey().privateKey)
        assertNull(pendingKey())
        assertEquals(1, registered().authEpoch)
        assertTrue(network.rotationAttempts.isEmpty())
    }

    @Test
    fun preconditions() = runTest {
        val fresh = client(DeviceAddress(UserId("carol"), DeviceId("tablet")), InMemoryClientStorage())
        assertFailsWith<SecureMessageClientException.NotInitialized> { fresh.prepareDeviceAuthenticationRotation() }
        setUp()
        assertFailsWith<SecureMessageClientException.NoPendingDeviceAuthenticationRotation> { phone.completeDeviceAuthenticationRotation() }
        assertFailsWith<SecureMessageClientException.NoPendingDeviceAuthenticationRotation> { phone.resolveDeviceAuthenticationRotation() }
        assertEquals(1, registered().authEpoch)
    }

    @Test
    fun failedPendingKeyPersistenceLeavesNothing() = runTest {
        val k1 = setUp()
        failing.failPendingRotationKeyStore = true
        assertFailsWith<StorageFailure> { phone.prepareDeviceAuthenticationRotation() }
        failing.failPendingRotationKeyStore = false
        assertNull(pendingKey())
        assertContentEquals(k1.privateKey, activeKey().privateKey)
        assertTrue(network.rotationAttempts.isEmpty())
        phone.rotateDeviceAuthenticationKey()
        assertEquals(2, registered().authEpoch)
    }

    @Test
    fun networkFailureBeforeSubmissionKeepsBothKeys() = runTest {
        val k1 = setUp()
        phone.prepareDeviceAuthenticationRotation()
        val k2 = assertNotNull(pendingKey())

        failNetworkCall(1) // the epoch read
        assertFailsWith<SecureMessageTransportException.UnexpectedResponse> { phone.completeDeviceAuthenticationRotation() }
        failNetworkCall(2) // the rotation request itself
        assertFailsWith<SecureMessageTransportException.UnexpectedResponse> { phone.completeDeviceAuthenticationRotation() }
        assertTrue(network.rotationAttempts.isEmpty())
        assertContentEquals(k1.privateKey, activeKey().privateKey)
        assertContentEquals(k2.privateKey, assertNotNull(pendingKey()).privateKey)
        assertEquals(1, registered().authEpoch)
        phone.receive() // K1 still works

        phone.completeDeviceAuthenticationRotation()
        assertContentEquals(k2.privateKey, activeKey().privateKey)
        assertEquals(2, registered().authEpoch)
    }

    @Test
    fun definiteServerRejectionKeepsK1AndThePendingKey() = runTest {
        val k1 = setUp()
        phone.prepareDeviceAuthenticationRotation()
        val k2 = assertNotNull(pendingKey())
        failNetworkCall(2) { SecureMessageTransportException.DeviceAuthenticationRotationRejected(RotationFailure.INVALID_PROOF) }
        val rejected = assertFailsWith<SecureMessageTransportException.DeviceAuthenticationRotationRejected> {
            phone.completeDeviceAuthenticationRotation()
        }
        assertEquals(RotationFailure.INVALID_PROOF, rejected.reason)
        assertContentEquals(k1.privateKey, activeKey().privateKey)
        assertContentEquals(k2.privateKey, assertNotNull(pendingKey()).privateKey, "kept for another attempt, never deleted automatically")
        assertEquals(1, registered().authEpoch)
        phone.completeDeviceAuthenticationRotation()
        assertEquals(2, registered().authEpoch)
    }

    @Test
    fun lostResponseIsResolvedOnTheNextAttempt() = runTest {
        val k1 = setUp()
        phone.prepareDeviceAuthenticationRotation()
        val k2 = assertNotNull(pendingKey())
        network.afterRotation = {
            network.afterRotation = {}
            throw SecureMessageTransportException.UnexpectedResponse(504)
        }
        assertFailsWith<SecureMessageTransportException.UnexpectedResponse> { phone.completeDeviceAuthenticationRotation() }
        // The server applied it; the phone does not know yet.
        assertContentEquals(k2.publicKey, registered().registration.publicKey)
        assertContentEquals(k1.privateKey, activeKey().privateKey)

        phone.completeDeviceAuthenticationRotation() // K1 is rejected for the epoch read; the K2 probe resolves it
        assertContentEquals(k2.privateKey, activeKey().privateKey)
        assertNull(pendingKey())
        assertEquals(2, registered().authEpoch, "no second transition")
        assertEquals(1, network.rotationAttempts.size)
        phone.receive()
    }

    @Test
    fun lostResponseIsResolvedByAnExplicitProbe() = runTest {
        setUp()
        phone.prepareDeviceAuthenticationRotation()
        assertFalse(phone.resolveDeviceAuthenticationRotation(), "not registered yet")
        assertNotNull(pendingKey(), "kept")
        network.afterRotation = {
            network.afterRotation = {}
            throw SecureMessageTransportException.UnexpectedResponse(504)
        }
        assertFailsWith<SecureMessageTransportException.UnexpectedResponse> { phone.completeDeviceAuthenticationRotation() }
        assertTrue(phone.resolveDeviceAuthenticationRotation())
        assertNull(pendingKey())
        assertEquals(2, registered().authEpoch)
    }

    @Test
    fun promotionFailureIsResolvedAfterRestart() = runTest {
        val k1 = setUp()
        phone.prepareDeviceAuthenticationRotation()
        val k2 = assertNotNull(pendingKey())
        failing.failRotationKeyPromotion = true
        assertFailsWith<StorageFailure> { phone.completeDeviceAuthenticationRotation() }
        failing.failRotationKeyPromotion = false
        assertEquals(2, registered().authEpoch, "the server committed")
        assertContentEquals(k1.privateKey, activeKey().privateKey, "the promotion rolled back")
        assertContentEquals(k2.privateKey, assertNotNull(pendingKey()).privateKey, "K2 survived")

        phone.completeDeviceAuthenticationRotation() // after a restart: resolves, no second transition
        assertContentEquals(k2.privateKey, activeKey().privateKey)
        assertNull(pendingKey())
        assertEquals(2, registered().authEpoch)
        assertEquals(1, network.rotationAttempts.size)
    }

    @Test
    fun cancelRemovesOnlyThePendingRotationKey() = runTest {
        val k1 = setUp()
        phone.prepareDeviceAuthenticationRotation()
        val k2 = assertNotNull(pendingKey())
        phone.cancelDeviceAuthenticationRotation()
        assertNull(pendingKey())
        assertNull(phoneStorage.deviceAuthentication.pendingRecoveryKeyPair())
        assertContentEquals(k1.privateKey, activeKey().privateKey)
        phone.cancelDeviceAuthenticationRotation() // nothing pending: harmless
        phone.prepareDeviceAuthenticationRotation()
        assertFalse(k2.publicKey.contentEquals(assertNotNull(pendingKey()).publicKey), "a new rotation gets a new key")
    }

    @Test
    fun recoveryAndRotationCannotBePendingTogether() = runTest {
        setUp()
        phone.prepareDeviceAuthenticationRotation()
        assertFailsWith<SecureMessageClientException.DeviceAuthenticationRotationInProgress> {
            phone.prepareDeviceAuthenticationRecovery(PHONE_LAPTOP)
        }
        assertNull(phoneStorage.deviceAuthentication.pendingRecoveryKeyPair())
        phone.cancelDeviceAuthenticationRotation()

        phone.prepareDeviceAuthenticationRecovery(PHONE_LAPTOP)
        assertFailsWith<SecureMessageClientException.DeviceAuthenticationRecoveryInProgress> { phone.prepareDeviceAuthenticationRotation() }
        assertNull(pendingKey())
        phone.cancelDeviceAuthenticationRecovery()
        phone.rotateDeviceAuthenticationKey()
        assertEquals(2, registered().authEpoch)
    }

    @Test
    fun lostK1DuringAnUnappliedRotationEscapesToRecovery() = runTest {
        setUp()
        phone.prepareDeviceAuthenticationRotation()
        val k2 = assertNotNull(pendingKey())
        phoneStorage.lost = true

        assertFailsWith<SecureMessageClientException.NotInitialized> { phone.completeDeviceAuthenticationRotation() }
        assertFalse(phone.resolveDeviceAuthenticationRotation(), "the server still holds K1")
        assertNull(phoneStorage.deviceAuthentication.keyPair(), "K2 is never promoted just because K1 vanished")
        phone.cancelDeviceAuthenticationRotation()

        val request = phone.prepareDeviceAuthenticationRecovery(PHONE_LAPTOP)
        phone.completeDeviceAuthenticationRecovery(laptop.authorizeDeviceRecovery(request))
        assertContentEquals(request.replacementPublicKey, activeKey().publicKey)
        assertFalse(k2.publicKey.contentEquals(activeKey().publicKey))
        assertEquals(2, registered().authEpoch)
        assertNotNull(registered().recoveryId)
        phone.receive()
    }

    @Test
    fun lostK1AfterAnAppliedRotationIsResolvedWithoutRecovery() = runTest {
        setUp()
        phone.prepareDeviceAuthenticationRotation()
        val k2 = assertNotNull(pendingKey())
        network.afterRotation = {
            network.afterRotation = {}
            phoneStorage.lost = true
            throw SecureMessageTransportException.UnexpectedResponse(504)
        }
        assertFailsWith<SecureMessageTransportException.UnexpectedResponse> { phone.completeDeviceAuthenticationRotation() }
        assertTrue(phone.resolveDeviceAuthenticationRotation())
        assertContentEquals(k2.privateKey, activeKey().privateKey)
        phone.initialize()
        phone.receive()
    }

    @Test
    fun competingRecoveryWinsAndTheRotationFailsCleanly() = runTest {
        val k1 = setUp()
        phone.prepareDeviceAuthenticationRotation()
        val k2 = assertNotNull(pendingKey())
        // Meanwhile the laptop recovers the phone to K3 (for example after a backup restore elsewhere).
        val k3 = engine.createDeviceAuthenticationKey()
        val recovery = dev.kreienbuehl.ksecuremessage.protocol.DeviceRecovery.prepare(k3, ALICE, PHONE_LAPTOP, clock.now())
        network.recoverDevice(laptop.authorizeDeviceRecovery(recovery))

        val rejected = assertFailsWith<SecureMessageTransportException.AuthenticationFailed> { phone.completeDeviceAuthenticationRotation() }
        assertEquals(AuthenticationFailure.INVALID, rejected.failure)
        assertContentEquals(k3.publicKey, registered().registration.publicKey)
        assertEquals(2, registered().authEpoch)
        assertContentEquals(k1.privateKey, activeKey().privateKey, "nothing promoted")
        assertContentEquals(k2.privateKey, assertNotNull(pendingKey()).privateKey)
    }

    @Test
    fun rotationThenRecoveryThenRotation() = runTest {
        setUp()
        phone.rotateDeviceAuthenticationKey()
        phoneStorage.lost = true
        val request = phone.prepareDeviceAuthenticationRecovery(PHONE_LAPTOP)
        phone.completeDeviceAuthenticationRecovery(laptop.authorizeDeviceRecovery(request))
        assertEquals(3, registered().authEpoch)
        phone.rotateDeviceAuthenticationKey()
        assertEquals(4, registered().authEpoch)
        assertContentEquals(activeKey().publicKey, registered().registration.publicKey)
        phone.receive()
    }

    /**
     * Delegates to [delegate]; [lost] hides the active device authentication
     * key, like an installation that lost it, until a pending key is promoted.
     */
    private class LosableKeyStorage(private val delegate: ClientStorage) : ClientStorage by delegate {
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

            override suspend fun promotePendingRecoveryKeyPair() {
                storage.deviceAuthentication.promotePendingRecoveryKeyPair()
                lost = false
            }

            override suspend fun promotePendingRotationKeyPair() {
                storage.deviceAuthentication.promotePendingRotationKeyPair()
                lost = false
            }
        }
    }
}
