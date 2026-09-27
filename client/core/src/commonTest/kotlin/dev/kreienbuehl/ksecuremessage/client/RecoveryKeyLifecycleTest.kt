package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException.LastDeviceRecoveryFailure
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException.RecoveryKeyTransitionFailure
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.LastDeviceRecoveryKeyStatus
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryKey
import dev.kreienbuehl.ksecuremessage.protocol.VerificationState
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage
import dev.kreienbuehl.ksecuremessage.storage.DeviceAuthenticationKeyStore
import dev.kreienbuehl.ksecuremessage.storage.client.inmemory.InMemoryClientStorage
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.days

/**
 * Offline recovery key rotation and revocation on the client
 * (docs/recovery-key-lifecycle.md), against [ServerBackedNetwork], which
 * applies the server's checks and the atomic storage transitions: explicit
 * operations with the current key supplied by the application, resolution of
 * a lost response by calling again, re-registration after a revocation, the
 * effect on last-device recovery, and no change to messaging or device
 * authentication state.
 */
class RecoveryKeyLifecycleTest {
    private val engine = KodiumProtocolEngine()
    private val clock = ManualClock()
    private lateinit var tracking: TransactionTrackingStorage
    private val network = ServerBackedNetwork(clock) {
        if (::tracking.isInitialized) assertEquals(0, tracking.depth, "network call inside a storage transaction")
    }

    private val phoneStorage = LostKeyStorage(InMemoryClientStorage())
    private val laptop = DeviceAddress(UserId("alice"), DeviceId("laptop"))

    init {
        tracking = TransactionTrackingStorage(phoneStorage)
    }

    private fun client(address: DeviceAddress, storage: ClientStorage) =
        SecureMessageClient(address, storage, engine, network, PreKeyConfiguration(oneTimePreKeyTarget = 3), clock)

    /** Alice's phone; a new instance each time, like an application restart. */
    private val phone get() = client(ALICE, tracking)
    private val laptopClient = client(laptop, InMemoryClientStorage())
    private val bob = client(BOB, InMemoryClientStorage())

    // Offline recovery keys, as the application gets them back from their text form.
    private lateinit var r1: LastDeviceRecoveryKey
    private lateinit var r2: LastDeviceRecoveryKey
    private lateinit var r3: LastDeviceRecoveryKey

    /** Phone, laptop and Bob registered; the phone and Bob talked; the phone registered R1. */
    private suspend fun setUp(registerRecoveryKey: Boolean = true) {
        r1 = LastDeviceRecoveryKey.decode(phone.createLastDeviceRecoveryKey().encode())
        r2 = LastDeviceRecoveryKey.decode(phone.createLastDeviceRecoveryKey().encode())
        r3 = LastDeviceRecoveryKey.decode(phone.createLastDeviceRecoveryKey().encode())
        for (device in listOf(phone, laptopClient, bob)) {
            device.initialize()
            device.registerDevice()
            device.publishPreKeys()
        }
        bob.send(ALICE, "hello".encodeToByteArray())
        val phone = phone
        assertEquals("hello", phone.accept(phone.receive().single()).decodeToString())
        bob.decrypt(bob.receive().single()) // the ACK
        if (registerRecoveryKey) phone.registerLastDeviceRecoveryKey(r1)
    }

    private suspend fun assertActive(key: LastDeviceRecoveryKey, epoch: Long) {
        val status = assertIs<LastDeviceRecoveryKeyStatus.Active>(laptopClient.lastDeviceRecoveryKeyStatus())
        assertEquals(epoch, status.epoch)
        assertTrue(status.isKey(key.publicKey))
    }

    @Test
    fun rotationReplacesTheRecoveryKeyAndChangesNothingElse() = runTest {
        setUp()
        assertEquals(LastDeviceRecoveryKeyStatus.Unconfigured, bob.lastDeviceRecoveryKeyStatus())
        val before = assertIs<LastDeviceRecoveryKeyStatus.Active>(phone.lastDeviceRecoveryKeyStatus())
        assertEquals(1, before.epoch)
        assertTrue(before.isKey(r1.publicKey))

        val identity = assertNotNull(phoneStorage.identity.identity())
        val deviceKey = assertNotNull(phoneStorage.deviceAuthentication.keyPair())
        val session = assertNotNull(phoneStorage.sessions.load(BOB)).state
        val oneTimePreKeys = phoneStorage.preKeys.publicOneTimePreKeys().map { it.id }
        val safetyNumber = phone.safetyNumber(BOB)
        phone.markRemoteIdentityVerified(safetyNumber)
        val registration = assertNotNull(network.server.devices.registrationState(ALICE))

        clock.advanceBy(1.days)
        assertEquals(LastDeviceRecoveryKeyRotationResult.ROTATED, phone.rotateLastDeviceRecoveryKey(r1, r2))
        val after = assertIs<LastDeviceRecoveryKeyStatus.Active>(phone.lastDeviceRecoveryKeyStatus())
        assertEquals(2, after.epoch)
        assertEquals(clock.now, after.installedAt)
        assertTrue(after.isKey(r2.publicKey))
        assertEquals(1, network.recoveryKeyTransitionAttempts.size)

        // Messaging identity, pins, verification, safety number, sessions, prekeys and device authentication stay.
        assertContentEquals(identity.privateKey, phoneStorage.identity.identity()?.privateKey)
        assertContentEquals(deviceKey.privateKey, phoneStorage.deviceAuthentication.keyPair()?.privateKey)
        assertContentEquals(session, phoneStorage.sessions.load(BOB)?.state)
        assertEquals(oneTimePreKeys, phoneStorage.preKeys.publicOneTimePreKeys().map { it.id })
        assertEquals(VerificationState.VERIFIED, phone.remoteIdentityTrust(BOB)?.verification)
        assertEquals(safetyNumber, phone.safetyNumber(BOB))
        val registrationAfter = assertNotNull(network.server.devices.registrationState(ALICE))
        assertContentEquals(registration.registration.publicKey, registrationAfter.registration.publicKey)
        assertEquals(registration.authEpoch, registrationAfter.authEpoch)
        assertEquals(registration.authKeyInstalledAt, registrationAfter.authKeyInstalledAt)
        assertTrue(phone.pendingMessages(BOB).isEmpty())
        bob.send(ALICE, "still here".encodeToByteArray())
        assertEquals("still here", phone.accept(phone.receive().single()).decodeToString())
    }

    @Test
    fun aLostRotationResponseIsResolvedByCallingAgain() = runTest {
        setUp()
        var loseResponse = true
        network.afterRecoveryKeyTransition = {
            if (loseResponse) {
                loseResponse = false
                throw SecureMessageTransportException.UnexpectedResponse(504)
            }
        }
        assertFailsWith<SecureMessageTransportException.UnexpectedResponse> { phone.rotateLastDeviceRecoveryKey(r1, r2) }
        assertActive(r2, epoch = 2)
        // After a restart the application calls again with the same keys: nothing is sent, the rotation is done.
        assertEquals(LastDeviceRecoveryKeyRotationResult.ALREADY_ACTIVE, phone.rotateLastDeviceRecoveryKey(r1, r2))
        assertEquals(1, network.recoveryKeyTransitionAttempts.size)
        assertActive(r2, epoch = 2)
    }

    @Test
    fun theSuppliedKeysMustMatchTheServer() = runTest {
        setUp(registerRecoveryKey = false)
        assertFailsWith<SecureMessageClientException.LastDeviceRecoveryKeyNotConfigured> { phone.rotateLastDeviceRecoveryKey(r1, r2) }
        assertFailsWith<SecureMessageClientException.LastDeviceRecoveryKeyNotConfigured> { phone.revokeLastDeviceRecoveryKey(r1) }
        phone.registerLastDeviceRecoveryKey(r1)
        // A device alone cannot replace or revoke the recovery key: it needs the active key.
        assertFailsWith<SecureMessageClientException.LastDeviceRecoveryKeyMismatch> { phone.rotateLastDeviceRecoveryKey(r3, r2) }
        assertFailsWith<SecureMessageClientException.LastDeviceRecoveryKeyMismatch> { phone.revokeLastDeviceRecoveryKey(r2) }
        assertFailsWith<IllegalArgumentException> { phone.rotateLastDeviceRecoveryKey(r1, LastDeviceRecoveryKey.decode(r1.encode())) }
        // Registration never replaces it either.
        val conflict = assertFailsWith<SecureMessageTransportException.LastDeviceRecoveryKeyRejected> { phone.registerLastDeviceRecoveryKey(r2) }
        assertEquals(SecureMessageTransportException.RecoveryKeyFailure.CONFLICT, conflict.reason)
        assertEquals(0, network.recoveryKeyTransitionAttempts.size, "nothing was sent")
        assertActive(r1, epoch = 1)
    }

    @Test
    fun anotherDeviceRotatesAndTheStaleCallerConflicts() = runTest {
        setUp()
        // The laptop rotates R1 -> R2; the phone still thinks R1 is active and tries R1 -> R3.
        assertEquals(LastDeviceRecoveryKeyRotationResult.ROTATED, laptopClient.rotateLastDeviceRecoveryKey(r1, r2))
        assertFailsWith<SecureMessageClientException.LastDeviceRecoveryKeyMismatch> { phone.rotateLastDeviceRecoveryKey(r1, r3) }
        assertActive(r2, epoch = 2)
        // With the current key it works from any device of the user.
        assertEquals(LastDeviceRecoveryKeyRotationResult.ROTATED, phone.rotateLastDeviceRecoveryKey(r2, r3))
        assertActive(r3, epoch = 3)
    }

    @Test
    fun revocationAndRegistrationAfterIt() = runTest {
        setUp()
        clock.advanceBy(1.days)
        assertEquals(LastDeviceRecoveryKeyRevocationResult.REVOKED, phone.revokeLastDeviceRecoveryKey(r1))
        assertEquals(LastDeviceRecoveryKeyStatus.Revoked(2, clock.now), phone.lastDeviceRecoveryKeyStatus())
        assertEquals(LastDeviceRecoveryKeyRevocationResult.ALREADY_REVOKED, laptopClient.revokeLastDeviceRecoveryKey(r1))
        assertEquals(1, network.recoveryKeyTransitionAttempts.size)
        assertFailsWith<SecureMessageClientException.LastDeviceRecoveryKeyNotConfigured> { phone.rotateLastDeviceRecoveryKey(r1, r2) }

        // Last-device recovery is off.
        val challenge = assertFailsWith<SecureMessageTransportException.LastDeviceRecoveryRejected> { network.lastDeviceRecoveryChallenge(ALICE) }
        assertEquals(LastDeviceRecoveryFailure.NOT_CONFIGURED, challenge.reason)

        // A new key is registered explicitly; the epoch continues.
        laptopClient.registerLastDeviceRecoveryKey(r3)
        assertActive(r3, epoch = 3)
        assertFailsWith<SecureMessageClientException.LastDeviceRecoveryKeyMismatch> { phone.revokeLastDeviceRecoveryKey(r1) }
    }

    @Test
    fun aLostRevocationResponseIsResolvedByCallingAgain() = runTest {
        setUp()
        var loseResponse = true
        network.afterRecoveryKeyTransition = {
            if (loseResponse) {
                loseResponse = false
                throw SecureMessageTransportException.UnexpectedResponse(504)
            }
        }
        assertFailsWith<SecureMessageTransportException.UnexpectedResponse> { phone.revokeLastDeviceRecoveryKey(r1) }
        assertEquals(LastDeviceRecoveryKeyRevocationResult.ALREADY_REVOKED, phone.revokeLastDeviceRecoveryKey(r1))
        assertEquals(1, network.recoveryKeyTransitionAttempts.size)
        assertIs<LastDeviceRecoveryKeyStatus.Revoked>(phone.lastDeviceRecoveryKeyStatus())
    }

    @Test
    fun lastDeviceRecoveryUsesTheRotatedKeyOnly() = runTest {
        setUp()
        assertEquals(LastDeviceRecoveryKeyRotationResult.ROTATED, phone.rotateLastDeviceRecoveryKey(r1, r2))
        val lost = assertNotNull(phoneStorage.deviceAuthentication.keyPair())
        phoneStorage.lost = true

        phone.prepareLastDeviceRecovery()
        val old = assertFailsWith<SecureMessageTransportException.LastDeviceRecoveryRejected> { phone.completeLastDeviceRecovery(r1) }
        assertEquals(LastDeviceRecoveryFailure.INVALID_PROOF, old.reason, "the rotated-out key recovers nothing")
        assertContentEquals(lost.publicKey, network.server.devices.registration(ALICE)?.publicKey)

        phone.completeLastDeviceRecovery(r2)
        assertEquals(2, network.server.devices.registrationState(ALICE)?.authEpoch)
        phone.initialize()
        assertActive(r2, epoch = 2)
    }

    @Test
    fun revocationStopsLastDeviceRecovery() = runTest {
        setUp()
        laptopClient.revokeLastDeviceRecoveryKey(r1)
        phoneStorage.lost = true
        phone.prepareLastDeviceRecovery()
        val failure = assertFailsWith<SecureMessageTransportException.LastDeviceRecoveryRejected> { phone.completeLastDeviceRecovery(r1) }
        assertEquals(LastDeviceRecoveryFailure.NOT_CONFIGURED, failure.reason)
        assertEquals(1, network.server.devices.registrationState(ALICE)?.authEpoch)
    }

    @Test
    fun aDeviceWithoutItsAuthenticationKeyCannotChangeTheRecoveryKey() = runTest {
        setUp()
        phoneStorage.lost = true
        assertFailsWith<SecureMessageClientException.NotInitialized> { phone.rotateLastDeviceRecoveryKey(r1, r2) }
        assertFailsWith<SecureMessageClientException.NotInitialized> { phone.revokeLastDeviceRecoveryKey(r1) }
        assertEquals(0, network.recoveryKeyTransitionAttempts.size)
        assertActive(r1, epoch = 1)
    }

    @Test
    fun aTransitionThatLosesTheRaceIsReported() = runTest {
        setUp()
        // Between the phone's status read and its submission, the laptop rotates R1 -> R2.
        var interfere = true
        network.beforeRecoveryKeyTransition = {
            if (interfere) {
                interfere = false
                assertEquals(LastDeviceRecoveryKeyRotationResult.ROTATED, laptopClient.rotateLastDeviceRecoveryKey(r1, r2))
            }
        }
        val rotation = assertFailsWith<SecureMessageTransportException.RecoveryKeyRotationRejected> { phone.rotateLastDeviceRecoveryKey(r1, r3) }
        assertEquals(RecoveryKeyTransitionFailure.CONFLICT, rotation.reason)
        assertActive(r2, epoch = 2)

        interfere = true
        network.beforeRecoveryKeyTransition = {
            if (interfere) {
                interfere = false
                assertEquals(LastDeviceRecoveryKeyRotationResult.ROTATED, laptopClient.rotateLastDeviceRecoveryKey(r2, r3))
            }
        }
        val revocation = assertFailsWith<SecureMessageTransportException.RecoveryKeyRevocationRejected> { phone.revokeLastDeviceRecoveryKey(r2) }
        assertEquals(RecoveryKeyTransitionFailure.CONFLICT, revocation.reason)
        assertActive(r3, epoch = 3)

        // A concurrent identical revocation (the other device revoked the same key first) is reported as already revoked.
        interfere = true
        network.beforeRecoveryKeyTransition = {
            if (interfere) {
                interfere = false
                assertEquals(LastDeviceRecoveryKeyRevocationResult.REVOKED, laptopClient.revokeLastDeviceRecoveryKey(r3))
            }
        }
        assertEquals(LastDeviceRecoveryKeyRevocationResult.ALREADY_REVOKED, phone.revokeLastDeviceRecoveryKey(r3))
    }

    /**
     * Client storage whose active device authentication key can be hidden,
     * like an installation that lost it: [lost] makes
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
