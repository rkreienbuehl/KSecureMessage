package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException.LastDeviceRecoveryFailure
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException.RecoveryKeyResetFailure
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.LastDeviceRecoveryKeyStatus
import dev.kreienbuehl.ksecuremessage.model.RecoveryKeyResetStatus
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
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.milliseconds

/**
 * Delayed recovery key reset on the client (docs/recovery-key-reset.md),
 * against [ServerBackedNetwork] (server checks, a 3-day policy delay and the
 * atomic storage transitions): request, visibility to every device, the
 * eligibility boundary, completion with a backed-up key, cancellation by a
 * device and by the offline key without any device, lost responses, the
 * effect on last-device recovery, and no change to messaging or device
 * authentication state.
 */
class RecoveryKeyResetTest {
    private val engine = KodiumProtocolEngine()
    private val clock = ManualClock()
    private lateinit var tracking: TransactionTrackingStorage
    private val network = ServerBackedNetwork(clock) {
        if (::tracking.isInitialized) assertEquals(0, tracking.depth, "network call inside a storage transaction")
    }
    private val delay = 3.days

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

    private lateinit var r1: LastDeviceRecoveryKey
    private lateinit var r2: LastDeviceRecoveryKey
    private lateinit var r3: LastDeviceRecoveryKey

    /** Phone, laptop and Bob registered; the phone and Bob talked; the phone registered R1. */
    private suspend fun setUp() {
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
        phone.registerLastDeviceRecoveryKey(r1)
    }

    private suspend fun assertActive(key: LastDeviceRecoveryKey, epoch: Long) {
        val status = assertIs<LastDeviceRecoveryKeyStatus.Active>(laptopClient.lastDeviceRecoveryKeyStatus())
        assertEquals(epoch, status.epoch)
        assertTrue(status.isKey(key.publicKey))
    }

    @Test
    fun aLostKeyIsResetAfterTheDelayAndNothingElseChanges() = runTest {
        setUp()
        val identity = assertNotNull(phoneStorage.identity.identity())
        val deviceKey = assertNotNull(phoneStorage.deviceAuthentication.keyPair())
        val session = assertNotNull(phoneStorage.sessions.load(BOB)).state
        val oneTimePreKeys = phoneStorage.preKeys.publicOneTimePreKeys().map { it.id }
        val safetyNumber = phone.safetyNumber(BOB)
        phone.markRemoteIdentityVerified(safetyNumber)
        val registration = assertNotNull(network.server.devices.registrationState(ALICE))
        val laptopRegistration = assertNotNull(network.server.devices.registrationState(laptop))

        // R1 is lost. The laptop requests a reset; every device of the user sees it.
        assertSame(RecoveryKeyResetStatus.None, phone.lastDeviceRecoveryKeyResetStatus())
        val reset = laptopClient.requestLastDeviceRecoveryKeyReset()
        assertEquals(laptop, reset.requestedBy)
        assertEquals(clock.now + delay, reset.eligibleAt)
        assertEquals(1, reset.recoveryKeyEpoch)
        assertTrue(reset.recoveryPublicKey.contentEquals(r1.publicKey))
        assertEquals(reset, phone.lastDeviceRecoveryKeyResetStatus())
        assertSame(RecoveryKeyResetStatus.None, bob.lastDeviceRecoveryKeyResetStatus(), "another user sees nothing")

        // Before the eligibility time the server refuses; nothing changes.
        clock.now = reset.eligibleAt - 1.milliseconds
        val early = assertFailsWith<SecureMessageTransportException.RecoveryKeyResetRejected> { phone.completeLastDeviceRecoveryKeyReset(r2) }
        assertEquals(RecoveryKeyResetFailure.NOT_YET_ELIGIBLE, early.reason)
        assertActive(r1, epoch = 1)

        // From the eligibility time on, any device of the user (not only the requester) completes it with a new, backed-up key.
        clock.now = reset.eligibleAt
        assertEquals(LastDeviceRecoveryKeyResetResult.COMPLETED, phone.completeLastDeviceRecoveryKeyReset(r2))
        assertActive(r2, epoch = 2)
        assertEquals(clock.now, assertIs<LastDeviceRecoveryKeyStatus.Active>(phone.lastDeviceRecoveryKeyStatus()).installedAt)
        assertSame(RecoveryKeyResetStatus.None, phone.lastDeviceRecoveryKeyResetStatus())

        // Messaging identity, pins, verification, safety number, sessions, prekeys and device authentication stay.
        assertContentEquals(identity.privateKey, phoneStorage.identity.identity()?.privateKey)
        assertContentEquals(deviceKey.privateKey, phoneStorage.deviceAuthentication.keyPair()?.privateKey)
        assertContentEquals(session, phoneStorage.sessions.load(BOB)?.state)
        assertEquals(oneTimePreKeys, phoneStorage.preKeys.publicOneTimePreKeys().map { it.id })
        assertEquals(VerificationState.VERIFIED, phone.remoteIdentityTrust(BOB)?.verification)
        assertEquals(safetyNumber, phone.safetyNumber(BOB))
        for ((address, before) in listOf(ALICE to registration, laptop to laptopRegistration)) {
            val after = assertNotNull(network.server.devices.registrationState(address))
            assertContentEquals(before.registration.publicKey, after.registration.publicKey)
            assertEquals(before.authEpoch, after.authEpoch)
            assertEquals(before.authKeyInstalledAt, after.authKeyInstalledAt)
        }
        assertTrue(phone.pendingMessages(limit = 100, recipient = BOB).messages.isEmpty())
        assertEquals(0, phone.pendingReceivedMessageCount())
        bob.send(ALICE, "still here".encodeToByteArray())
        assertEquals("still here", phone.accept(phone.receive().single()).decodeToString())
    }

    @Test
    fun aRepeatedRequestReturnsTheSameResetAndLostResponsesResolve() = runTest {
        setUp()
        var loseResponse = true
        network.afterRecoveryKeyReset = { kind ->
            if (kind == "request" && loseResponse) {
                loseResponse = false
                throw SecureMessageTransportException.UnexpectedResponse(504)
            }
        }
        assertFailsWith<SecureMessageTransportException.UnexpectedResponse> { phone.requestLastDeviceRecoveryKeyReset() }
        // The status recovers it; a new request (after a restart, a day later) returns the same reset.
        val pending = assertIs<RecoveryKeyResetStatus.Pending>(phone.lastDeviceRecoveryKeyResetStatus())
        clock.advanceBy(1.days)
        assertEquals(pending, phone.requestLastDeviceRecoveryKeyReset())
        assertEquals(pending, laptopClient.requestLastDeviceRecoveryKeyReset(), "another device does not restart it either")

        // A lost completion response: calling again finds the new key active and sends nothing.
        clock.now = pending.eligibleAt
        loseResponse = true
        network.afterRecoveryKeyReset = { kind ->
            if (kind == "completion" && loseResponse) {
                loseResponse = false
                throw SecureMessageTransportException.UnexpectedResponse(504)
            }
        }
        assertFailsWith<SecureMessageTransportException.UnexpectedResponse> { phone.completeLastDeviceRecoveryKeyReset(r2) }
        assertActive(r2, epoch = 2)
        val attempts = network.recoveryKeyResetAttempts.size
        assertEquals(LastDeviceRecoveryKeyResetResult.ALREADY_ACTIVE, phone.completeLastDeviceRecoveryKeyReset(r2))
        assertEquals(attempts, network.recoveryKeyResetAttempts.size)
        assertActive(r2, epoch = 2)
    }

    @Test
    fun aLostCancellationResponseIsResolvedByTheStatus() = runTest {
        setUp()
        val reset = phone.requestLastDeviceRecoveryKeyReset()
        network.afterRecoveryKeyReset = { kind -> if (kind == "cancellation") throw SecureMessageTransportException.UnexpectedResponse(504) }
        assertFailsWith<SecureMessageTransportException.UnexpectedResponse> { laptopClient.cancelLastDeviceRecoveryKeyReset(reset) }
        network.afterRecoveryKeyReset = {}
        val again = assertIs<LastDeviceRecoveryKeyResetCancellationResult.NotPending>(laptopClient.cancelLastDeviceRecoveryKeyReset(reset))
        assertSame(RecoveryKeyResetStatus.None, again.currentReset)
        val status = assertIs<LastDeviceRecoveryKeyStatus.Active>(again.recoveryKeyStatus)
        assertEquals(1, status.epoch, "same key and epoch: the cancellation took effect")
        assertTrue(status.isKey(r1.publicKey))
    }

    @Test
    fun aCompletionThatWonIsVisibleToALateCanceller() = runTest {
        setUp()
        val reset = phone.requestLastDeviceRecoveryKeyReset()
        clock.now = reset.eligibleAt
        laptopClient.completeLastDeviceRecoveryKeyReset(r2)
        val late = assertIs<LastDeviceRecoveryKeyResetCancellationResult.NotPending>(phone.cancelLastDeviceRecoveryKeyReset(reset))
        assertTrue(assertIs<LastDeviceRecoveryKeyStatus.Active>(late.recoveryKeyStatus).isKey(r2.publicKey), "the completion won")
        // The offline key R1 can neither cancel nor roll anything back any more.
        val offline = assertIs<LastDeviceRecoveryKeyResetCancellationResult.NotPending>(phone.cancelLastDeviceRecoveryKeyReset(r1, reset))
        assertNull(offline.currentReset, "R1 is no longer the active key")
        assertActive(r2, epoch = 2)
    }

    @Test
    fun theOfflineKeySeesAndCancelsAResetWithoutAnyDevice() = runTest {
        setUp()
        // A compromised laptop requests a reset; the legitimate owner still holds R1 but has lost the phone's key.
        val reset = laptopClient.requestLastDeviceRecoveryKeyReset()
        phoneStorage.lost = true
        assertFailsWith<SecureMessageClientException.NotInitialized> { phone.lastDeviceRecoveryKeyResetStatus() }
        val attempts = network.recoveryKeyResetAttempts.size

        assertEquals(reset, phone.lastDeviceRecoveryKeyResetStatus(r1))
        val wrongKey = assertFailsWith<SecureMessageTransportException.RecoveryKeyResetRejected> { phone.lastDeviceRecoveryKeyResetStatus(r2) }
        assertEquals(RecoveryKeyResetFailure.INVALID_PROOF, wrongKey.reason)
        assertFailsWith<IllegalArgumentException> { phone.cancelLastDeviceRecoveryKeyReset(r2, reset) }

        assertSame(LastDeviceRecoveryKeyResetCancellationResult.Cancelled, phone.cancelLastDeviceRecoveryKeyReset(r1, reset))
        assertEquals(attempts + 1, network.recoveryKeyResetAttempts.size)
        assertSame(RecoveryKeyResetStatus.None, phone.lastDeviceRecoveryKeyResetStatus(r1))
        assertActive(r1, epoch = 1)
        // Retrying is harmless and recreates nothing.
        val again = assertIs<LastDeviceRecoveryKeyResetCancellationResult.NotPending>(phone.cancelLastDeviceRecoveryKeyReset(r1, reset))
        assertSame(RecoveryKeyResetStatus.None, again.currentReset)
        assertNull(again.recoveryKeyStatus)
        clock.now = reset.eligibleAt
        val completion = assertFailsWith<SecureMessageClientException.LastDeviceRecoveryKeyResetNotPending> { laptopClient.completeLastDeviceRecoveryKeyReset(r3) }
        assertNotNull(completion.message)
        assertActive(r1, epoch = 1)
    }

    @Test
    fun theCurrentKeyStaysAuthoritativeDuringTheDelayAndTheNewOneAfter() = runTest {
        setUp()
        val reset = laptopClient.requestLastDeviceRecoveryKeyReset()
        // During the delay R1 still recovers a device.
        phoneStorage.lost = true
        phone.prepareLastDeviceRecovery()
        phone.completeLastDeviceRecovery(r1)
        assertEquals(2, network.server.devices.registrationState(ALICE)?.authEpoch)
        phone.initialize()
        assertEquals(reset, phone.lastDeviceRecoveryKeyResetStatus(), "a device recovery does not touch the reset")

        clock.now = reset.eligibleAt
        assertEquals(LastDeviceRecoveryKeyResetResult.COMPLETED, phone.completeLastDeviceRecoveryKeyReset(r2))
        phoneStorage.lost = true
        phone.prepareLastDeviceRecovery()
        val old = assertFailsWith<SecureMessageTransportException.LastDeviceRecoveryRejected> { phone.completeLastDeviceRecovery(r1) }
        assertEquals(LastDeviceRecoveryFailure.INVALID_PROOF, old.reason, "the reset-out key recovers nothing")
        phone.completeLastDeviceRecovery(r2)
        assertEquals(3, network.server.devices.registrationState(ALICE)?.authEpoch)
    }

    @Test
    fun aRotationWithTheRecoveredKeyWinsOverAPendingReset() = runTest {
        setUp()
        val reset = phone.requestLastDeviceRecoveryKeyReset()
        // R1 turns up again: the normal rotation is preferred and removes the reset.
        assertEquals(LastDeviceRecoveryKeyRotationResult.ROTATED, laptopClient.rotateLastDeviceRecoveryKey(r1, r3))
        assertSame(RecoveryKeyResetStatus.None, phone.lastDeviceRecoveryKeyResetStatus())
        clock.now = reset.eligibleAt
        assertFailsWith<SecureMessageClientException.LastDeviceRecoveryKeyResetNotPending> { phone.completeLastDeviceRecoveryKeyReset(r2) }
        assertActive(r3, epoch = 2)
    }

    @Test
    fun aCompletionThatLosesToAnIdenticalOneIsReportedAsCompleted() = runTest {
        setUp()
        val reset = phone.requestLastDeviceRecoveryKeyReset()
        clock.now = reset.eligibleAt
        var interfere = true
        network.beforeRecoveryKeyResetCompletion = {
            if (interfere) {
                interfere = false
                assertEquals(LastDeviceRecoveryKeyResetResult.COMPLETED, laptopClient.completeLastDeviceRecoveryKeyReset(r2))
            }
        }
        assertEquals(LastDeviceRecoveryKeyResetResult.COMPLETED, phone.completeLastDeviceRecoveryKeyReset(r2))
        assertActive(r2, epoch = 2)

        // A competing completion with another key is reported as the server's refusal.
        val next = phone.requestLastDeviceRecoveryKeyReset()
        clock.now = next.eligibleAt
        interfere = true
        network.beforeRecoveryKeyResetCompletion = {
            if (interfere) {
                interfere = false
                laptopClient.completeLastDeviceRecoveryKeyReset(r3)
            }
        }
        val lost = assertFailsWith<SecureMessageTransportException.RecoveryKeyResetRejected> { phone.completeLastDeviceRecoveryKeyReset(r1) }
        assertEquals(RecoveryKeyResetFailure.NOT_PENDING, lost.reason)
        assertActive(r3, epoch = 3)
    }

    @Test
    fun localRefusalsSendNothing() = runTest {
        setUp()
        assertFailsWith<SecureMessageClientException.LastDeviceRecoveryKeyResetNotPending> { phone.completeLastDeviceRecoveryKeyReset(r2) }
        val reset = phone.requestLastDeviceRecoveryKeyReset()
        clock.now = reset.eligibleAt
        val attempts = network.recoveryKeyResetAttempts.size
        assertFailsWith<IllegalArgumentException> { phone.completeLastDeviceRecoveryKeyReset(r1) }
        assertEquals(attempts, network.recoveryKeyResetAttempts.size)
        assertFailsWith<SecureMessageClientException.LastDeviceRecoveryKeyNotConfigured> { bob.completeLastDeviceRecoveryKeyReset(r2) }
        assertFailsWith<IllegalArgumentException> { bob.cancelLastDeviceRecoveryKeyReset(reset) }
        // A device without its authentication key cannot request, read, complete or cancel as a device.
        phoneStorage.lost = true
        assertFailsWith<SecureMessageClientException.NotInitialized> { phone.requestLastDeviceRecoveryKeyReset() }
        assertFailsWith<SecureMessageClientException.NotInitialized> { phone.completeLastDeviceRecoveryKeyReset(r2) }
        assertFailsWith<SecureMessageClientException.NotInitialized> { phone.cancelLastDeviceRecoveryKeyReset(reset) }
        assertEquals(attempts, network.recoveryKeyResetAttempts.size)
    }

    @Test
    fun withoutAServerPolicyResetsAreNotAvailable() = runTest {
        setUp()
        network.recoveryKeyResetDelay = null
        val failure = assertFailsWith<SecureMessageTransportException.RecoveryKeyResetRejected> { phone.requestLastDeviceRecoveryKeyReset() }
        assertEquals(RecoveryKeyResetFailure.NOT_AVAILABLE, failure.reason)
        assertSame(RecoveryKeyResetStatus.None, phone.lastDeviceRecoveryKeyResetStatus())
        clock.advanceBy(10.hours)
        assertActive(r1, epoch = 1)
    }

    /** Client storage whose active device authentication key can be hidden (see RecoveryKeyLifecycleTest). */
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
