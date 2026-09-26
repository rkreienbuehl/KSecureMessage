package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage
import dev.kreienbuehl.ksecuremessage.storage.client.inmemory.InMemoryClientStorage
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.milliseconds

private val LAPTOP = DeviceAddress(UserId("alice"), DeviceId("laptop"))

/**
 * Device authentication rotation policy on the client
 * (docs/device-authentication-rotation.md): the key's age comes from the
 * server's installation time (read with a signed request, never stored
 * locally) and the client's clock; evaluation never rotates; rotate-if-needed
 * reuses the routine rotation and never starts a competing transition.
 *
 * The server ([ServerBackedNetwork]) and the clients have separate manual
 * clocks, so a test can tell whose time is used. Every network call checks
 * that no storage transaction is open.
 */
class DeviceAuthenticationRotationPolicyClientTest {
    private val engine = KodiumProtocolEngine()
    private val serverClock = ManualClock()
    private val clientClock = ManualClock(serverClock.now)
    private val t0 = serverClock.now
    private val policy = DeviceAuthenticationRotationPolicy(30.days)

    private val phoneStorage = InMemoryClientStorage()
    private val tracking = TransactionTrackingStorage(phoneStorage)

    private val network = ServerBackedNetwork(serverClock) {
        assertEquals(0, tracking.depth, "network call inside a storage transaction")
    }

    private fun client(address: DeviceAddress, storage: ClientStorage) =
        SecureMessageClient(address, storage, engine, network, PreKeyConfiguration(oneTimePreKeyTarget = 3), clientClock)

    private val phone get() = client(ALICE, tracking) // a new instance each time, like an application restart
    private val laptop = client(LAPTOP, InMemoryClientStorage())
    private val bob = client(BOB, InMemoryClientStorage())

    /** Phone, laptop and Bob registered with prekeys at [t0] (server time). */
    private suspend fun setUp() {
        for (device in listOf(phone, laptop, bob)) {
            device.initialize()
            device.registerDevice()
            device.publishPreKeys()
        }
    }

    private suspend fun registered() = assertNotNull(network.server.devices.registrationState(ALICE))

    /** Sets both clocks, as if client and server agreed on the time. */
    private fun at(time: kotlin.time.Instant) {
        serverClock.now = time
        clientClock.now = time
    }

    @Test
    fun dueFromTheMaximumAgeRotatesOnceAndTheNewKeyIsYoung() = runTest {
        setUp()
        at(t0 + 29.days)
        val notYet = assertIs<DeviceAuthenticationRotationDecision.NotNeeded>(phone.evaluateDeviceAuthenticationRotation(policy))
        assertEquals(1, notYet.status.authEpoch)
        assertEquals(t0, notYet.status.authKeyInstalledAt)
        assertEquals(29.days, notYet.status.age)
        assertIs<DeviceAuthenticationRotationResult.NotNeeded>(phone.rotateDeviceAuthenticationKeyIfNeeded(policy))
        assertTrue(network.rotationAttempts.isEmpty())

        at(t0 + 30.days)
        val due = assertIs<DeviceAuthenticationRotationDecision.Due>(phone.evaluateDeviceAuthenticationRotation(policy))
        assertEquals(30.days, due.status.age, "exactly at the boundary")
        // Evaluation never rotates and never creates a key.
        assertEquals(1, registered().authEpoch)
        assertNull(phoneStorage.deviceAuthentication.pendingRotationKeyPair())
        assertTrue(network.rotationAttempts.isEmpty())

        val k1 = assertNotNull(phoneStorage.deviceAuthentication.keyPair())
        val rotated = assertIs<DeviceAuthenticationRotationResult.Rotated>(phone.rotateDeviceAuthenticationKeyIfNeeded(policy))
        assertEquals(1, rotated.previous.authEpoch)
        assertEquals(30.days, rotated.previous.age)
        assertEquals(2, registered().authEpoch)
        assertEquals(t0 + 30.days, registered().authKeyInstalledAt)
        val k2 = assertNotNull(phoneStorage.deviceAuthentication.keyPair())
        assertContentEquals(k2.publicKey, registered().registration.publicKey)
        assertTrue(!k1.publicKey.contentEquals(k2.publicKey))

        // The new key's age starts at the rotation: immediately not due again.
        val after = assertIs<DeviceAuthenticationRotationDecision.NotNeeded>(phone.evaluateDeviceAuthenticationRotation(policy))
        assertEquals(2, after.status.authEpoch)
        assertEquals(Duration.ZERO, after.status.age)
        assertIs<DeviceAuthenticationRotationResult.NotNeeded>(phone.rotateDeviceAuthenticationKeyIfNeeded(policy))
        assertEquals(1, network.rotationAttempts.size)
        phone.receive() // K2 signs
    }

    @Test
    fun ageUsesTheServerInstallationTimeAndTheClientClock() = runTest {
        // The client clock runs 5 days ahead of the server's.
        clientClock.now = t0 + 5.days
        setUp()
        val status = phone.deviceAuthenticationRotationStatus()
        assertEquals(t0, status.authKeyInstalledAt, "the server's time, not the client's")
        assertEquals(t0 + 5.days, status.evaluatedAt)
        assertEquals(5.days, status.age)
        assertEquals(1, status.authEpoch)
        assertEquals(false, status.pendingRotation)
        assertEquals(false, status.pendingRecovery)

        // A restarted client (new instance, same storage) reads the same authoritative time.
        clientClock.advanceBy(1.days)
        val restarted = phone.deviceAuthenticationRotationStatus()
        assertEquals(t0, restarted.authKeyInstalledAt)
        assertEquals(6.days, restarted.age)
    }

    @Test
    fun theServerIsAskedOnEveryEvaluation() = runTest {
        setUp()
        at(t0 + 10.days)
        val before = network.registrationStatusRequests
        repeat(3) { phone.evaluateDeviceAuthenticationRotation(policy) }
        assertEquals(before + 3, network.registrationStatusRequests, "no caching")

        // The server's time moves when the key changes elsewhere; the client follows without local state.
        phone.rotateDeviceAuthenticationKey()
        assertEquals(t0 + 10.days, phone.deviceAuthenticationRotationStatus().authKeyInstalledAt)
    }

    @Test
    fun aClientClockBehindTheInstallationTimeNeverMakesTheKeyDue() = runTest {
        setUp()
        at(t0 + 60.days)
        phone.rotateDeviceAuthenticationKey() // installed at t0 + 60d (server time)
        clientClock.now = t0 // the client clock moves back
        val decision = assertIs<DeviceAuthenticationRotationDecision.NotNeeded>(
            phone.evaluateDeviceAuthenticationRotation(DeviceAuthenticationRotationPolicy(1.milliseconds)),
        )
        assertEquals(Duration.ZERO, decision.status.age, "clamped, not -60 days")
        assertIs<DeviceAuthenticationRotationResult.NotNeeded>(phone.rotateDeviceAuthenticationKeyIfNeeded(DeviceAuthenticationRotationPolicy(1.milliseconds)))
        assertEquals(2, registered().authEpoch)
    }

    @Test
    fun aClientClockJumpingForwardMayMakeTheKeyDue() = runTest {
        setUp()
        clientClock.advanceBy(400.days) // wall-clock policy: accepted, a routine rotation is safe
        assertIs<DeviceAuthenticationRotationResult.Rotated>(phone.rotateDeviceAuthenticationKeyIfNeeded(policy))
        assertEquals(2, registered().authEpoch)
        assertEquals(t0, registered().authKeyInstalledAt, "installed at the server's time")
    }

    @Test
    fun infinitePolicyNeverRotates() = runTest {
        setUp()
        at(t0 + 10_000.days)
        val never = DeviceAuthenticationRotationPolicy(Duration.INFINITE)
        assertIs<DeviceAuthenticationRotationDecision.NotNeeded>(phone.evaluateDeviceAuthenticationRotation(never))
        assertIs<DeviceAuthenticationRotationResult.NotNeeded>(phone.rotateDeviceAuthenticationKeyIfNeeded(never))
        assertEquals(1, registered().authEpoch)
    }

    @Test
    fun recoveryResetsTheAgeAndBlocksRoutineRotationWhilePending() = runTest {
        setUp()
        at(t0 + 100.days)
        assertIs<DeviceAuthenticationRotationDecision.Due>(phone.evaluateDeviceAuthenticationRotation(policy))

        val request = phone.prepareDeviceAuthenticationRecovery(LAPTOP)
        val calls = network.registrationStatusRequests
        assertEquals(DeviceAuthenticationRotationDecision.RecoveryPending, phone.evaluateDeviceAuthenticationRotation(policy))
        assertEquals(DeviceAuthenticationRotationResult.RecoveryInProgress, phone.rotateDeviceAuthenticationKeyIfNeeded(policy))
        assertEquals(calls, network.registrationStatusRequests, "decided locally")
        assertNull(phoneStorage.deviceAuthentication.pendingRotationKeyPair(), "no competing transition")
        assertTrue(network.rotationAttempts.isEmpty())

        // The recovery's response is lost; the registration probe resolves it later without refreshing the time.
        network.afterRecovery = {
            network.afterRecovery = {}
            throw SecureMessageTransportException.UnexpectedResponse(504)
        }
        val authorization = laptop.authorizeDeviceRecovery(request)
        assertFailsWith<SecureMessageTransportException.UnexpectedResponse> { phone.completeDeviceAuthenticationRecovery(authorization) }
        assertEquals(t0 + 100.days, registered().authKeyInstalledAt, "the recovered key's age starts at the recovery")
        at(t0 + 101.days)
        assertTrue(phone.resolveDeviceAuthenticationRecovery())
        assertEquals(t0 + 100.days, registered().authKeyInstalledAt, "the probe did not refresh it")

        val status = assertIs<DeviceAuthenticationRotationDecision.NotNeeded>(phone.evaluateDeviceAuthenticationRotation(policy)).status
        assertEquals(2, status.authEpoch)
        assertEquals(1.days, status.age, "not the 101 days of the lost key")
    }

    @Test
    fun pendingRotationIsResumedWithItsExistingKeyWhateverThePolicySays() = runTest {
        setUp()
        at(t0 + 1.days)
        phone.prepareDeviceAuthenticationRotation()
        val k2 = assertNotNull(phoneStorage.deviceAuthentication.pendingRotationKeyPair())
        val calls = network.registrationStatusRequests
        assertEquals(DeviceAuthenticationRotationDecision.RotationPending, phone.evaluateDeviceAuthenticationRotation(policy))
        assertEquals(calls, network.registrationStatusRequests, "decided locally")
        assertTrue(phone.deviceAuthenticationRotationStatus().pendingRotation)

        val never = DeviceAuthenticationRotationPolicy(Duration.INFINITE)
        assertEquals(DeviceAuthenticationRotationResult.ResumedPendingRotation, phone.rotateDeviceAuthenticationKeyIfNeeded(never))
        assertContentEquals(k2.publicKey, registered().registration.publicKey, "the prepared key, no second one")
        assertContentEquals(k2.privateKey, assertNotNull(phoneStorage.deviceAuthentication.keyPair()).privateKey)
        assertNull(phoneStorage.deviceAuthentication.pendingRotationKeyPair())
        assertEquals(2, registered().authEpoch)
        assertEquals(1, network.rotationAttempts.size)
    }

    @Test
    fun lostRotationResponseIsResolvedWithoutRefreshingTheTime() = runTest {
        setUp()
        val t1 = t0 + 30.days
        at(t1)
        network.afterRotation = {
            network.afterRotation = {}
            throw SecureMessageTransportException.UnexpectedResponse(504)
        }
        assertFailsWith<SecureMessageTransportException.UnexpectedResponse> { phone.rotateDeviceAuthenticationKeyIfNeeded(policy) }
        assertEquals(t1, registered().authKeyInstalledAt)
        assertNotNull(phoneStorage.deviceAuthentication.pendingRotationKeyPair())

        // Later: K1 is rejected for the status read, the K2 registration probe resolves it.
        at(t1 + 10.days)
        assertEquals(DeviceAuthenticationRotationResult.ResumedPendingRotation, phone.rotateDeviceAuthenticationKeyIfNeeded(policy))
        assertEquals(t1, registered().authKeyInstalledAt, "the probe is a registration retry")
        assertEquals(2, registered().authEpoch)
        assertEquals(1, network.rotationAttempts.size, "no second transition")
        val status = phone.deviceAuthenticationRotationStatus()
        assertEquals(10.days, status.age)
        assertEquals(false, status.pendingRotation)
    }

    @Test
    fun nothingEvaluatesOrRotatesImplicitly() = runTest {
        setUp()
        val statusReads = network.registrationStatusRequests
        repeat(3) {
            at(serverClock.now + 400.days)
            val phone = phone
            phone.initialize()
            phone.registerDevice()
            phone.publishPreKeys()
            bob.send(ALICE, "hi".encodeToByteArray())
            phone.decrypt(phone.receive().single())
            phone.send(BOB, "hello".encodeToByteArray())
        }
        assertEquals(1, registered().authEpoch)
        assertEquals(t0, registered().authKeyInstalledAt)
        assertNull(phoneStorage.deviceAuthentication.pendingRotationKeyPair())
        assertTrue(network.rotationAttempts.isEmpty())
        assertEquals(statusReads, network.registrationStatusRequests, "no hidden status reads either")
    }

    @Test
    fun concurrentCallsOnOneInstanceRotateOnce() = runTest {
        setUp()
        at(t0 + 30.days)
        val phone = phone
        val results = List(4) { async { phone.rotateDeviceAuthenticationKeyIfNeeded(policy) } }.awaitAll()
        assertEquals(1, results.count { it is DeviceAuthenticationRotationResult.Rotated })
        assertEquals(3, results.count { it is DeviceAuthenticationRotationResult.NotNeeded })
        assertEquals(2, registered().authEpoch)
        assertEquals(1, network.rotationAttempts.size)
        assertNull(phoneStorage.deviceAuthentication.pendingRotationKeyPair())
        assertContentEquals(assertNotNull(phoneStorage.deviceAuthentication.keyPair()).publicKey, registered().registration.publicKey)
    }

    @Test
    fun anotherInstanceOnSharedStorageCompletesTheRotationWhileTheResponseIsPending() = runTest {
        setUp()
        at(t0 + 30.days)
        val first = phone
        val second = phone
        var secondResult: DeviceAuthenticationRotationResult? = null
        network.whileRotationResponsePending = {
            network.whileRotationResponsePending = {}
            // The server installed K2; the first instance has not promoted it yet.
            secondResult = second.rotateDeviceAuthenticationKeyIfNeeded(policy)
        }
        assertIs<DeviceAuthenticationRotationResult.Rotated>(first.rotateDeviceAuthenticationKeyIfNeeded(policy))
        // The second found the shared pending key, resolved it with the registration probe and promoted it;
        // the first then found exactly the key it submitted already active.
        assertEquals(DeviceAuthenticationRotationResult.ResumedPendingRotation, secondResult)
        assertEquals(2, registered().authEpoch)
        assertEquals(1, network.rotationAttempts.size)
        assertNull(phoneStorage.deviceAuthentication.pendingRotationKeyPair())
        assertContentEquals(assertNotNull(phoneStorage.deviceAuthentication.keyPair()).publicKey, registered().registration.publicKey)
        assertIs<DeviceAuthenticationRotationDecision.NotNeeded>(first.evaluateDeviceAuthenticationRotation(policy))
    }

    @Test
    fun concurrentInstancesOnSharedStorageConverge() = runTest {
        setUp()
        at(t0 + 30.days)
        val first = phone
        val second = phone
        val outcomes = listOf(first, second).map { client ->
            async { runCatching { client.rotateDeviceAuthenticationKeyIfNeeded(policy) } }
        }.awaitAll()
        // Storage allows one pending key, the server's compare-and-set one rotation.
        assertEquals(2, registered().authEpoch, "exactly one rotation")
        assertNull(phoneStorage.deviceAuthentication.pendingRotationKeyPair())
        assertContentEquals(assertNotNull(phoneStorage.deviceAuthentication.keyPair()).publicKey, registered().registration.publicKey)
        assertTrue(outcomes.any { it.getOrNull() is DeviceAuthenticationRotationResult.Rotated || it.getOrNull() == DeviceAuthenticationRotationResult.ResumedPendingRotation })
        for (outcome in outcomes) {
            outcome.exceptionOrNull()?.let { throw AssertionError("a stale instance must resynchronize, not fail", it) }
        }
        assertIs<DeviceAuthenticationRotationDecision.NotNeeded>(phone.evaluateDeviceAuthenticationRotation(policy))
    }
}
