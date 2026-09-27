package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.client.DeviceAuthenticationHealthInconsistency.MULTIPLE_PENDING_TRANSITIONS
import dev.kreienbuehl.ksecuremessage.client.DeviceAuthenticationHealthInconsistency.ROTATION_PENDING_WITHOUT_ACTIVE_KEY
import dev.kreienbuehl.ksecuremessage.client.DeviceAuthenticationRecoveryKind.DEVICE_RECOVERY
import dev.kreienbuehl.ksecuremessage.client.DeviceAuthenticationRecoveryKind.LAST_DEVICE_RECOVERY
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException.AuthenticationFailure
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceAuthenticationRegistrationStatus
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.DeviceRegistration
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.LastDeviceRecoveryKeyStatus
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication
import dev.kreienbuehl.ksecuremessage.model.RecoveryKeyResetId
import dev.kreienbuehl.ksecuremessage.model.RecoveryKeyResetStatus
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationRotationAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecoveryAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryChallenge
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryKey
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryKeyRegistration
import dev.kreienbuehl.ksecuremessage.protocol.LocalIdentity
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyResetCancellationAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyResetCompletionAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyResetStatusQuery
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRevocationAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRotationAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.SecureSession
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage
import dev.kreienbuehl.ksecuremessage.storage.DeviceAuthenticationKeyStore
import dev.kreienbuehl.ksecuremessage.storage.IdentityStore
import dev.kreienbuehl.ksecuremessage.storage.SessionStore
import dev.kreienbuehl.ksecuremessage.storage.client.inmemory.InMemoryClientStorage
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
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
import kotlin.test.fail
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.milliseconds

private val LAPTOP = DeviceAddress(UserId("alice"), DeviceId("laptop"))

/**
 * Device authentication health (docs/device-authentication-health.md): the
 * read-only classification of the local key slots and, only when they do not
 * decide, one signed registration status read, against [ServerBackedNetwork].
 * The phone has its own client clock, separate from the server clock. Its
 * transport counts the status reads, can hold one open, can script a failure
 * and can refuse every other request; its storage can lose the active key,
 * pretend to be pre-milestone-12 storage, report an extra pending slot (a
 * state real storage refuses) and refuse every write.
 */
class DeviceAuthenticationHealthTest {
    private val engine = KodiumProtocolEngine()
    private val serverClock = ManualClock()
    private val phoneClock = ManualClock(serverClock.now)
    private val t0 = serverClock.now
    private val policy = DeviceAuthenticationRotationPolicy(30.days)

    private val network = ServerBackedNetwork(serverClock)
    private val phoneNetwork = HealthNetwork(network)
    private val phoneStorage = HealthStorage(InMemoryClientStorage())

    private fun client(address: DeviceAddress, storage: ClientStorage, transport: SecureMessageTransport, clock: ManualClock) =
        SecureMessageClient(address, storage, engine, transport, PreKeyConfiguration(oneTimePreKeyTarget = 3), clock)

    private val phone = client(ALICE, phoneStorage, phoneNetwork, phoneClock)
    private val laptop = client(LAPTOP, InMemoryClientStorage(), network, serverClock)
    private val bob = client(BOB, InMemoryClientStorage(), network, serverClock)

    /** Phone, laptop and Bob initialized; with [register] registered with prekeys at [t0] (server time), and the phone and Bob talked. */
    private suspend fun setUp(register: Boolean = true) {
        for (device in listOf(phone, laptop, bob)) {
            device.initialize()
            if (!register) continue
            device.registerDevice()
            device.publishPreKeys()
        }
        if (register) {
            bob.send(ALICE, "hello".encodeToByteArray())
            assertEquals("hello", phone.accept(phone.receive().single()).decodeToString())
            bob.decrypt(bob.receive().single()) // the ACK
        }
        phoneNetwork.statusReads = 0
    }

    private suspend fun registered() = assertNotNull(network.server.devices.registrationState(ALICE))

    private fun assertReads(expected: Int) = assertEquals(expected, phoneNetwork.statusReads, "registration status reads")

    /** Refuses every write and every request except the registration status read. */
    private fun readOnly() {
        phoneNetwork.onlyStatusReads = true
        phoneStorage.writesBlocked = true
    }

    private fun writable() {
        phoneNetwork.onlyStatusReads = false
        phoneStorage.writesBlocked = false
    }

    // Base states

    @Test
    fun registeredWithoutPolicyIsHealthyWithTheServerMetadata() = runTest {
        setUp()
        phoneClock.now = t0 + 5.days
        readOnly()
        val health = assertIs<DeviceAuthenticationHealth.Healthy>(phone.deviceAuthenticationHealth())
        assertNull(health.policy, "no policy, no age evaluation")
        assertEquals(1, health.status.authEpoch)
        assertEquals(t0, health.status.authKeyInstalledAt)
        assertEquals(phoneClock.now, health.status.evaluatedAt)
        assertEquals(5.days, health.status.age)
        assertFalse(health.status.pendingRotation)
        assertFalse(health.status.pendingRecovery)
        assertReads(1)

        phoneClock.now = t0 + 1000.days
        assertIs<DeviceAuthenticationHealth.Healthy>(phone.deviceAuthenticationHealth(), "no default policy")
        assertReads(2)
    }

    @Test
    fun finitePolicyIsHealthyBeforeAndDueFromTheMaximumAge() = runTest {
        setUp()
        readOnly()
        phoneClock.now = t0 + 30.days - 1.milliseconds
        val before = assertIs<DeviceAuthenticationHealth.Healthy>(phone.deviceAuthenticationHealth(policy))
        assertEquals(policy, before.policy)
        assertReads(1)

        phoneClock.now = t0 + 30.days
        val due = assertIs<DeviceAuthenticationHealth.RotationDue>(phone.deviceAuthenticationHealth(policy))
        assertEquals(policy, due.policy)
        assertEquals(30.days, due.status.age)
        assertEquals(1, due.status.authEpoch)
        assertReads(2)
        assertEquals(1, registered().authEpoch, "nothing rotated")
        assertTrue(network.rotationAttempts.isEmpty())
    }

    @Test
    fun infinitePolicyIsNeverDue() = runTest {
        setUp()
        readOnly()
        phoneClock.now = t0 + 100_000.days
        val never = DeviceAuthenticationRotationPolicy(Duration.INFINITE)
        assertEquals(never, assertIs<DeviceAuthenticationHealth.Healthy>(phone.deviceAuthenticationHealth(never)).policy)
        assertReads(1)
    }

    // Clock

    @Test
    fun aClientClockBehindTheInstallationTimeGivesAgeZero() = runTest {
        setUp()
        readOnly()
        phoneClock.now = t0 - 10.days
        val health = assertIs<DeviceAuthenticationHealth.Healthy>(phone.deviceAuthenticationHealth(DeviceAuthenticationRotationPolicy(1.milliseconds)))
        assertEquals(Duration.ZERO, health.status.age)
        assertEquals(t0 - 10.days, health.status.evaluatedAt)
    }

    @Test
    fun aClientClockJumpingForwardMayMakeTheKeyDue() = runTest {
        setUp()
        readOnly()
        assertIs<DeviceAuthenticationHealth.Healthy>(phone.deviceAuthenticationHealth(policy))
        phoneClock.advanceBy(365.days)
        assertIs<DeviceAuthenticationHealth.RotationDue>(phone.deviceAuthenticationHealth(policy))
        assertEquals(t0, registered().authKeyInstalledAt, "the server time did not move")
    }

    // Freshness

    @Test
    fun everyCallReadsTheServerAgain() = runTest {
        setUp()
        phoneClock.now = t0 + 40.days
        val first = assertIs<DeviceAuthenticationHealth.RotationDue>(phone.deviceAuthenticationHealth(policy))
        assertEquals(1, first.status.authEpoch)

        // The phone rotates (explicitly); the server installs the new key at its own time.
        serverClock.now = t0 + 40.days
        phone.rotateDeviceAuthenticationKey()
        phoneNetwork.statusReads = 0
        readOnly()
        phoneClock.now = t0 + 41.days
        val second = assertIs<DeviceAuthenticationHealth.Healthy>(phone.deviceAuthenticationHealth(policy))
        assertEquals(2, second.status.authEpoch)
        assertEquals(t0 + 40.days, second.status.authKeyInstalledAt)
        assertEquals(1.days, second.status.age)
        assertReads(1)
    }

    // Pending transitions: decided locally

    @Test
    fun pendingDeviceRecoveryIsReportedWithoutAskingTheServer() = runTest {
        setUp()
        phone.prepareDeviceAuthenticationRecovery(LAPTOP)
        val pending = assertNotNull(phoneStorage.deviceAuthentication.pendingRecoveryKeyPair())
        readOnly()
        phoneClock.now = t0 + 400.days
        assertEquals(DeviceAuthenticationHealth.RecoveryPending(DEVICE_RECOVERY), phone.deviceAuthenticationHealth(policy))
        assertReads(0)
        assertContentEquals(pending.publicKey, assertNotNull(phoneStorage.deviceAuthentication.pendingRecoveryKeyPair()).publicKey, "not resolved")
        assertNotNull(phoneStorage.deviceAuthentication.keyPair(), "the active key is untouched")
        assertEquals(1, registered().authEpoch)
    }

    @Test
    fun pendingRecoveryAfterKeyLossIsRecoveryPendingNotActiveKeyMissing() = runTest {
        setUp()
        phoneStorage.lost = true
        phone.prepareDeviceAuthenticationRecovery(LAPTOP)
        readOnly()
        assertEquals(DeviceAuthenticationHealth.RecoveryPending(DEVICE_RECOVERY), phone.deviceAuthenticationHealth())
        assertReads(0)
    }

    @Test
    fun pendingLastDeviceRecoveryIsReportedWithoutAskingTheServer() = runTest {
        setUp()
        phoneStorage.lost = true
        phone.prepareLastDeviceRecovery()
        readOnly()
        assertEquals(DeviceAuthenticationHealth.RecoveryPending(LAST_DEVICE_RECOVERY), phone.deviceAuthenticationHealth(policy))
        assertReads(0)
        assertNotNull(phoneStorage.deviceAuthentication.pendingLastDeviceRecoveryKeyPair(), "not resolved")
        assertTrue(network.lastDeviceRecoveryAttempts.isEmpty())
    }

    @Test
    fun pendingRotationTakesPrecedenceOverADueKey() = runTest {
        setUp()
        phone.prepareDeviceAuthenticationRotation()
        val k2 = assertNotNull(phoneStorage.deviceAuthentication.pendingRotationKeyPair())
        readOnly()
        phoneClock.now = t0 + 400.days
        assertSame(DeviceAuthenticationHealth.RotationPending, phone.deviceAuthenticationHealth(policy))
        assertReads(0)
        assertContentEquals(k2.publicKey, assertNotNull(phoneStorage.deviceAuthentication.pendingRotationKeyPair()).publicKey, "not completed")
        assertTrue(network.rotationAttempts.isEmpty())
        assertEquals(1, registered().authEpoch)
    }

    // Missing key

    @Test
    fun missingActiveKeyIsReportedWithoutAskingTheServerAndNeverRecreated() = runTest {
        setUp()
        phoneStorage.lost = true
        readOnly()
        assertSame(DeviceAuthenticationHealth.ActiveKeyMissing, phone.deviceAuthenticationHealth(policy))
        assertSame(DeviceAuthenticationHealth.ActiveKeyMissing, phone.deviceAuthenticationHealth())
        assertReads(0)
        assertNull(phoneStorage.deviceAuthentication.keyPair(), "no key was created (every store would have failed)")
        assertNotNull(network.server.devices.registrationState(ALICE), "the server still has the registration; not asked")
    }

    @Test
    fun withoutIdentityOrBeforeTheUpgradeKeyItIsNotInitialized() = runTest {
        val fresh = client(ALICE, HealthStorage(InMemoryClientStorage()).also { it.writesBlocked = true }, phoneNetwork, phoneClock)
        assertFailsWith<SecureMessageClientException.NotInitialized> { fresh.deviceAuthenticationHealth() }

        setUp()
        phoneStorage.lost = true
        phoneStorage.awaitsUpgrade = true // storage from before milestone 12: initialize() would create the first key
        readOnly()
        assertFailsWith<SecureMessageClientException.NotInitialized> { phone.deviceAuthenticationHealth() }
        assertReads(0)
    }

    // Inconsistent local state

    @Test
    fun severalPendingTransitionsAreInconsistent() = runTest {
        setUp()
        phone.prepareDeviceAuthenticationRotation()
        phoneStorage.fakePendingRecovery = true
        readOnly()
        assertEquals(DeviceAuthenticationHealth.Inconsistent(MULTIPLE_PENDING_TRANSITIONS), phone.deviceAuthenticationHealth(policy))
        phoneStorage.fakePendingRecovery = false
        phoneStorage.fakePendingLastDeviceRecovery = true
        assertEquals(DeviceAuthenticationHealth.Inconsistent(MULTIPLE_PENDING_TRANSITIONS), phone.deviceAuthenticationHealth())
        assertReads(0)
        assertNotNull(phoneStorage.deviceAuthentication.pendingRotationKeyPair(), "nothing was chosen or removed")
    }

    @Test
    fun pendingRotationWithoutTheActiveKeyIsInconsistent() = runTest {
        setUp()
        phone.prepareDeviceAuthenticationRotation()
        phoneStorage.lost = true
        readOnly()
        assertEquals(DeviceAuthenticationHealth.Inconsistent(ROTATION_PENDING_WITHOUT_ACTIVE_KEY), phone.deviceAuthenticationHealth(policy))
        assertReads(0)
        assertNotNull(phoneStorage.deviceAuthentication.pendingRotationKeyPair(), "K2 is not promoted because K1 vanished")
    }

    // Server answers

    @Test
    fun activeKeyWithoutServerRegistrationIsUnregistered() = runTest {
        setUp(register = false)
        readOnly()
        assertSame(DeviceAuthenticationHealth.Unregistered, phone.deviceAuthenticationHealth(policy))
        assertReads(1)
        assertNull(network.server.devices.registrationState(ALICE), "nothing registered")
    }

    @Test
    fun operationalFailuresAreThrownNotClassified() = runTest {
        setUp()
        readOnly()
        phoneNetwork.failure = SecureMessageTransportException.UnexpectedResponse(500)
        assertFailsWith<SecureMessageTransportException.UnexpectedResponse> { phone.deviceAuthenticationHealth(policy) }
        phoneNetwork.failure = SecureMessageTransportException.AuthenticationFailed(AuthenticationFailure.EXPIRED)
        assertEquals(
            AuthenticationFailure.EXPIRED,
            assertFailsWith<SecureMessageTransportException.AuthenticationFailed> { phone.deviceAuthenticationHealth() }.failure,
        )
        phoneNetwork.failure = null

        // Another storage for the same address holds a key the server never registered: INVALID, thrown.
        val stranger = client(ALICE, InMemoryClientStorage(), phoneNetwork, phoneClock)
        stranger.initialize()
        assertEquals(
            AuthenticationFailure.INVALID,
            assertFailsWith<SecureMessageTransportException.AuthenticationFailed> { stranger.deviceAuthenticationHealth() }.failure,
        )
    }

    // No writes, no automatic action

    @Test
    fun healthChangesNothingInAnyState() = runTest {
        setUp()
        laptop.registerLastDeviceRecoveryKey(LastDeviceRecoveryKey.decode(laptop.createLastDeviceRecoveryKey().encode()))
        val bundle = phone.currentPreKeyBundle().toString() // PreKeyBundle compares arrays by identity; its text shows them
        val oneTimePreKeys = phone.publicOneTimePreKeys().toString()
        val session = assertNotNull(phoneStorage.sessions.load(BOB)).state
        val activeKey = assertNotNull(phoneStorage.deviceAuthentication.keyPair()).publicKey
        val registration = registered()
        val recoveryKey = network.server.lastDeviceRecovery.recoveryKeyState(ALICE.userId)
        bob.send(ALICE, "queued".encodeToByteArray())

        suspend fun assertUnchanged(label: String) {
            assertEquals(bundle, phone.currentPreKeyBundle().toString(), label)
            assertEquals(oneTimePreKeys, phone.publicOneTimePreKeys().toString(), label)
            assertContentEquals(session, assertNotNull(phoneStorage.sessions.load(BOB)).state, label)
            assertEquals(registration.authEpoch, registered().authEpoch, label)
            assertEquals(registration.authKeyInstalledAt, registered().authKeyInstalledAt, label)
            assertContentEquals(registration.registration.publicKey, registered().registration.publicKey, label)
            assertEquals(recoveryKey, network.server.lastDeviceRecovery.recoveryKeyState(ALICE.userId), label)
            assertTrue(network.rotationAttempts.isEmpty(), label)
            assertTrue(network.lastDeviceRecoveryAttempts.isEmpty(), label)
            assertTrue(network.lastDeviceRecoveryChallenges.isEmpty(), label)
        }

        phoneClock.now = t0 + 400.days
        readOnly()
        assertIs<DeviceAuthenticationHealth.RotationDue>(phone.deviceAuthenticationHealth(policy))
        assertIs<DeviceAuthenticationHealth.Healthy>(phone.deviceAuthenticationHealth())
        assertContentEquals(activeKey, assertNotNull(phoneStorage.deviceAuthentication.keyPair()).publicKey)
        assertUnchanged("due")

        writable()
        phone.prepareDeviceAuthenticationRotation()
        val k2 = assertNotNull(phoneStorage.deviceAuthentication.pendingRotationKeyPair()).publicKey
        readOnly()
        assertSame(DeviceAuthenticationHealth.RotationPending, phone.deviceAuthenticationHealth(policy))
        assertContentEquals(k2, assertNotNull(phoneStorage.deviceAuthentication.pendingRotationKeyPair()).publicKey)
        assertUnchanged("rotation pending")

        writable()
        phone.cancelDeviceAuthenticationRotation()
        phone.prepareDeviceAuthenticationRecovery(LAPTOP)
        val recovery = assertNotNull(phoneStorage.deviceAuthentication.pendingRecoveryKeyPair()).publicKey
        readOnly()
        assertIs<DeviceAuthenticationHealth.RecoveryPending>(phone.deviceAuthenticationHealth(policy))
        assertContentEquals(recovery, assertNotNull(phoneStorage.deviceAuthentication.pendingRecoveryKeyPair()).publicKey)
        assertUnchanged("recovery pending")

        writable()
        phone.cancelDeviceAuthenticationRecovery()
        phoneStorage.lost = true
        readOnly()
        assertSame(DeviceAuthenticationHealth.ActiveKeyMissing, phone.deviceAuthenticationHealth(policy))
        assertUnchanged("key missing")

        // The queued message is still there: nothing received it.
        writable()
        phoneStorage.lost = false
        assertEquals("queued", phone.accept(phone.receive().single()).decodeToString())
    }

    @Test
    fun nothingEvaluatesHealthImplicitly() = runTest {
        setUp()
        phoneClock.now = t0 + 400.days
        phone.initialize()
        phone.registerDevice()
        phone.publishPreKeys()
        bob.send(ALICE, "hi".encodeToByteArray())
        phone.accept(phone.receive().single())
        phone.send(BOB, "hello".encodeToByteArray())
        assertReads(0)
        assertEquals(1, registered().authEpoch)
    }

    // Concurrency

    @Test
    fun rotationPreparedDuringTheReadWaitsForTheHealthEvaluation() = runTest {
        setUp()
        val gate = CompletableDeferred<Unit>()
        phoneNetwork.duringStatusRead = { gate.await() }
        val health = async { phone.deviceAuthenticationHealth(policy) }
        runCurrent()
        assertEquals(1, phoneNetwork.statusReads, "the read is open")
        val prepare = async { phone.prepareDeviceAuthenticationRotation() }
        runCurrent()
        assertNull(phoneStorage.deviceAuthentication.pendingRotationKeyPair(), "the rotation waits for the evaluation")
        gate.complete(Unit)
        assertIs<DeviceAuthenticationHealth.Healthy>(health.await(), "the evaluation ran entirely before the rotation")
        prepare.await()
        phoneNetwork.duringStatusRead = {}
        assertSame(DeviceAuthenticationHealth.RotationPending, phone.deviceAuthenticationHealth(policy))
        assertReads(1)
    }

    @Test
    fun recoveryPreparedDuringTheReadIsReportedByTheRecheck() = runTest {
        setUp()
        phoneNetwork.duringStatusRead = {
            phoneNetwork.duringStatusRead = {}
            // Device recovery does not take the device authentication lock: it lands during the read.
            phone.prepareDeviceAuthenticationRecovery(LAPTOP)
        }
        assertEquals(DeviceAuthenticationHealth.RecoveryPending(DEVICE_RECOVERY), phone.deviceAuthenticationHealth(policy))
        assertReads(1)
        assertEquals(DeviceAuthenticationHealth.RecoveryPending(DEVICE_RECOVERY), phone.deviceAuthenticationHealth(policy))
        assertReads(1)
    }

    @Test
    fun resultsDoNotDescribeKeyMaterial() = runTest {
        setUp()
        val text = listOf(
            phone.deviceAuthenticationHealth(policy),
            DeviceAuthenticationHealth.RecoveryPending(DEVICE_RECOVERY),
            DeviceAuthenticationHealth.Inconsistent(MULTIPLE_PENDING_TRANSITIONS),
        ).joinToString()
        val key = assertNotNull(phoneStorage.deviceAuthentication.keyPair())
        for (bytes in listOf(key.publicKey, key.privateKey)) {
            assertFalse(text.contains(bytes.contentToString()))
        }
    }

    /**
     * The phone's transport: counts registration status reads, runs
     * [duringStatusRead] inside them (after the server answered), throws
     * [failure] instead of reading, and with [onlyStatusReads] refuses every
     * other request.
     */
    private class HealthNetwork(private val base: ServerBackedNetwork) : SecureMessageTransport by base {
        var statusReads = 0
        var duringStatusRead: suspend () -> Unit = {}
        var failure: Exception? = null
        var onlyStatusReads = false

        private fun other() {
            if (onlyStatusReads) fail("health must not send anything but the registration status read")
        }

        override suspend fun registrationStatus(address: DeviceAddress, signer: ServerRequestSigner): DeviceAuthenticationRegistrationStatus {
            statusReads++
            failure?.let { throw it }
            val status = base.registrationStatus(address, signer)
            duringStatusRead()
            return status
        }

        override suspend fun registerDevice(registration: DeviceRegistration, signer: ServerRequestSigner) =
            other().let { base.registerDevice(registration, signer) }

        override suspend fun recoverDevice(authorization: DeviceRecoveryAuthorization) = other().let { base.recoverDevice(authorization) }

        override suspend fun rotateDeviceAuthenticationKey(authorization: DeviceAuthenticationRotationAuthorization) =
            other().let { base.rotateDeviceAuthenticationKey(authorization) }

        override suspend fun registerLastDeviceRecoveryKey(
            address: DeviceAddress,
            registration: LastDeviceRecoveryKeyRegistration,
            signer: ServerRequestSigner,
        ) = other().let { base.registerLastDeviceRecoveryKey(address, registration, signer) }

        override suspend fun lastDeviceRecoveryKeyStatus(address: DeviceAddress, signer: ServerRequestSigner): LastDeviceRecoveryKeyStatus =
            other().let { base.lastDeviceRecoveryKeyStatus(address, signer) }

        override suspend fun rotateLastDeviceRecoveryKey(authorization: RecoveryKeyRotationAuthorization, signer: ServerRequestSigner) =
            other().let { base.rotateLastDeviceRecoveryKey(authorization, signer) }

        override suspend fun revokeLastDeviceRecoveryKey(authorization: RecoveryKeyRevocationAuthorization, signer: ServerRequestSigner) =
            other().let { base.revokeLastDeviceRecoveryKey(authorization, signer) }

        override suspend fun requestLastDeviceRecoveryKeyReset(address: DeviceAddress, signer: ServerRequestSigner): RecoveryKeyResetStatus.Pending =
            other().let { base.requestLastDeviceRecoveryKeyReset(address, signer) }

        override suspend fun lastDeviceRecoveryKeyResetStatus(address: DeviceAddress, signer: ServerRequestSigner): RecoveryKeyResetStatus =
            other().let { base.lastDeviceRecoveryKeyResetStatus(address, signer) }

        override suspend fun completeLastDeviceRecoveryKeyReset(authorization: RecoveryKeyResetCompletionAuthorization, signer: ServerRequestSigner) =
            other().let { base.completeLastDeviceRecoveryKeyReset(authorization, signer) }

        override suspend fun cancelLastDeviceRecoveryKeyReset(address: DeviceAddress, resetId: RecoveryKeyResetId, signer: ServerRequestSigner) =
            other().let { base.cancelLastDeviceRecoveryKeyReset(address, resetId, signer) }

        override suspend fun lastDeviceRecoveryKeyResetStatusByRecoveryKey(query: RecoveryKeyResetStatusQuery): RecoveryKeyResetStatus =
            other().let { base.lastDeviceRecoveryKeyResetStatusByRecoveryKey(query) }

        override suspend fun cancelLastDeviceRecoveryKeyResetByRecoveryKey(authorization: RecoveryKeyResetCancellationAuthorization) =
            other().let { base.cancelLastDeviceRecoveryKeyResetByRecoveryKey(authorization) }

        override suspend fun lastDeviceRecoveryChallenge(target: DeviceAddress): LastDeviceRecoveryChallenge =
            other().let { base.lastDeviceRecoveryChallenge(target) }

        override suspend fun recoverLastDevice(authorization: LastDeviceRecoveryAuthorization) = other().let { base.recoverLastDevice(authorization) }

        override suspend fun publishPreKeys(publication: PreKeyPublication, signer: ServerRequestSigner) =
            other().let { base.publishPreKeys(publication, signer) }

        override suspend fun fetchPreKeyBundle(address: DeviceAddress): PreKeyBundle = other().let { base.fetchPreKeyBundle(address) }

        override suspend fun send(envelope: EncryptedEnvelope) = other().let { base.send(envelope) }

        override suspend fun receive(address: DeviceAddress, signer: ServerRequestSigner): List<EncryptedEnvelope> =
            other().let { base.receive(address, signer) }
    }

    /**
     * The phone's storage. [lost] hides the active key (a lost key; the
     * pending slots stay visible), [awaitsUpgrade] makes it look like storage
     * from before milestone 12, the `fakePending…` flags report a pending
     * slot the real storage does not hold (a state it refuses), and
     * [writesBlocked] fails every device authentication key, identity and
     * session write.
     */
    private class HealthStorage(private val delegate: ClientStorage) : ClientStorage by delegate {
        var lost = false
        var awaitsUpgrade = false
        var fakePendingRecovery = false
        var fakePendingLastDeviceRecovery = false
        var writesBlocked = false

        private val fakeKey = DeviceAuthenticationKeyPair(ByteArray(32) { 1 }, ByteArray(32) { 2 })

        override val deviceAuthentication: DeviceAuthenticationKeyStore get() = view(delegate)
        override val identity: IdentityStore get() = identityView(delegate)
        override val sessions: SessionStore get() = sessionView(delegate)

        override suspend fun <T> transaction(block: suspend ClientStorage.() -> T): T = delegate.transaction {
            val tx = this
            object : ClientStorage by tx {
                override val deviceAuthentication: DeviceAuthenticationKeyStore = view(tx)
                override val identity: IdentityStore = identityView(tx)
                override val sessions: SessionStore = sessionView(tx)
            }.block()
        }

        private fun write() {
            if (writesBlocked) fail("health must not write")
        }

        private fun copy(keyPair: DeviceAuthenticationKeyPair) = DeviceAuthenticationKeyPair(keyPair.publicKey.copyOf(), keyPair.privateKey.copyOf())

        private fun view(storage: ClientStorage) = object : DeviceAuthenticationKeyStore by storage.deviceAuthentication {
            private val real = storage.deviceAuthentication

            override suspend fun keyPair() = if (lost) null else real.keyPair()

            override suspend fun awaitsUpgradeKey() = awaitsUpgrade || real.awaitsUpgradeKey()

            override suspend fun pendingRecoveryKeyPair() = real.pendingRecoveryKeyPair() ?: if (fakePendingRecovery) copy(fakeKey) else null

            override suspend fun pendingLastDeviceRecoveryKeyPair() =
                real.pendingLastDeviceRecoveryKeyPair() ?: if (fakePendingLastDeviceRecovery) copy(fakeKey) else null

            override suspend fun store(keyPair: DeviceAuthenticationKeyPair) = write().let { real.store(keyPair) }

            override suspend fun storePendingRecoveryKeyPair(keyPair: DeviceAuthenticationKeyPair) =
                write().let { real.storePendingRecoveryKeyPair(keyPair) }

            override suspend fun removePendingRecoveryKeyPair() = write().let { real.removePendingRecoveryKeyPair() }

            override suspend fun promotePendingRecoveryKeyPair() = write().let { real.promotePendingRecoveryKeyPair(); lost = false }

            override suspend fun storePendingRotationKeyPair(keyPair: DeviceAuthenticationKeyPair) =
                write().let { real.storePendingRotationKeyPair(keyPair) }

            override suspend fun removePendingRotationKeyPair() = write().let { real.removePendingRotationKeyPair() }

            override suspend fun promotePendingRotationKeyPair() = write().let { real.promotePendingRotationKeyPair() }

            override suspend fun storePendingLastDeviceRecoveryKeyPair(keyPair: DeviceAuthenticationKeyPair) =
                write().let { real.storePendingLastDeviceRecoveryKeyPair(keyPair) }

            override suspend fun removePendingLastDeviceRecoveryKeyPair() = write().let { real.removePendingLastDeviceRecoveryKeyPair() }

            override suspend fun promotePendingLastDeviceRecoveryKeyPair() =
                write().let { real.promotePendingLastDeviceRecoveryKeyPair(); lost = false }
        }

        private fun identityView(storage: ClientStorage) = object : IdentityStore by storage.identity {
            override suspend fun store(identity: LocalIdentity) = write().let { storage.identity.store(identity) }
        }

        private fun sessionView(storage: ClientStorage) = object : SessionStore by storage.sessions {
            override suspend fun store(session: SecureSession) = write().let { storage.sessions.store(session) }

            override suspend fun remove(address: DeviceAddress) = write().let { storage.sessions.remove(address) }
        }
    }
}
