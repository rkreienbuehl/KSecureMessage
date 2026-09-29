package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.client.RecoveryKeyResetAwarenessInconsistency.RESET_EPOCH_MISMATCH
import dev.kreienbuehl.ksecuremessage.client.RecoveryKeyResetAwarenessInconsistency.RESET_KEY_MISMATCH
import dev.kreienbuehl.ksecuremessage.client.RecoveryKeyResetAwarenessInconsistency.RESET_OF_OTHER_USER
import dev.kreienbuehl.ksecuremessage.client.RecoveryKeyResetAwarenessInconsistency.RESET_WITHOUT_ACTIVE_RECOVERY_KEY
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException.RecoveryKeyResetFailure
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
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationRotationAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecoveryAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryChallenge
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryKey
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryKeyRegistration
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyResetCancellationAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyResetCompletionAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRevocationAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRotationAuthorization
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage
import dev.kreienbuehl.ksecuremessage.storage.client.inmemory.InMemoryClientStorage
import kotlinx.coroutines.test.runTest
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Instant

/**
 * Recovery key reset awareness (docs/recovery-key-reset.md, "Reset
 * awareness"): the read-only composition of the signed recovery key status
 * and the signed reset status, against [ServerBackedNetwork]. The phone has
 * its own client clock, separate from the server clock. Its transport counts
 * the two reads, can run a transition between them, can script a response,
 * and can refuse every other request.
 */
class RecoveryKeyResetAwarenessTest {
    private val engine = KodiumProtocolEngine()
    private val serverClock = ManualClock()
    private val phoneClock = ManualClock()
    private val network = ServerBackedNetwork(serverClock)
    private val phoneNetwork = AwarenessNetwork(network)
    private val delay = 3.days

    private val phoneStorage = InMemoryClientStorage()
    private val laptop = DeviceAddress(UserId("alice"), DeviceId("laptop"))

    private fun client(address: DeviceAddress, storage: ClientStorage, transport: SecureMessageTransport, clock: ManualClock) =
        SecureMessageClient(address, storage, engine, transport, PreKeyConfiguration(oneTimePreKeyTarget = 3), clock)

    private val phone = client(ALICE, phoneStorage, phoneNetwork, phoneClock)
    private val laptopClient = client(laptop, InMemoryClientStorage(), network, serverClock)
    private val bob = client(BOB, InMemoryClientStorage(), network, serverClock)

    private lateinit var r1: LastDeviceRecoveryKey
    private lateinit var r2: LastDeviceRecoveryKey

    /** Phone, laptop and Bob registered; the phone and Bob talked. With [register], the phone registered R1. */
    private suspend fun setUp(register: Boolean = true) {
        r1 = LastDeviceRecoveryKey.decode(phone.createLastDeviceRecoveryKey().encode())
        r2 = LastDeviceRecoveryKey.decode(phone.createLastDeviceRecoveryKey().encode())
        for (device in listOf(phone, laptopClient, bob)) {
            device.initialize()
            device.registerDevice()
            device.publishPreKeys()
        }
        bob.send(ALICE, "hello".encodeToByteArray())
        assertEquals("hello", phone.accept(phone.receive().single()).decodeToString())
        bob.decrypt(bob.receive().single()) // the ACK
        if (register) phone.registerLastDeviceRecoveryKey(r1)
        phoneNetwork.resetCounts()
    }

    private fun assertReads(expected: Int) {
        assertEquals(expected, phoneNetwork.keyStatusReads, "recovery key status reads")
        assertEquals(expected, phoneNetwork.resetStatusReads, "reset status reads")
    }

    private fun pending(owner: DeviceAddress, key: ByteArray, epoch: Long, requestedAt: Instant = serverClock.now) =
        RecoveryKeyResetStatus.Pending(RecoveryKeyResetId(Random.nextBytes(16)), owner, requestedAt, requestedAt + delay, epoch, key)

    @Test
    fun noPendingResetIsNoneWhateverTheRecoveryKeyState() = runTest {
        setUp(register = false)
        assertSame(RecoveryKeyResetAwareness.None, phone.recoveryKeyResetAwareness(), "unconfigured")
        assertReads(1)

        phone.registerLastDeviceRecoveryKey(r1)
        phoneNetwork.resetCounts()
        assertSame(RecoveryKeyResetAwareness.None, phone.recoveryKeyResetAwareness(), "active")
        assertReads(1)

        laptopClient.revokeLastDeviceRecoveryKey(r1)
        phoneNetwork.resetCounts()
        assertSame(RecoveryKeyResetAwareness.None, phone.recoveryKeyResetAwareness(), "revoked")
        assertReads(1)
    }

    @Test
    fun aPendingResetIsPendingBeforeAndEligibleFromItsEligibilityTime() = runTest {
        setUp()
        val reset = laptopClient.requestLastDeviceRecoveryKeyReset()

        phoneClock.now = reset.eligibleAt - 1.milliseconds
        val before = assertIs<RecoveryKeyResetAwareness.Pending>(phone.recoveryKeyResetAwareness())
        assertEquals(reset, before.reset)
        assertEquals(phoneClock.now, before.evaluatedAt)
        assertEquals(1.milliseconds, before.remainingUntilEligible)
        assertEquals(1, before.reset.recoveryKeyEpoch)
        assertContentEquals(r1.publicKey, before.reset.recoveryPublicKey)
        assertEquals(laptop, before.reset.requestedBy)

        phoneClock.now = reset.eligibleAt
        val at = assertIs<RecoveryKeyResetAwareness.Eligible>(phone.recoveryKeyResetAwareness())
        assertEquals(reset, at.reset)
        assertEquals(reset.eligibleAt, at.evaluatedAt)

        phoneClock.now = reset.eligibleAt + 1.hours
        assertEquals(reset, assertIs<RecoveryKeyResetAwareness.Eligible>(phone.recoveryKeyResetAwareness()).reset)
        assertReads(3)
    }

    @Test
    fun theClientClockClassifiesAndNeverGivesANegativeRemainingTime() = runTest {
        setUp()
        val reset = laptopClient.requestLastDeviceRecoveryKeyReset()

        // A client clock behind the request time: pending, the whole delay and more to go.
        phoneClock.now = reset.requestedAt - 2.hours
        val behind = assertIs<RecoveryKeyResetAwareness.Pending>(phone.recoveryKeyResetAwareness())
        assertEquals(delay + 2.hours, behind.remainingUntilEligible)

        // Forward past the eligibility time, then back again: pending again, remaining positive.
        phoneClock.now = reset.eligibleAt + 1.days
        assertIs<RecoveryKeyResetAwareness.Eligible>(phone.recoveryKeyResetAwareness())
        phoneClock.now = reset.eligibleAt - 5.hours
        val back = assertIs<RecoveryKeyResetAwareness.Pending>(phone.recoveryKeyResetAwareness())
        assertEquals(5.hours, back.remainingUntilEligible)
        assertTrue(back.remainingUntilEligible > Duration.ZERO)

        // A hand-built awareness past the eligibility time still clamps at zero.
        assertEquals(Duration.ZERO, RecoveryKeyResetAwareness.Pending(reset, reset.eligibleAt + 1.hours).remainingUntilEligible)
    }

    @Test
    fun eligibleByTheClientClockIsNoServerGuarantee() = runTest {
        setUp()
        val reset = laptopClient.requestLastDeviceRecoveryKeyReset()
        phoneClock.now = reset.eligibleAt + 1.hours
        serverClock.now = reset.eligibleAt - 1.hours
        assertIs<RecoveryKeyResetAwareness.Eligible>(phone.recoveryKeyResetAwareness())

        val refused = assertFailsWith<SecureMessageTransportException.RecoveryKeyResetRejected> { laptopClient.completeLastDeviceRecoveryKeyReset(r2) }
        assertEquals(RecoveryKeyResetFailure.NOT_YET_ELIGIBLE, refused.reason)
        assertEquals(reset, network.server.lastDeviceRecovery.pendingRecoveryKeyReset(ALICE.userId))
    }

    @Test
    fun aCancellationBetweenTheReadsGivesNone() = runTest {
        setUp()
        val reset = laptopClient.requestLastDeviceRecoveryKeyReset()
        phoneNetwork.afterKeyStatusRead = { read -> if (read == 1) laptopClient.cancelLastDeviceRecoveryKeyReset(reset) }
        assertSame(RecoveryKeyResetAwareness.None, phone.recoveryKeyResetAwareness())
        assertReads(1)
    }

    @Test
    fun aCompletionAndANewRequestBetweenTheReadsAreReadAgainOnce() = runTest {
        setUp()
        val first = laptopClient.requestLastDeviceRecoveryKeyReset()
        lateinit var second: RecoveryKeyResetStatus.Pending
        phoneNetwork.afterKeyStatusRead = { read ->
            if (read == 1) {
                serverClock.now = first.eligibleAt
                laptopClient.completeLastDeviceRecoveryKeyReset(r2)
                second = laptopClient.requestLastDeviceRecoveryKeyReset()
            }
        }
        // First pair: R1 at epoch 1 with a reset of R2 at epoch 2. The fresh pair is consistent.
        val awareness = assertIs<RecoveryKeyResetAwareness.Pending>(phone.recoveryKeyResetAwareness())
        assertEquals(second, awareness.reset)
        assertEquals(2, awareness.reset.recoveryKeyEpoch)
        assertContentEquals(r2.publicKey, awareness.reset.recoveryPublicKey)
        assertReads(2)
    }

    @Test
    fun aCompletionBetweenTheReadsGivesNoneForTheCurrentState() = runTest {
        setUp()
        val reset = laptopClient.requestLastDeviceRecoveryKeyReset()
        phoneNetwork.afterKeyStatusRead = { read ->
            if (read == 1) {
                serverClock.now = reset.eligibleAt
                laptopClient.completeLastDeviceRecoveryKeyReset(r2)
            }
        }
        assertSame(RecoveryKeyResetAwareness.None, phone.recoveryKeyResetAwareness(), "no history is inferred")
        assertReads(1)
    }

    @Test
    fun aRotationBetweenTheReadsGivesNone() = runTest {
        setUp()
        laptopClient.requestLastDeviceRecoveryKeyReset()
        phoneNetwork.afterKeyStatusRead = { read -> if (read == 1) laptopClient.rotateLastDeviceRecoveryKey(r1, r2) }
        assertSame(RecoveryKeyResetAwareness.None, phone.recoveryKeyResetAwareness())
        assertReads(1)
    }

    @Test
    fun aRegistrationAndRequestBetweenTheReadsAreReadAgainOnce() = runTest {
        setUp()
        laptopClient.revokeLastDeviceRecoveryKey(r1)
        lateinit var reset: RecoveryKeyResetStatus.Pending
        phoneNetwork.afterKeyStatusRead = { read ->
            if (read == 1) {
                laptopClient.registerLastDeviceRecoveryKey(r2)
                reset = laptopClient.requestLastDeviceRecoveryKeyReset()
            }
        }
        // First pair: revoked with a reset. The fresh pair: R2 active at epoch 3 with its reset.
        val awareness = assertIs<RecoveryKeyResetAwareness.Pending>(phone.recoveryKeyResetAwareness())
        assertEquals(reset, awareness.reset)
        assertEquals(3, reset.recoveryKeyEpoch)
        assertReads(2)
    }

    @Test
    fun aPersistentEpochMismatchIsInconsistentAfterExactlyOneReread() = runTest {
        setUp()
        phoneNetwork.resetStatusOverride = { pending(ALICE, r1.publicKey, epoch = 2) }
        assertEquals(RecoveryKeyResetAwareness.Inconsistent(RESET_EPOCH_MISMATCH), phone.recoveryKeyResetAwareness())
        assertReads(2)
    }

    @Test
    fun aPersistentKeyMismatchIsInconsistentAfterExactlyOneReread() = runTest {
        setUp()
        phoneNetwork.resetStatusOverride = { pending(ALICE, r2.publicKey, epoch = 1) }
        assertEquals(RecoveryKeyResetAwareness.Inconsistent(RESET_KEY_MISMATCH), phone.recoveryKeyResetAwareness())
        assertReads(2)
    }

    @Test
    fun aResetWithoutAnActiveKeyIsInconsistentNeverNone() = runTest {
        setUp()
        laptopClient.revokeLastDeviceRecoveryKey(r1)
        phoneNetwork.resetCounts()
        phoneNetwork.resetStatusOverride = { pending(ALICE, r1.publicKey, epoch = 1) }
        assertEquals(RecoveryKeyResetAwareness.Inconsistent(RESET_WITHOUT_ACTIVE_RECOVERY_KEY), phone.recoveryKeyResetAwareness())
        assertReads(2)

        phoneNetwork.resetCounts()
        phoneNetwork.keyStatusOverride = { LastDeviceRecoveryKeyStatus.Unconfigured }
        assertEquals(RecoveryKeyResetAwareness.Inconsistent(RESET_WITHOUT_ACTIVE_RECOVERY_KEY), phone.recoveryKeyResetAwareness())
        assertReads(2)
    }

    @Test
    fun aMismatchOnlyInTheFirstPairGivesTheFreshResult() = runTest {
        setUp()
        val reset = laptopClient.requestLastDeviceRecoveryKeyReset()
        phoneNetwork.keyStatusOverride = { read -> if (read == 1) LastDeviceRecoveryKeyStatus.Active(2, serverClock.now, r2.publicKey) else null }
        assertEquals(reset, assertIs<RecoveryKeyResetAwareness.Pending>(phone.recoveryKeyResetAwareness()).reset)
        assertReads(2)
    }

    @Test
    fun anotherUsersResetIsInconsistentWithoutRereadAndOnlyTheOwnDeviceIsQueried() = runTest {
        setUp()
        phoneNetwork.resetStatusOverride = { pending(BOB, r1.publicKey, epoch = 1) }
        assertEquals(RecoveryKeyResetAwareness.Inconsistent(RESET_OF_OTHER_USER), phone.recoveryKeyResetAwareness())
        assertReads(1)
        assertEquals(setOf(ALICE), phoneNetwork.queriedAddresses)

        // Bob's own awareness never sees Alice's reset.
        phoneNetwork.resetStatusOverride = { null }
        laptopClient.requestLastDeviceRecoveryKeyReset()
        assertSame(RecoveryKeyResetAwareness.None, bob.recoveryKeyResetAwareness())
    }

    @Test
    fun awarenessWritesNothingAndReadsFreshEveryTime() = runTest {
        setUp()
        val reset = laptopClient.requestLastDeviceRecoveryKeyReset()
        val server = network.server
        suspend fun serverState() = listOf(
            server.lastDeviceRecovery.recoveryKeyState(ALICE.userId)?.let { "${it.epoch} ${it.status} ${it.publicKey?.toList()} ${it.installedAt}" },
            server.lastDeviceRecovery.pendingRecoveryKeyReset(ALICE.userId),
            server.devices.registrationState(ALICE)?.let { "${it.registration.publicKey.toList()} ${it.authEpoch} ${it.authKeyInstalledAt}" },
            server.preKeys.oneTimePreKeyCount(ALICE),
            server.preKeys.oneTimePreKeyCount(BOB),
        )
        suspend fun clientState() = listOf(
            phoneStorage.sessions.load(BOB)?.state?.toList(),
            phoneStorage.deviceAuthentication.keyPair()?.publicKey?.toList(),
            phone.pendingMessageCount(),
            phone.pendingReceivedMessageCount(),
        )
        val serverBefore = serverState()
        val clientBefore = clientState()
        phoneNetwork.writesBlocked = true

        phoneClock.now = reset.eligibleAt - 1.hours
        assertIs<RecoveryKeyResetAwareness.Pending>(phone.recoveryKeyResetAwareness())
        phoneClock.now = reset.eligibleAt
        assertIs<RecoveryKeyResetAwareness.Eligible>(phone.recoveryKeyResetAwareness())
        assertIs<RecoveryKeyResetAwareness.Eligible>(phone.recoveryKeyResetAwareness())
        assertReads(3)

        assertEquals(serverBefore, serverState())
        assertEquals(clientBefore, clientState())
        assertTrue(server.mailboxes.drain(ALICE).isEmpty())
        assertTrue(server.mailboxes.drain(BOB).isEmpty())

        // No cached result: a cancellation elsewhere is seen by the next call.
        laptopClient.cancelLastDeviceRecoveryKeyReset(reset)
        assertSame(RecoveryKeyResetAwareness.None, phone.recoveryKeyResetAwareness())
        assertReads(4)
    }

    @Test
    fun awarenessNeedsAnInitializedClient() = runTest {
        assertFailsWith<SecureMessageClientException.NotInitialized> { phone.recoveryKeyResetAwareness() }
        assertReads(0)
    }

    @Test
    fun malformedResetTimingCannotReachTheAwareness() {
        val at = Instant.parse("2026-01-01T00:00:00Z")
        val id = RecoveryKeyResetId(ByteArray(16))
        assertFailsWith<IllegalArgumentException> { RecoveryKeyResetStatus.Pending(id, ALICE, at, at, 1, ByteArray(32)) }
        assertFailsWith<IllegalArgumentException> { RecoveryKeyResetStatus.Pending(id, ALICE, at, at - 1.milliseconds, 1, ByteArray(32)) }
        assertNotNull(RecoveryKeyResetStatus.Pending(id, ALICE, at, at + 1.milliseconds, 1, ByteArray(32)))
    }

    /**
     * The phone's transport: counts and scripts the two status reads, runs
     * [afterKeyStatusRead] between them, and with [writesBlocked] fails every
     * other request (including drains, bundle fetches and signing on behalf
     * of another call).
     */
    private class AwarenessNetwork(private val base: ServerBackedNetwork) : SecureMessageTransport by base {
        var keyStatusReads = 0
        var resetStatusReads = 0
        val queriedAddresses = mutableSetOf<DeviceAddress>()
        var afterKeyStatusRead: suspend (Int) -> Unit = {}
        var keyStatusOverride: (Int) -> LastDeviceRecoveryKeyStatus? = { null }
        var resetStatusOverride: (Int) -> RecoveryKeyResetStatus? = { null }
        var writesBlocked = false

        fun resetCounts() {
            keyStatusReads = 0
            resetStatusReads = 0
        }

        private fun write() {
            if (writesBlocked) fail("awareness must not write")
        }

        override suspend fun lastDeviceRecoveryKeyStatus(address: DeviceAddress, signer: ServerRequestSigner): LastDeviceRecoveryKeyStatus {
            val read = ++keyStatusReads
            queriedAddresses += address
            val status = base.lastDeviceRecoveryKeyStatus(address, signer)
            afterKeyStatusRead(read)
            return keyStatusOverride(read) ?: status
        }

        override suspend fun lastDeviceRecoveryKeyResetStatus(address: DeviceAddress, signer: ServerRequestSigner): RecoveryKeyResetStatus {
            val read = ++resetStatusReads
            queriedAddresses += address
            val status = base.lastDeviceRecoveryKeyResetStatus(address, signer)
            return resetStatusOverride(read) ?: status
        }

        override suspend fun registerDevice(registration: DeviceRegistration, signer: ServerRequestSigner) =
            write().let { base.registerDevice(registration, signer) }

        override suspend fun recoverDevice(authorization: DeviceRecoveryAuthorization) = write().let { base.recoverDevice(authorization) }

        override suspend fun registrationStatus(address: DeviceAddress, signer: ServerRequestSigner): DeviceAuthenticationRegistrationStatus =
            write().let { base.registrationStatus(address, signer) }

        override suspend fun rotateDeviceAuthenticationKey(authorization: DeviceAuthenticationRotationAuthorization) =
            write().let { base.rotateDeviceAuthenticationKey(authorization) }

        override suspend fun registerLastDeviceRecoveryKey(
            address: DeviceAddress,
            registration: LastDeviceRecoveryKeyRegistration,
            signer: ServerRequestSigner,
        ) = write().let { base.registerLastDeviceRecoveryKey(address, registration, signer) }

        override suspend fun rotateLastDeviceRecoveryKey(authorization: RecoveryKeyRotationAuthorization, signer: ServerRequestSigner) =
            write().let { base.rotateLastDeviceRecoveryKey(authorization, signer) }

        override suspend fun revokeLastDeviceRecoveryKey(authorization: RecoveryKeyRevocationAuthorization, signer: ServerRequestSigner) =
            write().let { base.revokeLastDeviceRecoveryKey(authorization, signer) }

        override suspend fun requestLastDeviceRecoveryKeyReset(address: DeviceAddress, signer: ServerRequestSigner): RecoveryKeyResetStatus.Pending =
            write().let { base.requestLastDeviceRecoveryKeyReset(address, signer) }

        override suspend fun completeLastDeviceRecoveryKeyReset(authorization: RecoveryKeyResetCompletionAuthorization, signer: ServerRequestSigner) =
            write().let { base.completeLastDeviceRecoveryKeyReset(authorization, signer) }

        override suspend fun cancelLastDeviceRecoveryKeyReset(address: DeviceAddress, resetId: RecoveryKeyResetId, signer: ServerRequestSigner) =
            write().let { base.cancelLastDeviceRecoveryKeyReset(address, resetId, signer) }

        override suspend fun cancelLastDeviceRecoveryKeyResetByRecoveryKey(authorization: RecoveryKeyResetCancellationAuthorization) =
            write().let { base.cancelLastDeviceRecoveryKeyResetByRecoveryKey(authorization) }

        override suspend fun lastDeviceRecoveryChallenge(target: DeviceAddress): LastDeviceRecoveryChallenge =
            write().let { base.lastDeviceRecoveryChallenge(target) }

        override suspend fun recoverLastDevice(authorization: LastDeviceRecoveryAuthorization) = write().let { base.recoverLastDevice(authorization) }

        override suspend fun publishPreKeys(publication: PreKeyPublication, signer: ServerRequestSigner) =
            write().let { base.publishPreKeys(publication, signer) }

        override suspend fun fetchPreKeyBundle(address: DeviceAddress): PreKeyBundle = write().let { base.fetchPreKeyBundle(address) }

        override suspend fun send(envelope: EncryptedEnvelope, signer: ServerRequestSigner) = write().let { base.send(envelope, signer) }

        override suspend fun receive(address: DeviceAddress, signer: ServerRequestSigner): List<EncryptedEnvelope> =
            write().let { base.receive(address, signer) }
    }
}
