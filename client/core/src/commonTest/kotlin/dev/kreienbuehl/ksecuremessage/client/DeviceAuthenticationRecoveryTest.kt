package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException.RecoveryFailure
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecovery
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecoveryCodec
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecoveryRequest
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequestAuthentication
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage
import dev.kreienbuehl.ksecuremessage.storage.DeviceAuthenticationKeyStore
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
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes

private val LAPTOP = DeviceAddress(UserId("alice"), DeviceId("laptop"))

/**
 * Device authentication recovery on the client (docs/device-recovery.md):
 * the lost device prepares a pending replacement key, another device of the
 * same user authorizes it, the lost device completes it; against
 * [ServerBackedNetwork], which applies the server's checks and the atomic
 * replacement of [dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationRepository.replaceForRecovery].
 */
class DeviceAuthenticationRecoveryTest {
    private val engine = KodiumProtocolEngine()
    private val clock = ManualClock()
    private var failNextNetworkCall = false
    private val network = ServerBackedNetwork {
        if (failNextNetworkCall) {
            failNextNetworkCall = false
            throw SecureMessageTransportException.UnexpectedResponse(503)
        }
    }

    private val laptopStorage = LostKeyStorage(InMemoryClientStorage())
    private val failing = FailingClientStorage(laptopStorage)

    private fun client(address: DeviceAddress, storage: ClientStorage) =
        SecureMessageClient(address, storage, engine, network, PreKeyConfiguration(oneTimePreKeyTarget = 3), clock)

    private val phone = client(ALICE, InMemoryClientStorage())
    private val laptop get() = client(LAPTOP, failing) // a new instance each time, like an application restart
    private val bob = client(BOB, InMemoryClientStorage())

    /** Phone, laptop and Bob registered; Bob and the laptop talk; then the laptop loses its authentication key. */
    private suspend fun lostLaptop(): DeviceAuthenticationKeyPair {
        for (device in listOf(phone, laptop, bob)) {
            device.initialize()
            device.registerDevice()
            device.publishPreKeys()
        }
        bob.send(LAPTOP, "before".encodeToByteArray())
        val laptop = laptop
        assertEquals("before", assertIs<ReceiveResult.Message>(laptop.decrypt(laptop.receive().single())).plaintext.decodeToString())
        bob.decrypt(bob.receive().single()) // the ACK
        bob.send(LAPTOP, "while lost".encodeToByteArray())
        val lost = assertNotNull(laptopStorage.deviceAuthentication.keyPair())
        laptopStorage.lost = true
        return lost
    }

    private suspend fun registeredLaptopKey() = assertNotNull(network.server.devices.registration(LAPTOP)).publicKey

    private suspend fun recover(): DeviceRecoveryRequest {
        val request = laptop.prepareDeviceAuthenticationRecovery(ALICE)
        laptop.completeDeviceAuthenticationRecovery(phone.authorizeDeviceRecovery(request))
        return request
    }

    @Test
    fun lostDeviceIsRecoveredThroughAnotherDeviceOfTheUser() = runTest {
        val lost = lostLaptop()
        val identity = laptopStorage.identity.identity()!!
        val signedPreKey = laptopStorage.preKeys.currentSignedPreKey()!!
        val oneTimePreKeys = laptopStorage.preKeys.publicOneTimePreKeys().map { it.id }
        val bobPin = laptopStorage.remoteIdentities.identityKey(BOB)
        val session = laptopStorage.sessions.load(BOB)!!.state

        // The lost key fails closed; nothing regenerates it.
        assertFailsWith<SecureMessageClientException.InconsistentStorage> { laptop.initialize() }
        assertFailsWith<SecureMessageClientException.NotInitialized> { laptop.receive() }

        val request = laptop.prepareDeviceAuthenticationRecovery(ALICE)
        val pending = assertNotNull(laptopStorage.deviceAuthentication.pendingRecoveryKeyPair())
        assertContentEquals(pending.publicKey, request.replacementPublicKey)
        assertContentEquals(lost.publicKey, registeredLaptopKey(), "preparing changes nothing on the server")
        // Transferred between the devices as opaque bytes.
        val authorization = phone.authorizeDeviceRecovery(DeviceRecoveryCodec.decodeRequest(DeviceRecoveryCodec.encodeRequest(request)))
        laptop.completeDeviceAuthenticationRecovery(DeviceRecoveryCodec.decodeAuthorization(DeviceRecoveryCodec.encodeAuthorization(authorization)))

        assertContentEquals(pending.publicKey, registeredLaptopKey())
        assertContentEquals(pending.privateKey, laptopStorage.deviceAuthentication.keyPair()?.privateKey)
        assertNull(laptopStorage.deviceAuthentication.pendingRecoveryKeyPair())
        assertEquals(2, network.server.devices.registrationState(LAPTOP)?.authEpoch)

        // Messaging state is untouched, and the queued message is readable with the recovered key.
        assertContentEquals(identity.privateKey, laptopStorage.identity.identity()?.privateKey)
        assertEquals(signedPreKey.id, laptopStorage.preKeys.currentSignedPreKey()?.id)
        assertEquals(oneTimePreKeys, laptopStorage.preKeys.publicOneTimePreKeys().map { it.id })
        assertContentEquals(bobPin, laptopStorage.remoteIdentities.identityKey(BOB))
        assertContentEquals(session, laptopStorage.sessions.load(BOB)?.state)
        val laptop = laptop
        laptop.initialize()
        val message = laptop.decrypt(laptop.receive().single())
        assertEquals("while lost", assertIs<ReceiveResult.Message>(message).plaintext.decodeToString())
        laptop.publishPreKeys()
    }

    @Test
    fun pendingKeyIsReusedAcrossAttemptsAndRestartsUntilCancelled() = runTest {
        lostLaptop()
        val first = laptop.prepareDeviceAuthenticationRecovery(ALICE)
        clock.advanceBy(10.minutes)
        val second = laptop.prepareDeviceAuthenticationRecovery(ALICE) // new client instance
        assertContentEquals(first.replacementPublicKey, second.replacementPublicKey)
        assertFalse(first.nonce == second.nonce)
        assertEquals(clock.now(), second.timestamp)

        laptop.cancelDeviceAuthenticationRecovery()
        assertNull(laptopStorage.deviceAuthentication.pendingRecoveryKeyPair())
        val third = laptop.prepareDeviceAuthenticationRecovery(ALICE)
        assertFalse(first.replacementPublicKey.contentEquals(third.replacementPublicKey))
        // The authorization of the cancelled key is refused locally.
        val stale = phone.authorizeDeviceRecovery(second)
        assertFailsWith<SecureMessageClientException.InvalidDeviceRecovery> { laptop.completeDeviceAuthenticationRecovery(stale) }
    }

    @Test
    fun preparationChecksTheAuthorizerAndNeedsTheIdentity() = runTest {
        lostLaptop()
        assertFailsWith<SecureMessageClientException.InvalidDeviceRecovery> { laptop.prepareDeviceAuthenticationRecovery(LAPTOP) }
        assertFailsWith<SecureMessageClientException.InvalidDeviceRecovery> { laptop.prepareDeviceAuthenticationRecovery(BOB) }
        assertNull(laptopStorage.deviceAuthentication.pendingRecoveryKeyPair(), "nothing created")
        assertFailsWith<SecureMessageClientException.NotInitialized> {
            client(DeviceAddress(UserId("alice"), DeviceId("new")), InMemoryClientStorage()).prepareDeviceAuthenticationRecovery(ALICE)
        }
    }

    @Test
    fun authorizerChecksTheRequestBeforeSigning() = runTest {
        lostLaptop()
        val request = laptop.prepareDeviceAuthenticationRecovery(ALICE)
        fun copy(
            target: DeviceAddress = request.target,
            authorizer: DeviceAddress = request.authorizer,
            pop: ByteArray = request.proofOfPossession,
        ) = DeviceRecoveryRequest(target, authorizer, request.replacementPublicKey, request.timestamp, request.nonce, pop)

        val invalid = listOf(
            copy(authorizer = DeviceAddress(UserId("alice"), DeviceId("tablet"))), // asks another device
            copy(target = ALICE), // the phone itself
            copy(target = DeviceAddress(UserId("mallory"), DeviceId("laptop")), authorizer = ALICE), // another user
            copy(pop = request.proofOfPossession.also { it[0] = (it[0].toInt() xor 1).toByte() }),
        )
        for (candidate in invalid) {
            assertFailsWith<SecureMessageClientException.InvalidDeviceRecovery> { phone.authorizeDeviceRecovery(candidate) }
        }
        // Freshness by the authorizer's clock, bounds included.
        clock.advanceBy(5.minutes)
        phone.authorizeDeviceRecovery(request)
        clock.advanceBy(1.milliseconds)
        assertFailsWith<SecureMessageClientException.InvalidDeviceRecovery> { phone.authorizeDeviceRecovery(request) }
        clock.advanceBy(-10.minutes - 2.milliseconds)
        assertFailsWith<SecureMessageClientException.InvalidDeviceRecovery> { phone.authorizeDeviceRecovery(request) }
        // An authorizer without a key cannot authorize.
        clock.now = request.timestamp
        assertFailsWith<SecureMessageClientException.NotInitialized> {
            client(ALICE, InMemoryClientStorage()).authorizeDeviceRecovery(request)
        }
    }

    @Test
    fun completionChecksTheAuthorizationAgainstThePendingKey() = runTest {
        lostLaptop()
        val authorization = phone.authorizeDeviceRecovery(laptop.prepareDeviceAuthenticationRecovery(ALICE))
        assertFailsWith<SecureMessageClientException.InvalidDeviceRecovery> {
            client(DeviceAddress(UserId("alice"), DeviceId("tablet")), InMemoryClientStorage()).completeDeviceAuthenticationRecovery(authorization)
        }
        laptop.cancelDeviceAuthenticationRecovery()
        assertFailsWith<SecureMessageClientException.NoPendingDeviceRecovery> { laptop.completeDeviceAuthenticationRecovery(authorization) }
        assertFailsWith<SecureMessageClientException.NoPendingDeviceRecovery> { laptop.resolveDeviceAuthenticationRecovery() }
    }

    @Test
    fun serverRejectionKeepsThePendingKeyForAnotherAttempt() = runTest {
        val lost = lostLaptop()
        val request = laptop.prepareDeviceAuthenticationRecovery(ALICE)
        // Signed by a key the server does not have for the phone.
        val forged = DeviceRecovery.authorize(engine.createDeviceAuthenticationKey(), request)
        val rejected = assertFailsWith<SecureMessageTransportException.DeviceRecoveryRejected> { laptop.completeDeviceAuthenticationRecovery(forged) }
        assertEquals(RecoveryFailure.INVALID_PROOF, rejected.reason)
        assertContentEquals(lost.publicKey, registeredLaptopKey())
        assertNotNull(laptopStorage.deviceAuthentication.pendingRecoveryKeyPair())
        assertNull(laptopStorage.deviceAuthentication.keyPair())

        laptop.completeDeviceAuthenticationRecovery(phone.authorizeDeviceRecovery(request))
        assertContentEquals(request.replacementPublicKey, registeredLaptopKey())
    }

    @Test
    fun failuresBeforeSubmissionLeaveARecoverableState() = runTest {
        lostLaptop()
        // Pending key creation fails: nothing stored, the next attempt creates one.
        failing.failPendingRecoveryKeyStore = true
        assertFailsWith<StorageFailure> { laptop.prepareDeviceAuthenticationRecovery(ALICE) }
        assertNull(laptopStorage.deviceAuthentication.pendingRecoveryKeyPair())
        failing.failPendingRecoveryKeyStore = false
        val request = laptop.prepareDeviceAuthenticationRecovery(ALICE)
        val authorization = phone.authorizeDeviceRecovery(request)

        // The request never reaches the server.
        failNextNetworkCall = true
        assertFailsWith<SecureMessageTransportException.UnexpectedResponse> { laptop.completeDeviceAuthenticationRecovery(authorization) }
        assertEquals(1, network.server.devices.registrationState(LAPTOP)?.authEpoch)
        assertContentEquals(request.replacementPublicKey, laptopStorage.deviceAuthentication.pendingRecoveryKeyPair()?.publicKey)

        laptop.completeDeviceAuthenticationRecovery(authorization) // same authorization, after a restart
        assertContentEquals(request.replacementPublicKey, registeredLaptopKey())
        assertContentEquals(request.replacementPublicKey, laptopStorage.deviceAuthentication.keyPair()?.publicKey)
    }

    @Test
    fun lostResponseIsCompletedByRetryingTheSameAuthorization() = runTest {
        lostLaptop()
        val request = laptop.prepareDeviceAuthenticationRecovery(ALICE)
        val authorization = phone.authorizeDeviceRecovery(request)
        network.afterRecovery = { network.afterRecovery = {}; throw SecureMessageTransportException.UnexpectedResponse(504) }
        assertFailsWith<SecureMessageTransportException.UnexpectedResponse> { laptop.completeDeviceAuthenticationRecovery(authorization) }
        assertContentEquals(request.replacementPublicKey, registeredLaptopKey(), "the server committed")
        assertNull(laptopStorage.deviceAuthentication.keyPair(), "the client did not promote")

        laptop.completeDeviceAuthenticationRecovery(authorization) // restart, then retry: already applied
        assertContentEquals(request.replacementPublicKey, laptopStorage.deviceAuthentication.keyPair()?.publicKey)
        assertEquals(2, network.server.devices.registrationState(LAPTOP)?.authEpoch, "replaced once")
    }

    @Test
    fun lostResponseIsCompletedByANewAuthorizationForTheSameKey() = runTest {
        lostLaptop()
        val request = laptop.prepareDeviceAuthenticationRecovery(ALICE)
        network.afterRecovery = { network.afterRecovery = {}; throw SecureMessageTransportException.UnexpectedResponse(504) }
        assertFailsWith<SecureMessageTransportException.UnexpectedResponse> {
            laptop.completeDeviceAuthenticationRecovery(phone.authorizeDeviceRecovery(request))
        }
        // The old authorization is gone (or expired); the user authorizes again: the server reports a
        // conflict (the key is already registered), and the client confirms it with a signed probe.
        clock.advanceBy(30.minutes)
        laptop.completeDeviceAuthenticationRecovery(phone.authorizeDeviceRecovery(laptop.prepareDeviceAuthenticationRecovery(ALICE)))
        assertContentEquals(request.replacementPublicKey, laptopStorage.deviceAuthentication.keyPair()?.publicKey)
        assertNull(laptopStorage.deviceAuthentication.pendingRecoveryKeyPair())
        assertEquals(2, network.server.devices.registrationState(LAPTOP)?.authEpoch)
    }

    @Test
    fun restartBeforePromotionIsResolvedWithTheServer() = runTest {
        lostLaptop()
        val request = laptop.prepareDeviceAuthenticationRecovery(ALICE)
        assertFalse(laptop.resolveDeviceAuthenticationRecovery(), "not registered yet")
        assertNotNull(laptopStorage.deviceAuthentication.pendingRecoveryKeyPair(), "kept")

        failing.failRecoveryKeyPromotion = true
        assertFailsWith<StorageFailure> { laptop.completeDeviceAuthenticationRecovery(phone.authorizeDeviceRecovery(request)) }
        failing.failRecoveryKeyPromotion = false
        assertNull(laptopStorage.deviceAuthentication.keyPair())

        assertTrue(laptop.resolveDeviceAuthenticationRecovery())
        assertContentEquals(request.replacementPublicKey, laptopStorage.deviceAuthentication.keyPair()?.publicKey)
        assertNull(laptopStorage.deviceAuthentication.pendingRecoveryKeyPair())
        assertEquals(2, network.server.devices.registrationState(LAPTOP)?.authEpoch, "the probe replaced nothing")
    }

    @Test
    fun recoveryWithTheOldKeyStillPresentKeepsItUntilPromotion() = runTest {
        lostLaptop()
        laptopStorage.lost = false // the key is not lost after all: recovery must not destroy it early
        val old = assertNotNull(laptopStorage.deviceAuthentication.keyPair())
        val request = laptop.prepareDeviceAuthenticationRecovery(ALICE)
        assertContentEquals(old.privateKey, laptopStorage.deviceAuthentication.keyPair()?.privateKey)
        laptop.receive() // the old key still works until the server replaced it

        laptop.completeDeviceAuthenticationRecovery(phone.authorizeDeviceRecovery(request))
        assertContentEquals(request.replacementPublicKey, laptopStorage.deviceAuthentication.keyPair()?.publicKey)
        // A request signed with the old key is rejected now.
        val oldSigner = ServerRequestSigner { ServerRequestAuthentication.sign(old, it, clock.now()) }
        val rejected = assertFailsWith<SecureMessageTransportException.AuthenticationFailed> { network.receive(LAPTOP, oldSigner) }
        assertEquals(SecureMessageTransportException.AuthenticationFailure.INVALID, rejected.failure)
        laptop.receive()
    }

    @Test
    fun recoveredDeviceCanBeRecoveredAgain() = runTest {
        lostLaptop()
        val first = recover()
        laptopStorage.lost = true
        val second = recover()
        assertFalse(first.replacementPublicKey.contentEquals(second.replacementPublicKey))
        assertContentEquals(second.replacementPublicKey, registeredLaptopKey())
        assertEquals(3, network.server.devices.registrationState(LAPTOP)?.authEpoch)
    }

    /**
     * In-memory storage whose active device authentication key can be
     * hidden, like an M12+ installation that lost it: [lost] makes
     * [DeviceAuthenticationKeyStore.keyPair] return `null` until a pending
     * recovery key is promoted.
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

            override suspend fun promotePendingRecoveryKeyPair() {
                storage.deviceAuthentication.promotePendingRecoveryKeyPair()
                lost = false
            }
        }
    }
}
