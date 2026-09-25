package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException.AuthenticationFailure
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.MessageId
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.RequestAuthentication
import dev.kreienbuehl.ksecuremessage.protocol.ServerApiPaths
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequest
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequestAuthentication
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage
import dev.kreienbuehl.ksecuremessage.storage.DeviceAuthenticationKeyStore
import dev.kreienbuehl.ksecuremessage.storage.inmemory.InMemoryClientStorage
import kotlinx.coroutines.test.runTest
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
import kotlin.time.Duration.Companion.seconds

/**
 * The device authentication key and the client's authenticated server
 * requests (docs/server-authentication.md), against [ServerBackedNetwork],
 * which checks signatures against registered keys and claims nonces.
 */
class DeviceAuthenticationTest {
    private val engine = KodiumProtocolEngine()
    private val clock = ManualClock()
    private var networkCalls = 0
    private val network = ServerBackedNetwork { networkCalls++ }

    private fun client(address: DeviceAddress, storage: ClientStorage = InMemoryClientStorage(), transport: SecureMessageTransport = network) =
        SecureMessageClient(address, storage, engine, transport, PreKeyConfiguration(oneTimePreKeyTarget = 3), clock)

    @Test
    fun initializeCreatesTheKeyLocallyAndNeverRegisters() = runTest {
        val storage = InMemoryClientStorage()
        val bob = client(BOB, storage)
        bob.initialize()

        val keyPair = assertNotNull(storage.deviceAuthentication.keyPair())
        assertEquals(ServerRequestAuthentication.PUBLIC_KEY_SIZE, keyPair.publicKey.size)
        assertFalse(keyPair.publicKey.contentEquals(storage.identity.identity()!!.publicKey.copyOfRange(32, 64)), "not the identity's signing key")
        assertEquals(0, networkCalls, "no network I/O")
        assertNull(network.server.devices.registration(BOB))

        bob.initialize()
        assertContentEquals(keyPair.privateKey, storage.deviceAuthentication.keyPair()?.privateKey, "kept on later starts")
    }

    @Test
    fun registrationIsExplicitAndIdempotent() = runTest {
        val storage = InMemoryClientStorage()
        val bob = client(BOB, storage)
        bob.initialize()
        bob.registerDevice()
        bob.registerDevice()

        assertContentEquals(storage.deviceAuthentication.keyPair()!!.publicKey, network.server.devices.registration(BOB)?.publicKey)
        assertFailsWith<SecureMessageClientException.NotInitialized> { client(ALICE).registerDevice() }
    }

    @Test
    fun anotherKeyForARegisteredAddressIsAConflict() = runTest {
        val bob = client(BOB)
        bob.initialize()
        bob.registerDevice()
        val registered = network.server.devices.registration(BOB)?.publicKey

        val impostor = client(BOB) // another installation claiming Bob's address
        impostor.initialize()
        assertFailsWith<SecureMessageTransportException.DeviceRegistrationConflict> { impostor.registerDevice() }
        assertContentEquals(registered, network.server.devices.registration(BOB)?.publicKey, "never replaced")
        assertFailsWith<SecureMessageTransportException.AuthenticationFailed> { impostor.publishPreKeys() }
        assertEquals(0, network.server.preKeys.oneTimePreKeyCount(BOB))
    }

    @Test
    fun unregisteredDeviceCanNeitherPublishNorDrain() = runTest {
        val bob = client(BOB)
        bob.initialize()
        val publish = assertFailsWith<SecureMessageTransportException.AuthenticationFailed> { bob.publishPreKeys() }
        assertEquals(AuthenticationFailure.NOT_REGISTERED, publish.failure)
        assertNull(network.server.preKeys.consumePreKeyBundle(BOB))

        val envelope = EncryptedEnvelope(MessageId("m"), ALICE, BOB, payload = byteArrayOf(1))
        network.send(envelope)
        val drain = assertFailsWith<SecureMessageTransportException.AuthenticationFailed> { bob.receive() }
        assertEquals(AuthenticationFailure.NOT_REGISTERED, drain.failure)
        assertEquals(listOf(envelope.id), network.receive(BOB).map { it.id }, "mailbox untouched")
    }

    @Test
    fun registeredDevicesExchangeMessagesThroughAuthenticatedRequests() = runTest {
        val aliceStorage = InMemoryClientStorage()
        val alice = client(ALICE, aliceStorage)
        val bob = client(BOB)
        alice.initialize()
        bob.initialize()
        alice.registerDevice()
        bob.registerDevice()
        bob.publishPreKeys()
        assertEquals(3, network.server.preKeys.oneTimePreKeyCount(BOB))

        val sent = alice.send(BOB, "Hello Bob".encodeToByteArray()) // fetches Bob's bundle publicly
        val message = assertIs<ReceiveResult.Message>(bob.decrypt(bob.receive().single()))
        assertEquals("Hello Bob", message.plaintext.decodeToString())
        assertTrue(message.ackSent)
        assertEquals(listOf(sent.id), alice.pendingMessages(BOB).map { it.id })

        val ack = assertIs<ReceiveResult.Acknowledgement>(alice.decrypt(alice.receive().single()))
        assertEquals(sent.id, ack.id)
        assertTrue(ack.cleared)
        assertEquals(emptyList(), alice.pendingMessages(BOB))
        assertEquals(emptyList(), bob.receive())
    }

    @Test
    fun theSignerSignsOnlyForThisDeviceWithTheClockAndFreshNonces() = runTest {
        val storage = InMemoryClientStorage()
        val captured = mutableListOf<Pair<ServerRequest, RequestAuthentication>>()
        val recording = object : SecureMessageTransport by FakeNetwork() {
            override suspend fun receive(address: DeviceAddress, signer: ServerRequestSigner): List<EncryptedEnvelope> {
                val request = ServerRequest(address, "GET", ServerApiPaths.device(address, ServerApiPaths.MESSAGES), ByteArray(0))
                repeat(2) { captured += request to signer.sign(request) }
                val other = ServerRequest(ALICE, "GET", ServerApiPaths.device(ALICE, ServerApiPaths.MESSAGES), ByteArray(0))
                assertFailsWith<IllegalArgumentException> { signer.sign(other) }
                return emptyList()
            }
        }
        val bob = client(BOB, storage, recording)
        bob.initialize()
        clock.advanceBy(3.seconds)
        bob.receive()

        val publicKey = storage.deviceAuthentication.keyPair()!!.publicKey
        for ((request, authentication) in captured) {
            assertEquals(clock.now, authentication.timestamp)
            assertTrue(ServerRequestAuthentication.verify(publicKey, request, authentication))
        }
        assertNotEquals(captured[0].second.nonce, captured[1].second.nonce, "a fresh nonce per signature")
    }

    @Test
    fun failedKeyCreationRollsBackTheInitialization() = runTest {
        val storage = FailingClientStorage(InMemoryClientStorage())
        storage.failDeviceAuthenticationKeyStore = true
        assertFailsWith<StorageFailure> { client(BOB, storage).initialize() }
        assertNull(storage.identity.identity())
        assertNull(storage.deviceAuthentication.keyPair())
        assertNull(storage.preKeys.currentSignedPreKey())

        storage.failDeviceAuthenticationKeyStore = false
        client(BOB, storage).initialize()
        assertNotNull(storage.deviceAuthentication.keyPair())
    }

    @Test
    fun aLostKeyIsNeverRecreated() = runTest {
        val storage = LegacyAwareStorage(InMemoryClientStorage(), awaitsUpgradeKey = false)
        storage.identity.store(engine.createIdentity())

        assertFailsWith<SecureMessageClientException.InconsistentStorage> { client(BOB, storage).initialize() }
        assertNull(storage.deviceAuthentication.keyPair())
        assertNull(storage.preKeys.currentSignedPreKey(), "nothing else was written either")
        assertFailsWith<SecureMessageClientException.NotInitialized> { client(BOB, storage).registerDevice() }
    }

    @Test
    fun aPreMilestone12InstallationGetsItsFirstKeyOnce() = runTest {
        val storage = LegacyAwareStorage(InMemoryClientStorage(), awaitsUpgradeKey = true)
        val identity = engine.createIdentity()
        storage.identity.store(identity)

        client(BOB, storage).initialize()
        val keyPair = assertNotNull(storage.deviceAuthentication.keyPair())
        assertFalse(storage.deviceAuthentication.awaitsUpgradeKey())
        assertContentEquals(identity.privateKey, storage.identity.identity()?.privateKey)
        client(BOB, storage).initialize()
        assertContentEquals(keyPair.privateKey, storage.deviceAuthentication.keyPair()?.privateKey)
    }

    @Test
    fun anAuthenticationKeyWithoutIdentityIsInconsistent() = runTest {
        val storage = InMemoryClientStorage()
        storage.deviceAuthentication.store(engine.createDeviceAuthenticationKey())
        assertFailsWith<SecureMessageClientException.InconsistentStorage> { client(BOB, storage).initialize() }
        assertNull(storage.identity.identity())
    }

    /**
     * In-memory storage that reports [awaitsUpgradeKey] like an adapter with
     * pre-milestone-12 data would, until a key is stored.
     */
    private class LegacyAwareStorage(private val delegate: ClientStorage, private var awaitsUpgradeKey: Boolean) : ClientStorage by delegate {
        override val deviceAuthentication: DeviceAuthenticationKeyStore get() = view(delegate)

        override suspend fun <T> transaction(block: suspend ClientStorage.() -> T): T = delegate.transaction {
            val tx = this
            object : ClientStorage by tx {
                override val deviceAuthentication: DeviceAuthenticationKeyStore = view(tx)
            }.block()
        }

        private fun view(storage: ClientStorage) = object : DeviceAuthenticationKeyStore by storage.deviceAuthentication {
            override suspend fun store(keyPair: DeviceAuthenticationKeyPair) {
                storage.deviceAuthentication.store(keyPair)
                awaitsUpgradeKey = false
            }

            override suspend fun awaitsUpgradeKey(): Boolean = awaitsUpgradeKey
        }
    }
}
