package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.MessageId
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.RatchetMessage
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.protocol.CiphertextMessageCodec
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.ProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.ProtocolException
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage
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
import kotlin.time.Clock

private const val TARGET = 3

class ClientLifecycleTest {
    private val engine: ProtocolEngine = KodiumProtocolEngine()
    private val network = FakeNetwork()

    private fun client(address: DeviceAddress, storage: ClientStorage, target: Int = TARGET) =
        SecureMessageClient(address, storage, engine, network, PreKeyConfiguration(oneTimePreKeyTarget = target))

    private suspend fun initializedClient(address: DeviceAddress, storage: ClientStorage = InMemoryClientStorage()) =
        client(address, storage).also {
            it.initialize()
            network.publish(it)
        }

    private suspend fun SecureMessageClient.receiveText(): String =
        decryptRaw(network.receive(localAddress).single()).decodeToString()

    private suspend fun ClientStorage.oneTimePreKeyIds() = preKeys.publicOneTimePreKeys().map { it.id.value }

    @Test
    fun initializeCreatesIdentityAndPreKeys() = runTest {
        val storage = InMemoryClientStorage()
        client(BOB, storage).initialize()

        assertNotNull(storage.identity.identity())
        assertEquals(SignedPreKeyId(0), storage.preKeys.currentSignedPreKey()?.id)
        assertEquals(listOf(0, 1, 2), storage.oneTimePreKeyIds())
    }

    @Test
    fun initializeIsIdempotent() = runTest {
        val storage = InMemoryClientStorage()
        val client = client(BOB, storage)
        client.initialize()
        val identity = assertNotNull(storage.identity.identity())
        val bundle = client.currentPreKeyBundle()
        val oneTimePreKeys = client.publicOneTimePreKeys()

        client.initialize()
        client.initialize()

        val again = assertNotNull(storage.identity.identity())
        assertContentEquals(identity.publicKey, again.publicKey)
        assertContentEquals(identity.privateKey, again.privateKey)
        assertEquals(bundle.signedPreKey.id, client.currentPreKeyBundle().signedPreKey.id)
        assertContentEquals(bundle.signedPreKey.publicKey, client.currentPreKeyBundle().signedPreKey.publicKey)
        assertEquals(oneTimePreKeys.map { it.id }, client.publicOneTimePreKeys().map { it.id })
        assertEquals(OneTimePreKeyId(2), storage.preKeys.highestOneTimePreKeyId())
    }

    @Test
    fun operationsBeforeInitializeFailWithoutWriting() = runTest {
        val storage = InMemoryClientStorage()
        val client = client(BOB, storage)
        val envelope = EncryptedEnvelope(
            MessageId("m1"),
            ALICE,
            BOB,
            payload = CiphertextMessageCodec.encode(RatchetMessage(ByteArray(80))),
        )

        assertFailsWith<SecureMessageClientException.NotInitialized> { client.currentPreKeyBundle() }
        assertFailsWith<SecureMessageClientException.NotInitialized> { client.publicOneTimePreKeys() }
        assertFailsWith<SecureMessageClientException.NotInitialized> { client.rotateSignedPreKey() }
        assertFailsWith<SecureMessageClientException.NotInitialized> { client.ensureSession(ALICE) }
        assertFailsWith<SecureMessageClientException.NotInitialized> { client.sendRaw(ALICE, byteArrayOf(1)) }
        assertFailsWith<SecureMessageClientException.NotInitialized> { client.decryptRaw(envelope) }

        assertNull(storage.identity.identity())
        assertNull(storage.preKeys.highestSignedPreKeyId())
        assertNull(storage.preKeys.highestOneTimePreKeyId())
    }

    @Test
    fun restartKeepsIdentityPreKeysAndSessions() = runTest {
        val storage = InMemoryClientStorage()
        val alice = initializedClient(ALICE)
        val bob = initializedClient(BOB, storage)
        val identity = assertNotNull(storage.identity.identity())

        alice.sendRaw(BOB, "Hello Bob".encodeToByteArray())
        assertEquals("Hello Bob", bob.receiveText())
        assertEquals(listOf(1, 2), storage.oneTimePreKeyIds(), "one-time prekey 0 was consumed")

        // Same storage, new client: the application restarted.
        val restarted = client(BOB, storage)
        restarted.initialize()

        val after = assertNotNull(storage.identity.identity())
        assertContentEquals(identity.publicKey, after.publicKey)
        assertContentEquals(identity.privateKey, after.privateKey)
        assertEquals(SignedPreKeyId(0), restarted.currentPreKeyBundle().signedPreKey.id)
        assertEquals(listOf(1, 2, 3), storage.oneTimePreKeyIds(), "only the consumed key is replaced, with a new ID")

        restarted.sendRaw(ALICE, "Hello Alice".encodeToByteArray())
        assertEquals("Hello Alice", alice.receiveText())
        alice.sendRaw(BOB, "Still there?".encodeToByteArray())
        assertEquals("Still there?", restarted.receiveText())
    }

    @Test
    fun missingSignedPreKeyIsCreatedForTheExistingIdentity() = runTest {
        val storage = InMemoryClientStorage()
        val identity = engine.createIdentity()
        storage.identity.store(identity)
        storage.deviceAuthentication.store(engine.createDeviceAuthenticationKey())

        val bob = client(BOB, storage)
        bob.initialize()

        assertContentEquals(identity.privateKey, storage.identity.identity()?.privateKey)
        val bundle = bob.currentPreKeyBundle()
        assertContentEquals(identity.publicKey, bundle.identityKey)
        // Verifies the signature against the identity key.
        engine.initiateSession(engine.createIdentity(), ALICE, bundle)
    }

    @Test
    fun lowInventoryIsRefilledWithNewIdsOnly() = runTest {
        val storage = InMemoryClientStorage()
        val client = client(BOB, storage)
        client.initialize()
        val identity = assertNotNull(storage.identity.identity())
        val signedPreKey = assertNotNull(storage.preKeys.currentSignedPreKey())

        storage.preKeys.removeOneTimePreKey(OneTimePreKeyId(0))
        storage.preKeys.removeOneTimePreKey(OneTimePreKeyId(2))
        client.initialize()

        assertEquals(listOf(1, 3, 4), storage.oneTimePreKeyIds())
        assertContentEquals(identity.privateKey, storage.identity.identity()?.privateKey)
        assertEquals(signedPreKey.id, storage.preKeys.currentSignedPreKey()?.id)
        assertContentEquals(signedPreKey.privateKey, storage.preKeys.currentSignedPreKey()?.privateKey)
    }

    @Test
    fun oneTimePreKeyIdExhaustionFailsAndWritesNothing() = runTest {
        val storage = InMemoryClientStorage()
        val identity = engine.createIdentity()
        storage.identity.store(identity)
        storage.deviceAuthentication.store(engine.createDeviceAuthenticationKey())
        storage.preKeys.storeCurrentSignedPreKey(engine.createSignedPreKey(identity, SignedPreKeyId(0)), Clock.System.now())
        storage.preKeys.storeOneTimePreKeys(engine.createOneTimePreKeys(OneTimePreKeyId(Int.MAX_VALUE - 1), 1))

        // Two more are needed but only Int.MAX_VALUE is left.
        assertFailsWith<SecureMessageClientException.PreKeyIdsExhausted> { client(BOB, storage, target = 3).initialize() }
        assertEquals(listOf(Int.MAX_VALUE - 1), storage.oneTimePreKeyIds())

        client(BOB, storage, target = 2).initialize()
        assertEquals(listOf(Int.MAX_VALUE - 1, Int.MAX_VALUE), storage.oneTimePreKeyIds())
        storage.preKeys.removeOneTimePreKey(OneTimePreKeyId(Int.MAX_VALUE))
        assertFailsWith<SecureMessageClientException.PreKeyIdsExhausted> { client(BOB, storage, target = 2).initialize() }
    }

    @Test
    fun signedPreKeyIdExhaustionFails() = runTest {
        val storage = InMemoryClientStorage()
        val identity = engine.createIdentity()
        storage.identity.store(identity)
        storage.deviceAuthentication.store(engine.createDeviceAuthenticationKey())
        storage.preKeys.storeCurrentSignedPreKey(engine.createSignedPreKey(identity, SignedPreKeyId(Int.MAX_VALUE)), Clock.System.now())
        val client = client(BOB, storage)
        client.initialize()

        assertFailsWith<SecureMessageClientException.PreKeyIdsExhausted> { client.rotateSignedPreKey() }
        assertEquals(SignedPreKeyId(Int.MAX_VALUE), client.currentPreKeyBundle().signedPreKey.id)
    }

    @Test
    fun prekeysWithoutIdentityAreRefused() = runTest {
        val storage = InMemoryClientStorage()
        storage.preKeys.storeCurrentSignedPreKey(engine.createSignedPreKey(engine.createIdentity(), SignedPreKeyId(0)), Clock.System.now())

        assertFailsWith<SecureMessageClientException.InconsistentStorage> { client(BOB, storage).initialize() }
        assertNull(storage.identity.identity())
        assertEquals(0, storage.preKeys.oneTimePreKeyCount())
    }

    @Test
    fun rotationKeepsTheOldSignedPreKeyForInFlightMessages() = runTest {
        val storage = InMemoryClientStorage()
        val alice = initializedClient(ALICE)
        val carol = initializedClient(CAROL)
        val bob = initializedClient(BOB, storage)

        alice.sendRaw(BOB, "sent before rotation".encodeToByteArray())
        val rotated = bob.rotateSignedPreKey()
        assertEquals(SignedPreKeyId(1), rotated.id)
        assertEquals(rotated.id, bob.currentPreKeyBundle().signedPreKey.id)
        assertNotNull(storage.preKeys.signedPreKey(SignedPreKeyId(0)))

        assertEquals("sent before rotation", bob.receiveText())

        network.bundles[BOB] = bob.currentPreKeyBundle()
        carol.sendRaw(BOB, "sent after rotation".encodeToByteArray())
        assertEquals("sent after rotation", bob.receiveText())
    }

    @Test
    fun bundleHoldsPublicDataOnly() = runTest {
        val storage = InMemoryClientStorage()
        val bob = client(BOB, storage)
        bob.initialize()
        val identity = assertNotNull(storage.identity.identity())
        val signedPreKey = assertNotNull(storage.preKeys.currentSignedPreKey())

        val bundle = bob.currentPreKeyBundle()
        assertEquals(BOB, bundle.address)
        assertContentEquals(identity.publicKey, bundle.identityKey)
        assertEquals(signedPreKey.id, bundle.signedPreKey.id)
        assertContentEquals(signedPreKey.publicKey, bundle.signedPreKey.publicKey)
        assertContentEquals(signedPreKey.signature, bundle.signedPreKey.signature)
        assertNull(bundle.oneTimePreKey, "the server picks one-time prekeys")

        val published = bob.publicOneTimePreKeys()
        assertEquals(listOf(0, 1, 2), published.map { it.id.value })
        for (key in published) {
            assertContentEquals(storage.preKeys.oneTimePreKey(key.id)?.publicKey, key.publicKey)
        }

        val privateKeys = listOf(identity.privateKey, signedPreKey.privateKey) +
            published.map { assertNotNull(storage.preKeys.oneTimePreKey(it.id)).privateKey }
        val publicValues = listOf(bundle.identityKey, bundle.signedPreKey.publicKey, bundle.signedPreKey.signature) +
            published.map { it.publicKey }
        for (value in publicValues) {
            assertFalse(privateKeys.any { it.contentEquals(value) }, "no private key is published")
        }

        engine.initiateSession(engine.createIdentity(), ALICE, bundle)
        val badSignature = bundle.signedPreKey.signature.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertFailsWith<ProtocolException.InvalidSignature> {
            engine.initiateSession(
                engine.createIdentity(),
                ALICE,
                bundle.copy(signedPreKey = bundle.signedPreKey.copy(signature = badSignature)),
            )
        }
    }

    @Test
    fun consumedOneTimePreKeyIdIsNeverPublishedAgain() = runTest {
        val storage = InMemoryClientStorage()
        val alice = initializedClient(ALICE)
        val bob = initializedClient(BOB, storage)
        val consumed = assertNotNull(network.bundles.getValue(BOB).oneTimePreKey).id

        alice.sendRaw(BOB, "Hello Bob".encodeToByteArray())
        bob.receiveText()
        repeat(3) { bob.initialize() }

        assertTrue(bob.publicOneTimePreKeys().none { it.id == consumed })
        assertNull(storage.preKeys.oneTimePreKey(consumed))
        assertEquals(TARGET, storage.preKeys.oneTimePreKeyCount())
    }
}
