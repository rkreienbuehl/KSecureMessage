package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyMessage
import dev.kreienbuehl.ksecuremessage.model.RatchetMessage
import dev.kreienbuehl.ksecuremessage.protocol.CiphertextMessageCodec
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.PreKeyFormat
import dev.kreienbuehl.ksecuremessage.protocol.ProtocolEngine
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
import kotlin.time.Duration.Companion.minutes

private const val TARGET = 3

/** Publication through [ServerBackedNetwork], which has the server's real prekey semantics. */
class PreKeyPublicationTest {
    private val engine: ProtocolEngine = KodiumProtocolEngine()
    private val storages = mutableListOf<TransactionTrackingStorage>()
    private var networkCalls = 0

    // Every network call checks that no client transaction is open.
    private val network = ServerBackedNetwork {
        networkCalls++
        assertTrue(storages.all { it.depth == 0 }, "network call inside a storage transaction")
    }

    private inner class Device(address: DeviceAddress) {
        val storage = TransactionTrackingStorage(InMemoryClientStorage()).also { storages += it }
        val client = SecureMessageClient(address, storage, engine, network, PreKeyConfiguration(oneTimePreKeyTarget = TARGET))

        suspend fun receiveText(): String = client.decryptRaw(network.receive(client.localAddress).single()).decodeToString()
    }

    private suspend fun device(address: DeviceAddress) = Device(address).also {
        it.client.initialize()
        it.client.registerDevice()
    }

    @Test
    fun publishFetchFirstContactAndReply() = runTest {
        val bob = device(BOB)
        bob.client.publishPreKeys()
        assertEquals(TARGET, network.server.preKeys.oneTimePreKeyCount(BOB))
        val alice = device(ALICE)

        alice.client.sendRaw(BOB, "Hello Bob".encodeToByteArray())
        assertEquals(TARGET - 1, network.server.preKeys.oneTimePreKeyCount(BOB), "the server consumed one")
        val first = network.receive(BOB).single()
        val preKeyMessage = assertIs<PreKeyMessage>(CiphertextMessageCodec.decode(first.payload))
        assertEquals(OneTimePreKeyId(0), preKeyMessage.oneTimePreKeyId, "lowest ID first")
        // Handed out by the server, but Bob keeps the private key until the message arrives.
        assertNotNull(bob.storage.preKeys.oneTimePreKey(OneTimePreKeyId(0)))

        assertEquals("Hello Bob", bob.client.decryptRaw(first).decodeToString())
        assertNotNull(bob.storage.sessions.load(ALICE))
        assertNull(bob.storage.preKeys.oneTimePreKey(OneTimePreKeyId(0)))

        bob.client.sendRaw(ALICE, "Hello Alice".encodeToByteArray())
        val reply = network.receive(ALICE).single()
        assertIs<RatchetMessage>(CiphertextMessageCodec.decode(reply.payload))
        assertEquals("Hello Alice", alice.client.decryptRaw(reply).decodeToString())

        alice.client.sendRaw(BOB, "again".encodeToByteArray())
        assertEquals("again", bob.receiveText())
        assertTrue(networkCalls >= 7)

        // Each side pinned the other's published identity key.
        assertContentEquals(bob.storage.identity.identity()?.publicKey, alice.client.remoteIdentityKey(BOB))
        assertContentEquals(alice.storage.identity.identity()?.publicKey, bob.client.remoteIdentityKey(ALICE))
    }

    @Test
    fun republishingDoesNotHandOutAConsumedOneTimePreKeyAgain() = runTest {
        val bob = device(BOB)
        bob.client.publishPreKeys()
        val alice = device(ALICE)
        val carol = device(CAROL)

        alice.client.sendRaw(BOB, "from Alice".encodeToByteArray())
        // Bob still holds private #0 and uploads it again before Alice's message arrives.
        bob.client.publishPreKeys()
        carol.client.sendRaw(BOB, "from Carol".encodeToByteArray())

        val (fromAlice, fromCarol) = network.receive(BOB)
        val carolMessage = assertIs<PreKeyMessage>(CiphertextMessageCodec.decode(fromCarol.payload))
        assertEquals(OneTimePreKeyId(1), carolMessage.oneTimePreKeyId)
        assertEquals("from Alice", bob.client.decryptRaw(fromAlice).decodeToString())
        assertEquals("from Carol", bob.client.decryptRaw(fromCarol).decodeToString())
    }

    @Test
    fun publishingAgainIsIdempotent() = runTest {
        val bob = device(BOB)
        repeat(3) { bob.client.publishPreKeys() }
        assertEquals(TARGET, network.server.preKeys.oneTimePreKeyCount(BOB))
    }

    @Test
    fun exhaustedServerInventoryFallsBackToNoOneTimePreKey() = runTest {
        val bob = device(BOB)
        bob.client.publishPreKeys()
        repeat(TARGET) { network.server.preKeys.consumePreKeyBundle(BOB) }
        val alice = device(ALICE)

        alice.client.sendRaw(BOB, "Hello Bob".encodeToByteArray())
        val first = network.receive(BOB).single()
        assertNull(assertIs<PreKeyMessage>(CiphertextMessageCodec.decode(first.payload)).oneTimePreKeyId)
        assertEquals("Hello Bob", bob.client.decryptRaw(first).decodeToString())
    }

    @Test
    fun rotatedSignedPreKeyIsServedAfterPublishing() = runTest {
        val bob = device(BOB)
        bob.client.publishPreKeys()
        val rotated = bob.client.rotateSignedPreKey()
        assertEquals(0, network.server.preKeys.consumePreKeyBundle(BOB)?.signedPreKey?.id?.value, "rotation is local only")

        bob.client.publishPreKeys()
        val bundle = assertNotNull(network.server.preKeys.consumePreKeyBundle(BOB))
        assertEquals(rotated.id, bundle.signedPreKey.id)
        assertContentEquals(rotated.signature, bundle.signedPreKey.signature)

        val alice = device(ALICE)
        alice.client.sendRaw(BOB, "after rotation".encodeToByteArray())
        assertEquals("after rotation", bob.receiveText())
    }

    @Test
    fun fetchingAnUnknownDeviceFails() = runTest {
        val alice = device(ALICE)
        assertFailsWith<SecureMessageTransportException.DeviceNotFound> {
            alice.client.sendRaw(BOB, "nobody home".encodeToByteArray())
        }
        assertNull(alice.storage.sessions.load(BOB))
    }

    @Test
    fun publishingBeforeInitializeFails() = runTest {
        val bob = Device(BOB)
        assertFailsWith<SecureMessageClientException.NotInitialized> { bob.client.publishPreKeys() }
        assertEquals(0, networkCalls)
    }

    @Test
    fun onlyPublicMaterialIsPublished() = runTest {
        val recording = FakeNetwork()
        val storage = InMemoryClientStorage()
        val bob = SecureMessageClient(BOB, storage, engine, recording, PreKeyConfiguration(oneTimePreKeyTarget = TARGET))
        bob.initialize()
        bob.publishPreKeys()

        val publication = recording.publications.single()
        val identity = assertNotNull(storage.identity.identity())
        val signedPreKey = assertNotNull(storage.preKeys.currentSignedPreKey())
        assertEquals(BOB, publication.address)
        assertContentEquals(identity.publicKey, publication.identityKey)
        assertEquals(signedPreKey.id, publication.signedPreKey.id)
        assertEquals((0 until TARGET).toList(), publication.oneTimePreKeys.map { it.id.value })
        PreKeyFormat.validate(publication)

        val privateKeys = listOf(identity.privateKey, signedPreKey.privateKey) +
            publication.oneTimePreKeys.map { assertNotNull(storage.preKeys.oneTimePreKey(it.id)).privateKey }
        val published = listOf(publication.identityKey, publication.signedPreKey.publicKey, publication.signedPreKey.signature) +
            publication.oneTimePreKeys.map { it.publicKey }
        for (value in published) {
            assertFalse(privateKeys.any { it.contentEquals(value) }, "no private key is published")
        }
    }

    // Creates more than MAX_ONE_TIME_PRE_KEYS_PER_PUBLICATION key pairs: past
    // runTest's 60 s default on slow hosted Apple runners (3 cores).
    @Test
    fun largeInventoriesArePublishedInBatches() = runTest(timeout = 10.minutes) {
        val recording = FakeNetwork()
        val max = PreKeyFormat.MAX_ONE_TIME_PRE_KEYS_PER_PUBLICATION
        val bob = SecureMessageClient(BOB, InMemoryClientStorage(), engine, recording, PreKeyConfiguration(oneTimePreKeyTarget = max + 1))
        bob.initialize()
        bob.publishPreKeys()

        assertEquals(listOf(max, 1), recording.publications.map { it.oneTimePreKeys.size })
        assertEquals(1, recording.publications.map { it.signedPreKey.id }.toSet().size)
    }
}
