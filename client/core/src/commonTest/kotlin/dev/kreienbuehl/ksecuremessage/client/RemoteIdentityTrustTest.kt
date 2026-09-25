package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyMessage
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.CiphertextMessageCodec
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.ProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.ProtocolException
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage
import dev.kreienbuehl.ksecuremessage.storage.RemoteIdentityStore
import dev.kreienbuehl.ksecuremessage.storage.client.inmemory.InMemoryClientStorage
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.yield
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Trust on first use: the first identity key that sets up a session with a
 * device is pinned, a different one later is rejected and changes nothing.
 * Every alternate identity here is a real, valid one, so the tests exercise
 * the pin and not signature or decryption checks.
 */
class RemoteIdentityTrustTest {
    private val engine: ProtocolEngine = KodiumProtocolEngine()
    private val network = FakeNetwork()

    private inner class Device(address: DeviceAddress, wrap: (ClientStorage) -> ClientStorage = { it }) {
        val storage = InMemoryClientStorage()
        val failing = FailingClientStorage(storage)
        val client = SecureMessageClient(address, wrap(failing), engine, network, PreKeyConfiguration(oneTimePreKeyTarget = 3))

        suspend fun identityKey(): ByteArray = assertNotNull(storage.identity.identity()).publicKey

        suspend fun receiveAll(): List<EncryptedEnvelope> = network.receive(client.localAddress)

        suspend fun decryptText(envelope: EncryptedEnvelope) = client.decryptRaw(envelope).decodeToString()
    }

    private suspend fun device(
        address: DeviceAddress,
        publishOneTimePreKey: Boolean = true,
        wrap: (ClientStorage) -> ClientStorage = { it },
    ) = Device(address, wrap).also {
        it.client.initialize()
        network.publish(it.client, publishOneTimePreKey)
    }

    // Initiator side

    @Test
    fun firstValidBundlePinsTheRemoteIdentity() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        assertNull(alice.client.remoteIdentityKey(BOB))

        alice.client.sendRaw(BOB, "Hello Bob".encodeToByteArray())
        assertContentEquals(bob.identityKey(), alice.client.remoteIdentityKey(BOB))
        assertNotNull(alice.storage.sessions.load(BOB))

        // A new session with the same identity is accepted.
        alice.storage.sessions.remove(BOB)
        network.publish(bob.client)
        alice.client.sendRaw(BOB, "Again".encodeToByteArray())
        assertNotNull(alice.storage.sessions.load(BOB))
        assertContentEquals(bob.identityKey(), alice.client.remoteIdentityKey(BOB))
    }

    @Test
    fun invalidBundlesPinNothing() = runTest {
        val alice = device(ALICE)
        device(BOB)
        val valid = network.bundles.getValue(BOB)

        network.bundles[BOB] = valid.copy(identityKey = valid.identityKey.copyOf(valid.identityKey.size - 1))
        assertFailsWith<ProtocolException.InvalidPreKeyBundle> { alice.client.sendRaw(BOB, byteArrayOf(1)) }

        val signature = valid.signedPreKey.signature.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        network.bundles[BOB] = valid.copy(signedPreKey = valid.signedPreKey.copy(signature = signature))
        assertFailsWith<ProtocolException.InvalidSignature> { alice.client.sendRaw(BOB, byteArrayOf(1)) }

        // A valid bundle for another device, served for BOB.
        network.bundles[BOB] = network.bundles.getValue(ALICE)
        assertFailsWith<ProtocolException.InvalidPreKeyBundle> { alice.client.ensureSession(BOB) }

        assertNull(alice.client.remoteIdentityKey(BOB))
        assertNull(alice.storage.sessions.load(BOB))
        assertNull(alice.client.remoteIdentityKey(ALICE))

        network.bundles[BOB] = valid
        alice.client.sendRaw(BOB, byteArrayOf(1))
        assertContentEquals(valid.identityKey, alice.client.remoteIdentityKey(BOB))
    }

    @Test
    fun sessionStoreFailureLeavesTheIdentityUnpinned() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)

        alice.failing.failSessionStore = true
        assertFailsWith<StorageFailure> { alice.client.sendRaw(BOB, byteArrayOf(1)) }
        assertFailsWith<StorageFailure> { alice.client.ensureSession(BOB) }
        assertNull(alice.client.remoteIdentityKey(BOB))
        assertNull(alice.storage.sessions.load(BOB))

        alice.failing.failSessionStore = false
        alice.client.sendRaw(BOB, byteArrayOf(1))
        assertContentEquals(bob.identityKey(), alice.client.remoteIdentityKey(BOB))
    }

    @Test
    fun pinFailureLeavesNoSession() = runTest {
        val alice = device(ALICE)
        device(BOB)

        alice.failing.failRemoteIdentityStore = true
        assertFailsWith<StorageFailure> { alice.client.sendRaw(BOB, byteArrayOf(1)) }
        assertNull(alice.storage.sessions.load(BOB))
        assertNull(alice.client.remoteIdentityKey(BOB))
    }

    @Test
    fun changedRemoteIdentityIsRejectedByTheInitiator() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        alice.client.sendRaw(BOB, "Hello Bob".encodeToByteArray())
        val pinned = bob.identityKey()

        // The server now serves a valid bundle of another identity for BOB.
        alice.storage.sessions.remove(BOB)
        val impostor = device(BOB)
        assertFalse(pinned.contentEquals(impostor.identityKey()))

        val error = assertFailsWith<SecureMessageClientException.IdentityChanged> {
            alice.client.sendRaw(BOB, "secret".encodeToByteArray())
        }
        assertEquals(BOB, error.address)
        assertEquals("Remote identity changed for $BOB", error.message)
        assertFailsWith<SecureMessageClientException.IdentityChanged> { alice.client.ensureSession(BOB) }

        assertContentEquals(pinned, alice.client.remoteIdentityKey(BOB))
        assertNull(alice.storage.sessions.load(BOB), "no replacement session")
    }

    // Responder side

    @Test
    fun firstContactPinsTheSenderAndRepeatedPreKeyMessagesAreAccepted() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)

        alice.client.sendRaw(BOB, "one".encodeToByteArray())
        alice.client.sendRaw(BOB, "two".encodeToByteArray())
        val (first, second) = bob.receiveAll()
        assertIs<PreKeyMessage>(CiphertextMessageCodec.decode(second.payload))

        assertEquals("one", bob.decryptText(first))
        assertContentEquals(alice.identityKey(), bob.client.remoteIdentityKey(ALICE))
        assertEquals("two", bob.decryptText(second))
        assertContentEquals(alice.identityKey(), bob.client.remoteIdentityKey(ALICE))
    }

    @Test
    fun forgedFirstContactPinsNothing() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val mallory = device(CAROL)
        alice.client.sendRaw(BOB, "Hello Bob".encodeToByteArray())
        val envelope = bob.receiveAll().single()

        // Mallory claims her own valid identity key in Alice's message.
        val message = CiphertextMessageCodec.decode(envelope.payload) as PreKeyMessage
        val forged = envelope.copy(payload = CiphertextMessageCodec.encode(message.copy(identityKey = mallory.identityKey())))

        for (bad in listOf(envelope.tampered(), forged)) {
            assertFailsWith<ProtocolException> { bob.client.decryptRaw(bad) }
            assertNull(bob.client.remoteIdentityKey(ALICE))
            assertNull(bob.storage.sessions.load(ALICE))
            assertNotNull(bob.storage.preKeys.oneTimePreKey(OneTimePreKeyId(0)))
        }

        assertEquals("Hello Bob", bob.decryptText(envelope))
        assertContentEquals(alice.identityKey(), bob.client.remoteIdentityKey(ALICE))
    }

    @Test
    fun changedSenderIdentityIsRejectedAndChangesNothing() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        alice.client.sendRaw(BOB, "Hello Bob".encodeToByteArray())
        bob.decryptText(bob.receiveAll().single())
        val pinned = alice.identityKey()
        val session = assertNotNull(bob.storage.sessions.load(ALICE)).state

        // Another valid identity for the same address, using Bob's next one-time prekey.
        network.publish(bob.client)
        val impostor = device(ALICE)
        impostor.client.sendRaw(BOB, "It's me".encodeToByteArray())
        val envelope = bob.receiveAll().single()
        val oneTimePreKeyId = assertNotNull((CiphertextMessageCodec.decode(envelope.payload) as PreKeyMessage).oneTimePreKeyId)
        val oneTimePreKeys = bob.storage.preKeys.oneTimePreKeyCount()

        val error = assertFailsWith<SecureMessageClientException.IdentityChanged> { bob.client.decryptRaw(envelope) }
        assertEquals(ALICE, error.address)
        assertContentEquals(pinned, bob.client.remoteIdentityKey(ALICE))
        assertContentEquals(session, bob.storage.sessions.load(ALICE)?.state, "session unchanged")
        assertNotNull(bob.storage.preKeys.oneTimePreKey(oneTimePreKeyId))
        assertEquals(oneTimePreKeys, bob.storage.preKeys.oneTimePreKeyCount())

        // Without a session the pin still decides.
        bob.storage.sessions.remove(ALICE)
        assertFailsWith<SecureMessageClientException.IdentityChanged> { bob.client.decryptRaw(envelope) }
        assertNull(bob.storage.sessions.load(ALICE))
        assertNotNull(bob.storage.preKeys.oneTimePreKey(oneTimePreKeyId))
        assertContentEquals(pinned, bob.client.remoteIdentityKey(ALICE))
    }

    @Test
    fun devicesOfOneUserArePinnedSeparately() = runTest {
        val bobPhone = DeviceAddress(UserId("bob"), DeviceId("phone"))
        val alice = device(ALICE)
        val laptop = device(BOB)
        val phone = device(bobPhone)
        assertFalse(laptop.identityKey().contentEquals(phone.identityKey()))

        alice.client.sendRaw(BOB, "to laptop".encodeToByteArray())
        alice.client.sendRaw(bobPhone, "to phone".encodeToByteArray())
        assertContentEquals(laptop.identityKey(), alice.client.remoteIdentityKey(BOB))
        assertContentEquals(phone.identityKey(), alice.client.remoteIdentityKey(bobPhone))

        assertEquals("to laptop", laptop.decryptText(laptop.receiveAll().single()))
        assertEquals("to phone", phone.decryptText(phone.receiveAll().single()))
        assertContentEquals(alice.identityKey(), laptop.client.remoteIdentityKey(ALICE))
        assertContentEquals(alice.identityKey(), phone.client.remoteIdentityKey(ALICE))
    }

    @Test
    fun concurrentContradictoryFirstContactsCannotBothBePinned() = runTest {
        // Suspends between the pin lookup and the rest of the transaction, so
        // an unserialized implementation would let both contacts pass the check.
        var hook: YieldAfterPinLookup? = null
        val bob = device(BOB, publishOneTimePreKey = false) { YieldAfterPinLookup(it).also { w -> hook = w } }
        val first = device(ALICE)
        first.client.sendRaw(BOB, "first".encodeToByteArray())
        val second = device(ALICE)
        second.client.sendRaw(BOB, "second".encodeToByteArray())
        val envelopes = bob.receiveAll()
        assertEquals(2, envelopes.size)

        val results = envelopes.map { async { runCatching { bob.decryptText(it) } } }.awaitAll()

        assertTrue(assertNotNull(hook).lookups >= 2, "both decrypts looked up the pin")
        assertEquals(1, results.count { it.isSuccess })
        val winner = if (results[0].isSuccess) first else second
        assertIs<SecureMessageClientException.IdentityChanged>(results.single { it.isFailure }.exceptionOrNull())
        assertContentEquals(winner.identityKey(), bob.client.remoteIdentityKey(ALICE))
    }

    // Sessions from before identities were pinned

    @Test
    fun sessionWithoutPinKeepsWorkingForRatchetMessages() = runTest {
        val storage = InMemoryClientStorage()
        val legacyBob = SecureMessageClient(BOB, NoPinning(storage), engine, network, PreKeyConfiguration(oneTimePreKeyTarget = 3))
        legacyBob.initialize()
        network.publish(legacyBob)
        val alice = device(ALICE)

        alice.client.sendRaw(BOB, "Hello Bob".encodeToByteArray())
        legacyBob.decryptRaw(network.receive(BOB).single())
        legacyBob.sendRaw(ALICE, "Hello Alice".encodeToByteArray())
        alice.decryptText(alice.receiveAll().single())
        assertNull(storage.remoteIdentities.identityKey(ALICE))

        val bob = SecureMessageClient(BOB, storage, engine, network)
        alice.client.sendRaw(BOB, "Ratchet".encodeToByteArray())
        assertEquals("Ratchet", bob.decryptRaw(network.receive(BOB).single()).decodeToString())
        assertNull(bob.remoteIdentityKey(ALICE), "no pin invented from routing metadata")
    }

    @Test
    fun sessionWithoutPinIsPinnedByTheNextPreKeyMessage() = runTest {
        val storage = InMemoryClientStorage()
        val legacyBob = SecureMessageClient(BOB, NoPinning(storage), engine, network, PreKeyConfiguration(oneTimePreKeyTarget = 3))
        legacyBob.initialize()
        network.publish(legacyBob)
        val alice = device(ALICE)

        alice.client.sendRaw(BOB, "one".encodeToByteArray())
        alice.client.sendRaw(BOB, "two".encodeToByteArray())
        val (first, second) = network.receive(BOB)
        legacyBob.decryptRaw(first)
        assertNull(storage.remoteIdentities.identityKey(ALICE))

        val bob = SecureMessageClient(BOB, storage, engine, network)
        assertEquals("two", bob.decryptRaw(second).decodeToString())
        assertContentEquals(alice.identityKey(), bob.remoteIdentityKey(ALICE))
    }

    /** Stands in for a client from before pinning: pin writes are dropped. */
    private class NoPinning(private val delegate: ClientStorage) : ClientStorage by delegate {
        override suspend fun <T> transaction(block: suspend ClientStorage.() -> T): T = delegate.transaction {
            val tx = this
            object : ClientStorage by tx {
                override val remoteIdentities: RemoteIdentityStore = object : RemoteIdentityStore by tx.remoteIdentities {
                    override suspend fun store(address: DeviceAddress, identityKey: ByteArray) = Unit
                }
            }.block()
        }
    }

    /** Yields to other coroutines after every pin lookup inside a transaction. */
    private class YieldAfterPinLookup(private val delegate: ClientStorage) : ClientStorage by delegate {
        var lookups = 0
            private set

        override suspend fun <T> transaction(block: suspend ClientStorage.() -> T): T = delegate.transaction {
            val tx = this
            object : ClientStorage by tx {
                override val remoteIdentities: RemoteIdentityStore = object : RemoteIdentityStore by tx.remoteIdentities {
                    override suspend fun identityKey(address: DeviceAddress): ByteArray? =
                        tx.remoteIdentities.identityKey(address).also {
                            lookups++
                            yield()
                        }
                }
            }.block()
        }
    }
}
