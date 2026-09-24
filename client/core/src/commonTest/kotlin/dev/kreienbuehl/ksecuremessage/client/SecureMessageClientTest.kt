package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.MessageId
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyMessage
import dev.kreienbuehl.ksecuremessage.model.RatchetMessage
import dev.kreienbuehl.ksecuremessage.protocol.CiphertextMessageCodec
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.ProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.ProtocolException
import dev.kreienbuehl.ksecuremessage.storage.inmemory.InMemoryClientStorage
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull

private class Device(val client: SecureMessageClient, val storage: InMemoryClientStorage)

class SecureMessageClientTest {
    private val engine: ProtocolEngine = KodiumProtocolEngine()
    private val network = FakeNetwork()

    private suspend fun device(address: DeviceAddress, publishOneTimePreKey: Boolean = true): Device {
        val storage = InMemoryClientStorage()
        val client = SecureMessageClient(address, storage, engine, network, PreKeyConfiguration(oneTimePreKeyTarget = 2))
        client.initialize()
        network.publish(client, publishOneTimePreKey)
        return Device(client, storage)
    }

    private suspend fun Device.receiveOne(): EncryptedEnvelope = network.receive(client.localAddress).single()

    private suspend fun Device.decryptText(envelope: EncryptedEnvelope) = client.decrypt(envelope).decodeToString()

    @Test
    fun aliceAndBobExchangeMessagesThroughClients() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)

        alice.client.send(BOB, "Hello Bob".encodeToByteArray())
        val first = bob.receiveOne()
        assertEquals(ALICE, first.sender)
        assertIs<PreKeyMessage>(CiphertextMessageCodec.decode(first.payload))
        assertNull(bob.storage.sessions.load(ALICE))

        assertEquals("Hello Bob", bob.decryptText(first))
        assertNotNull(bob.storage.sessions.load(ALICE))
        assertNull(bob.storage.preKeys.oneTimePreKey(OneTimePreKeyId(0)), "consumed one-time prekey is removed")
        assertNotNull(bob.storage.preKeys.oneTimePreKey(OneTimePreKeyId(1)))

        bob.client.send(ALICE, "Hello Alice".encodeToByteArray())
        val reply = alice.receiveOne()
        assertIs<RatchetMessage>(CiphertextMessageCodec.decode(reply.payload))
        assertEquals("Hello Alice", alice.decryptText(reply))

        // Alice has seen a reply, so she stops sending prekey messages.
        alice.client.send(BOB, "Still there?".encodeToByteArray())
        val third = bob.receiveOne()
        assertIs<RatchetMessage>(CiphertextMessageCodec.decode(third.payload))
        assertEquals("Still there?", bob.decryptText(third))
    }

    @Test
    fun repeatedPreKeyMessagesUseTheAcceptedSession() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)

        alice.client.send(BOB, "one".encodeToByteArray())
        alice.client.send(BOB, "two".encodeToByteArray())
        val (first, second) = network.receive(BOB)
        assertIs<PreKeyMessage>(CiphertextMessageCodec.decode(second.payload))

        assertEquals("one", bob.decryptText(first))
        assertEquals("two", bob.decryptText(second))
    }

    @Test
    fun sessionWithoutOneTimePreKey() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB, publishOneTimePreKey = false)

        alice.client.send(BOB, "Hello Bob".encodeToByteArray())
        val first = bob.receiveOne()
        assertNull(assertIs<PreKeyMessage>(CiphertextMessageCodec.decode(first.payload)).oneTimePreKeyId)
        assertEquals("Hello Bob", bob.decryptText(first))
        assertNotNull(bob.storage.preKeys.oneTimePreKey(OneTimePreKeyId(0)))

        bob.client.send(ALICE, "Hello Alice".encodeToByteArray())
        assertEquals("Hello Alice", alice.decryptText(alice.receiveOne()))
    }

    @Test
    fun failedFirstContactLeavesStorageUntouched() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)

        alice.client.send(BOB, "Hello Bob".encodeToByteArray())
        val first = bob.receiveOne()

        assertFailsWith<ProtocolException> { bob.client.decrypt(first.tampered()) }
        assertNull(bob.storage.sessions.load(ALICE))
        assertNotNull(bob.storage.preKeys.oneTimePreKey(OneTimePreKeyId(0)))

        assertEquals("Hello Bob", bob.decryptText(first))
    }

    @Test
    fun failedDecryptKeepsTheStoredSession() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        alice.client.send(BOB, "Hello Bob".encodeToByteArray())
        bob.decryptText(bob.receiveOne())
        bob.client.send(ALICE, "Hello Alice".encodeToByteArray())
        alice.decryptText(alice.receiveOne())

        alice.client.send(BOB, "secret".encodeToByteArray())
        val message = bob.receiveOne()
        val before = assertNotNull(bob.storage.sessions.load(ALICE)).state.copyOf()

        assertFailsWith<ProtocolException.DecryptionFailed> { bob.client.decrypt(message.tampered()) }
        assertContentEquals(before, bob.storage.sessions.load(ALICE)?.state)
        assertEquals("secret", bob.decryptText(message))
    }

    @Test
    fun consumedOneTimePreKeyCannotBeReused() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        val carol = device(CAROL)

        // The relay hands out the same one-time prekey twice.
        alice.client.send(BOB, "from Alice".encodeToByteArray())
        carol.client.send(BOB, "from Carol".encodeToByteArray())
        val (fromAlice, fromCarol) = network.receive(BOB)

        assertEquals("from Alice", bob.decryptText(fromAlice))
        assertFailsWith<ProtocolException.InvalidMessage> { bob.client.decrypt(fromCarol) }
        assertNull(bob.storage.sessions.load(CAROL))
    }

    @Test
    fun ratchetMessageWithoutSessionIsRejected() = runTest {
        val bob = device(BOB)
        val envelope = EncryptedEnvelope(
            id = MessageId("m1"),
            sender = ALICE,
            recipient = BOB,
            payload = CiphertextMessageCodec.encode(RatchetMessage(ByteArray(80))),
        )
        assertFailsWith<ProtocolException.InvalidSessionState> { bob.client.decrypt(envelope) }
    }

    @Test
    fun malformedPayloadIsRejected() = runTest {
        val bob = device(BOB)
        val envelope = EncryptedEnvelope(MessageId("m1"), ALICE, BOB, payload = byteArrayOf(1, 2, 0))
        assertFailsWith<ProtocolException.MalformedMessage> { bob.client.decrypt(envelope) }
        assertNull(bob.storage.sessions.load(ALICE))
    }

    @Test
    fun envelopeForAnotherDeviceOrVersionIsRejected() = runTest {
        val alice = device(ALICE)
        val bob = device(BOB)
        alice.client.send(BOB, "Hello Bob".encodeToByteArray())
        val envelope = bob.receiveOne()

        assertFailsWith<ProtocolException.InvalidMessage> { bob.client.decrypt(envelope.copy(recipient = CAROL)) }
        assertFailsWith<ProtocolException.InvalidMessage> { bob.client.decrypt(envelope.copy(protocolVersion = 2)) }
        assertEquals("Hello Bob", bob.decryptText(envelope))
    }
}
