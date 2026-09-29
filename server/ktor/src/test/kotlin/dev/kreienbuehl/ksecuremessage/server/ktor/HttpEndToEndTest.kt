package dev.kreienbuehl.ksecuremessage.server.ktor

import dev.kreienbuehl.ksecuremessage.client.PreKeyConfiguration
import dev.kreienbuehl.ksecuremessage.client.ReceiveResult
import dev.kreienbuehl.ksecuremessage.client.SecureMessageClient
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException
import dev.kreienbuehl.ksecuremessage.client.ktor.KtorSecureMessageTransport
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.MessageId
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyMessage
import dev.kreienbuehl.ksecuremessage.model.RatchetMessage
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.CiphertextMessageCodec
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.storage.client.inmemory.InMemoryClientStorage
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Bob and Alice register, Bob publishes, Alice fetches and writes first,
 * Bob acknowledges and replies: all over HTTP, every device-scoped request
 * signed with the device authentication key. Each side pins the other's identity key on first
 * contact; acknowledgements are ordinary encrypted envelopes.
 */
class HttpEndToEndTest {
    private val aliceAddress = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val bobAddress = DeviceAddress(UserId("bob"), DeviceId("laptop"))

    @Test
    fun publishFetchFirstContactAndReplyOverHttp() = testServer(TestDeviceRegistrationAuthorizer.allowAll()) { server, http ->
        val engine = KodiumProtocolEngine()
        val transport = KtorSecureMessageTransport("", http)
        val bobStorage = InMemoryClientStorage()
        val bob = SecureMessageClient(bobAddress, bobStorage, engine, transport, PreKeyConfiguration(oneTimePreKeyTarget = 5))
        val aliceStorage = InMemoryClientStorage()
        val alice = SecureMessageClient(aliceAddress, aliceStorage, engine, transport, PreKeyConfiguration(oneTimePreKeyTarget = 5))

        bob.initialize()
        bob.registerDevice()
        bob.registerDevice() // retry after a lost response
        bob.publishPreKeys()
        bob.publishPreKeys() // retry after a lost response
        alice.initialize()
        alice.registerDevice()
        assertEquals(5, server.preKeys.oneTimePreKeyCount(bobAddress))

        val aliceIdentity = alice.currentPreKeyBundle().identityKey
        val bobIdentity = bob.currentPreKeyBundle().identityKey
        assertNull(alice.remoteIdentityKey(bobAddress))

        val hello = alice.send(bobAddress, "Hello Bob".encodeToByteArray())
        assertEquals(4, server.preKeys.oneTimePreKeyCount(bobAddress))
        assertContentEquals(bobIdentity, alice.remoteIdentityKey(bobAddress), "Alice pinned Bob")

        val first = bob.receive().single()
        assertEquals(OneTimePreKeyId(0), assertIs<PreKeyMessage>(CiphertextMessageCodec.decode(first.payload)).oneTimePreKeyId)
        assertNotNull(bobStorage.preKeys.oneTimePreKey(OneTimePreKeyId(0)), "private key kept until the message arrives")
        val received = bob.accept(first)
        assertEquals("Hello Bob", received.plaintext.decodeToString())
        assertEquals(hello.id, received.id)
        assertTrue(received.ackSent)
        assertNull(bobStorage.preKeys.oneTimePreKey(OneTimePreKeyId(0)))
        assertContentEquals(aliceIdentity, bob.remoteIdentityKey(aliceAddress), "Bob pinned Alice")

        // The encrypted acknowledgement travels like any other message.
        assertEquals(listOf(hello.id), alice.pendingMessages(limit = 100, recipient = bobAddress).messages.map { it.id }, "HTTP 202 is not an acknowledgement")
        val ack = alice.receive().single()
        assertIs<RatchetMessage>(CiphertextMessageCodec.decode(ack.payload))
        val acknowledged = assertIs<ReceiveResult.Acknowledgement>(alice.decrypt(ack))
        assertEquals(hello.id, acknowledged.id)
        assertTrue(acknowledged.cleared)
        assertEquals(emptyList(), alice.pendingMessages(limit = 100, recipient = bobAddress).messages)

        bob.send(aliceAddress, "Hello Alice".encodeToByteArray())
        val reply = alice.receive().single()
        assertIs<RatchetMessage>(CiphertextMessageCodec.decode(reply.payload))
        assertEquals("Hello Alice", alice.accept(reply).plaintext.decodeToString())
        assertTrue(assertIs<ReceiveResult.Acknowledgement>(bob.decrypt(bob.receive().single())).cleared)
        assertEquals(emptyList(), bob.pendingMessages(limit = 100, recipient = aliceAddress).messages)

        // Bob refills and republishes; the consumed #0 is not handed out again.
        bob.initialize()
        bob.publishPreKeys()
        assertEquals(5, server.preKeys.oneTimePreKeyCount(bobAddress))

        // New client instances on the same storage keep the pins.
        val restartedAlice = SecureMessageClient(aliceAddress, aliceStorage, engine, transport)
        val restartedBob = SecureMessageClient(bobAddress, bobStorage, engine, transport)
        assertContentEquals(bobIdentity, restartedAlice.remoteIdentityKey(bobAddress))
        assertContentEquals(aliceIdentity, restartedBob.remoteIdentityKey(aliceAddress))
        restartedAlice.send(bobAddress, "after restart".encodeToByteArray())
        val afterRestart = restartedBob.accept(restartedBob.receive().single())
        assertEquals("after restart", afterRestart.plaintext.decodeToString())
        assertTrue(assertIs<ReceiveResult.Acknowledgement>(restartedAlice.decrypt(restartedAlice.receive().single())).cleared)
    }

    @Test
    fun unregisteredClientCannotPublishOrDrain() = testServer(TestDeviceRegistrationAuthorizer.allowAll()) { server, http ->
        val transport = KtorSecureMessageTransport("", http)
        val bob = SecureMessageClient(bobAddress, InMemoryClientStorage(), KodiumProtocolEngine(), transport)
        bob.initialize()
        server.mailboxes.enqueue(EncryptedEnvelope(MessageId("m1"), aliceAddress, bobAddress, payload = byteArrayOf(1)))

        val publish = assertFailsWith<SecureMessageTransportException.AuthenticationFailed> { bob.publishPreKeys() }
        assertEquals(SecureMessageTransportException.AuthenticationFailure.NOT_REGISTERED, publish.failure)
        assertEquals(0, server.preKeys.oneTimePreKeyCount(bobAddress))
        val drain = assertFailsWith<SecureMessageTransportException.AuthenticationFailed> { bob.receive() }
        assertEquals(SecureMessageTransportException.AuthenticationFailure.NOT_REGISTERED, drain.failure)

        bob.registerDevice()
        assertEquals(listOf("m1"), bob.receive().map { it.id.value }, "the mailbox was kept for its owner")
    }
}
