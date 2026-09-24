package dev.kreienbuehl.ksecuremessage.server.ktor

import dev.kreienbuehl.ksecuremessage.client.PreKeyConfiguration
import dev.kreienbuehl.ksecuremessage.client.SecureMessageClient
import dev.kreienbuehl.ksecuremessage.client.ktor.KtorSecureMessageTransport
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyMessage
import dev.kreienbuehl.ksecuremessage.model.RatchetMessage
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.CiphertextMessageCodec
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.storage.inmemory.InMemoryClientStorage
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * Bob publishes, Alice fetches and writes first, Bob replies: all over HTTP.
 * Each side pins the other's identity key on first contact.
 */
class HttpEndToEndTest {
    private val aliceAddress = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val bobAddress = DeviceAddress(UserId("bob"), DeviceId("laptop"))

    @Test
    fun publishFetchFirstContactAndReplyOverHttp() = testServer { server, http ->
        val engine = KodiumProtocolEngine()
        val transport = KtorSecureMessageTransport("", http)
        val bobStorage = InMemoryClientStorage()
        val bob = SecureMessageClient(bobAddress, bobStorage, engine, transport, PreKeyConfiguration(oneTimePreKeyTarget = 5))
        val aliceStorage = InMemoryClientStorage()
        val alice = SecureMessageClient(aliceAddress, aliceStorage, engine, transport, PreKeyConfiguration(oneTimePreKeyTarget = 5))

        bob.initialize()
        bob.publishPreKeys()
        bob.publishPreKeys() // retry after a lost response
        alice.initialize()
        assertEquals(5, server.preKeys.oneTimePreKeyCount(bobAddress))

        val aliceIdentity = alice.currentPreKeyBundle().identityKey
        val bobIdentity = bob.currentPreKeyBundle().identityKey
        assertNull(alice.remoteIdentityKey(bobAddress))

        alice.send(bobAddress, "Hello Bob".encodeToByteArray())
        assertEquals(4, server.preKeys.oneTimePreKeyCount(bobAddress))
        assertContentEquals(bobIdentity, alice.remoteIdentityKey(bobAddress), "Alice pinned Bob")

        val first = transport.receive(bobAddress).single()
        assertEquals(OneTimePreKeyId(0), assertIs<PreKeyMessage>(CiphertextMessageCodec.decode(first.payload)).oneTimePreKeyId)
        assertNotNull(bobStorage.preKeys.oneTimePreKey(OneTimePreKeyId(0)), "private key kept until the message arrives")
        assertEquals("Hello Bob", bob.decrypt(first).decodeToString())
        assertNull(bobStorage.preKeys.oneTimePreKey(OneTimePreKeyId(0)))
        assertContentEquals(aliceIdentity, bob.remoteIdentityKey(aliceAddress), "Bob pinned Alice")

        bob.send(aliceAddress, "Hello Alice".encodeToByteArray())
        val reply = transport.receive(aliceAddress).single()
        assertIs<RatchetMessage>(CiphertextMessageCodec.decode(reply.payload))
        assertEquals("Hello Alice", alice.decrypt(reply).decodeToString())

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
        assertEquals("after restart", restartedBob.decrypt(transport.receive(bobAddress).single()).decodeToString())
    }
}
