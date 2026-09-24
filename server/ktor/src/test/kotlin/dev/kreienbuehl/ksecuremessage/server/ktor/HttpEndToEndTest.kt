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
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/** Bob publishes, Alice fetches and writes first, Bob replies: all over HTTP. */
class HttpEndToEndTest {
    private val aliceAddress = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val bobAddress = DeviceAddress(UserId("bob"), DeviceId("laptop"))

    @Test
    fun publishFetchFirstContactAndReplyOverHttp() = testServer { server, http ->
        val engine = KodiumProtocolEngine()
        val transport = KtorSecureMessageTransport("", http)
        val bobStorage = InMemoryClientStorage()
        val bob = SecureMessageClient(bobAddress, bobStorage, engine, transport, PreKeyConfiguration(oneTimePreKeyTarget = 5))
        val alice = SecureMessageClient(aliceAddress, InMemoryClientStorage(), engine, transport, PreKeyConfiguration(oneTimePreKeyTarget = 5))

        bob.initialize()
        bob.publishPreKeys()
        bob.publishPreKeys() // retry after a lost response
        alice.initialize()
        assertEquals(5, server.preKeys.oneTimePreKeyCount(bobAddress))

        alice.send(bobAddress, "Hello Bob".encodeToByteArray())
        assertEquals(4, server.preKeys.oneTimePreKeyCount(bobAddress))

        val first = transport.receive(bobAddress).single()
        assertEquals(OneTimePreKeyId(0), assertIs<PreKeyMessage>(CiphertextMessageCodec.decode(first.payload)).oneTimePreKeyId)
        assertNotNull(bobStorage.preKeys.oneTimePreKey(OneTimePreKeyId(0)), "private key kept until the message arrives")
        assertEquals("Hello Bob", bob.decrypt(first).decodeToString())
        assertNull(bobStorage.preKeys.oneTimePreKey(OneTimePreKeyId(0)))

        bob.send(aliceAddress, "Hello Alice".encodeToByteArray())
        val reply = transport.receive(aliceAddress).single()
        assertIs<RatchetMessage>(CiphertextMessageCodec.decode(reply.payload))
        assertEquals("Hello Alice", alice.decrypt(reply).decodeToString())

        // Bob refills and republishes; the consumed #0 is not handed out again.
        bob.initialize()
        bob.publishPreKeys()
        assertEquals(5, server.preKeys.oneTimePreKeyCount(bobAddress))
    }
}
