package dev.kreienbuehl.ksecuremessage.server.ktor

import dev.kreienbuehl.ksecuremessage.client.PreKeyConfiguration
import dev.kreienbuehl.ksecuremessage.client.ReceiveResult
import dev.kreienbuehl.ksecuremessage.client.SecureMessageClient
import dev.kreienbuehl.ksecuremessage.client.ktor.KtorSecureMessageTransport
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.MessageId
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyMessage
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.CiphertextMessageCodec
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.ServerApiPaths
import dev.kreienbuehl.ksecuremessage.storage.client.inmemory.InMemoryClientStorage
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The HTTP API on persistent SQLite server storage, injected like a host
 * application would, with real server restarts (driver closed, file opened
 * again) between the steps.
 */
class SqlDelightHttpEndToEndTest {
    private val aliceAddress = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val bobAddress = DeviceAddress(UserId("bob"), DeviceId("laptop"))

    private fun persistentServer(block: suspend io.ktor.server.testing.ApplicationTestBuilder.(ReopenableServerStorage, io.ktor.client.HttpClient) -> Unit) =
        ReopenableServerStorage().use { storage -> testServer(storage, block = block) }

    @Test
    fun firstContactAcknowledgementAndReplyAcrossServerRestarts() = persistentServer { server, http ->
        val engine = KodiumProtocolEngine()
        val transport = KtorSecureMessageTransport("", http)
        val bobStorage = InMemoryClientStorage()
        val bob = SecureMessageClient(bobAddress, bobStorage, engine, transport, PreKeyConfiguration(oneTimePreKeyTarget = 5))
        val alice = SecureMessageClient(aliceAddress, InMemoryClientStorage(), engine, transport, PreKeyConfiguration(oneTimePreKeyTarget = 5))

        alice.initialize()
        alice.registerDevice()
        bob.initialize()
        bob.registerDevice()
        bob.publishPreKeys()
        val bobIdentity = bob.currentPreKeyBundle().identityKey

        server.restart()
        // Registrations and prekeys survived: identical retries are no-ops, the inventory is intact.
        alice.registerDevice()
        assertEquals(5, server.preKeys.oneTimePreKeyCount(bobAddress))
        val hello = alice.send(bobAddress, "Hello Bob".encodeToByteArray())
        assertContentEquals(bobIdentity, alice.remoteIdentityKey(bobAddress))

        server.restart()
        assertEquals(4, server.preKeys.oneTimePreKeyCount(bobAddress), "the consumed one-time prekey stays consumed")
        val first = bob.receive().single()
        assertEquals(OneTimePreKeyId(0), assertIs<PreKeyMessage>(CiphertextMessageCodec.decode(first.payload)).oneTimePreKeyId)
        val received = bob.accept(first)
        assertEquals("Hello Bob", received.plaintext.decodeToString())
        assertTrue(received.ackSent)

        server.restart()
        assertEquals(listOf(hello.id), alice.pendingMessages(bobAddress).map { it.id })
        val acknowledged = assertIs<ReceiveResult.Acknowledgement>(alice.decrypt(alice.receive().single()))
        assertEquals(hello.id, acknowledged.id)
        assertTrue(acknowledged.cleared)
        assertEquals(emptyList(), alice.pendingMessages(bobAddress))

        bob.send(aliceAddress, "Hello Alice".encodeToByteArray())
        server.restart()
        val reply = alice.accept(alice.receive().single())
        assertEquals("Hello Alice", reply.plaintext.decodeToString())
        assertTrue(reply.ackSent)

        server.restart()
        assertTrue(assertIs<ReceiveResult.Acknowledgement>(bob.decrypt(bob.receive().single())).cleared)
        assertEquals(emptyList(), bob.pendingMessages(aliceAddress))
        assertEquals(emptyList(), bob.receive(), "drained envelopes stay gone")

        // Bob republishes after the restarts: the consumed #0 is never handed out again.
        bob.initialize()
        bob.publishPreKeys()
        server.restart()
        assertEquals(5, server.preKeys.oneTimePreKeyCount(bobAddress))
        val ids = List(5) { server.preKeys.consumePreKeyBundle(bobAddress)?.oneTimePreKey?.id }
        assertFalse(OneTimePreKeyId(0) in ids)
    }

    @Test
    fun replayedRequestIsRejectedAfterServerRestart() = persistentServer { server, http ->
        val device = TestDevice(aliceAddress)
        device.register(KtorSecureMessageTransport("", http))
        val once = device.sign("GET", ServerApiPaths.MESSAGES, ByteArray(0))
        val path = ServerApiPaths.device(aliceAddress, ServerApiPaths.MESSAGES)
        assertEquals(HttpStatusCode.OK, http.raw(HttpMethod.Get, path, null, once).status)

        server.restart()
        val replay = http.raw(HttpMethod.Get, path, null, once)
        assertEquals(HttpStatusCode.Unauthorized, replay.status)
        assertEquals("""{"error":"authentication_replay"}""", replay.bodyAsText())
    }

    /** A persistence failure is a generic 500 without SQL details, never a 202. */
    @Test
    fun persistenceFailureIsAGenericServerError() = persistentServer { server, http ->
        val device = TestDevice(aliceAddress)
        device.register(KtorSecureMessageTransport("", http))

        server.driver.execute(null, "DROP TABLE mailbox_message", 0)
        val relay = http.post("/v1/messages") {
            contentType(ContentType.Application.Json)
            setBody(EncryptedEnvelope(MessageId("m1"), bobAddress, aliceAddress, payload = byteArrayOf(1)))
        }
        assertEquals(HttpStatusCode.InternalServerError, relay.status)
        assertEquals("""{"error":"internal_error"}""", relay.bodyAsText())

        // A storage failure during authentication (the nonce claim) is no 401 either.
        server.driver.execute(null, "DROP TABLE authentication_nonce", 0)
        val drain = http.raw(
            HttpMethod.Get,
            ServerApiPaths.device(aliceAddress, ServerApiPaths.MESSAGES),
            null,
            device.sign("GET", ServerApiPaths.MESSAGES, ByteArray(0)),
        )
        assertEquals(HttpStatusCode.InternalServerError, drain.status)
        assertEquals("""{"error":"internal_error"}""", drain.bodyAsText())
    }
}
