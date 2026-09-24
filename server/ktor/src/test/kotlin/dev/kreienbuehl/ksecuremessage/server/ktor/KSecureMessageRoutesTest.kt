package dev.kreienbuehl.ksecuremessage.server.ktor

import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException.Reason
import dev.kreienbuehl.ksecuremessage.client.ktor.KtorSecureMessageTransport
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.MessageId
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication
import dev.kreienbuehl.ksecuremessage.model.PublicOneTimePreKey
import dev.kreienbuehl.ksecuremessage.model.PublicSignedPreKey
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.PreKeyFormat
import io.ktor.client.request.get
import io.ktor.client.request.put
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.io.encoding.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

class KSecureMessageRoutesTest {
    private val bob = DeviceAddress(UserId("bob"), DeviceId("laptop"))

    private fun key(seed: Int, size: Int = PreKeyFormat.PUBLIC_KEY_SIZE) = ByteArray(size) { (seed + it).toByte() }

    private fun publication(oneTimePreKeys: IntRange = 0..2, identitySeed: Int = 1, signedPreKeyId: Int = 0) =
        PreKeyPublication(
            address = bob,
            identityKey = key(identitySeed),
            signedPreKey = PublicSignedPreKey(SignedPreKeyId(signedPreKeyId), key(2), key(3, PreKeyFormat.SIGNATURE_SIZE)),
            oneTimePreKeys = oneTimePreKeys.map { PublicOneTimePreKey(OneTimePreKeyId(it), key(100 + it)) },
        )

    private fun validJson(oneTimePreKeyId: Int = 0, identityKey: String = Base64.encode(key(1))) = """
        {"identityKey":"$identityKey",
         "signedPreKey":{"id":0,"publicKey":"${Base64.encode(key(2))}","signature":"${Base64.encode(key(3, 64))}"},
         "oneTimePreKeys":[{"id":$oneTimePreKeyId,"publicKey":"${Base64.encode(key(100))}"}]}
    """.trimIndent()

    @Test
    fun publishedKeysAreServedAsBase64AndConsumed() = testServer { storage, http ->
        val transport = KtorSecureMessageTransport("", http)
        val published = publication()
        transport.publishPreKeys(published)
        transport.publishPreKeys(published)
        assertEquals(3, storage.preKeys.oneTimePreKeyCount(bob))

        val raw = http.get("/v1/devices/bob/laptop/prekey-bundle")
        assertEquals(HttpStatusCode.OK, raw.status)
        val json = Json.parseToJsonElement(raw.bodyAsText()).jsonObject
        assertEquals(setOf("identityKey", "signedPreKey", "oneTimePreKey"), json.keys)
        assertContentEquals(published.identityKey, Base64.decode(json.getValue("identityKey").jsonPrimitive.content))
        assertEquals(0, json.getValue("oneTimePreKey").jsonObject.getValue("id").jsonPrimitive.int)

        val bundle = transport.fetchPreKeyBundle(bob)
        assertEquals(bob, bundle.address)
        assertContentEquals(published.signedPreKey.signature, bundle.signedPreKey.signature)
        assertEquals(OneTimePreKeyId(1), bundle.oneTimePreKey?.id)
        assertContentEquals(published.oneTimePreKeys[1].publicKey, bundle.oneTimePreKey?.publicKey)
        assertEquals(1, storage.preKeys.oneTimePreKeyCount(bob))
    }

    @Test
    fun publishReturnsNoContent() = testServer { _, http ->
        val response = http.put("/v1/devices/bob/laptop/prekeys") {
            contentType(ContentType.Application.Json)
            setBody(validJson())
        }
        assertEquals(HttpStatusCode.NoContent, response.status)
    }

    @Test
    fun exhaustedInventoryReturnsBundleWithoutOneTimePreKey() = testServer { _, http ->
        val transport = KtorSecureMessageTransport("", http)
        transport.publishPreKeys(publication(oneTimePreKeys = IntRange.EMPTY))
        val raw = Json.parseToJsonElement(http.get("/v1/devices/bob/laptop/prekey-bundle").bodyAsText()).jsonObject
        assertEquals(JsonNull, raw.getValue("oneTimePreKey"))
        assertNull(transport.fetchPreKeyBundle(bob).oneTimePreKey)
    }

    @Test
    fun unknownDeviceIsNotFound() = testServer { _, http ->
        assertEquals(HttpStatusCode.NotFound, http.get("/v1/devices/bob/laptop/prekey-bundle").status)
        assertFailsWith<SecureMessageTransportException.DeviceNotFound> {
            KtorSecureMessageTransport("", http).fetchPreKeyBundle(bob)
        }
    }

    @Test
    fun malformedRequestsAreBadRequestsAndChangeNothing() = testServer { storage, http ->
        val transport = KtorSecureMessageTransport("", http)
        transport.publishPreKeys(publication(oneTimePreKeys = 0..0))
        val bodies = listOf(
            "not json",
            "{}",
            validJson().replace("\"oneTimePreKeys\"", "\"extra\":1,\"oneTimePreKeys\""),
            validJson(identityKey = "***not base64***"),
            validJson(identityKey = Base64.encode(key(1, 32))),
            validJson(oneTimePreKeyId = -1),
        )
        for (body in bodies) {
            val response = http.put("/v1/devices/bob/laptop/prekeys") {
                contentType(ContentType.Application.Json)
                setBody(body)
            }
            assertEquals(HttpStatusCode.BadRequest, response.status, body)
            assertEquals("""{"error":"invalid_publication"}""", response.bodyAsText())
        }

        val duplicate = publication(oneTimePreKeys = 5..5).let { it.copy(oneTimePreKeys = it.oneTimePreKeys + it.oneTimePreKeys) }
        val rejected = assertFailsWith<SecureMessageTransportException.PublicationRejected> { transport.publishPreKeys(duplicate) }
        assertEquals(Reason.INVALID_PUBLICATION, rejected.reason)
        assertEquals(1, storage.preKeys.oneTimePreKeyCount(bob))
    }

    @Test
    fun conflictsAreReportedAndChangeNothing() = testServer { storage, http ->
        val transport = KtorSecureMessageTransport("", http)
        transport.publishPreKeys(publication(oneTimePreKeys = 0..2, signedPreKeyId = 5))

        suspend fun rejection(publication: PreKeyPublication) =
            assertFailsWith<SecureMessageTransportException.PublicationRejected> { transport.publishPreKeys(publication) }.reason

        assertEquals(Reason.IDENTITY_KEY_CONFLICT, rejection(publication(oneTimePreKeys = 3..4, identitySeed = 9, signedPreKeyId = 6)))
        assertEquals(Reason.SIGNED_PRE_KEY_CONFLICT, rejection(publication(oneTimePreKeys = 3..4, signedPreKeyId = 4)))
        val conflicting = publication(oneTimePreKeys = 2..4, signedPreKeyId = 5).let {
            it.copy(oneTimePreKeys = it.oneTimePreKeys.map { key -> if (key.id.value == 2) key.copy(publicKey = key(7)) else key })
        }
        assertEquals(Reason.ONE_TIME_PRE_KEY_CONFLICT, rejection(conflicting))

        val raw = http.put("/v1/devices/bob/laptop/prekeys") {
            contentType(ContentType.Application.Json)
            setBody(validJson(identityKey = Base64.encode(key(9))))
        }
        assertEquals(HttpStatusCode.Conflict, raw.status)
        assertEquals("""{"error":"identity_key_conflict"}""", raw.bodyAsText())

        assertEquals(3, storage.preKeys.oneTimePreKeyCount(bob))
        assertEquals(5, transport.fetchPreKeyBundle(bob).signedPreKey.id.value)
    }

    @Test
    fun concurrentHttpFetchesNeverShareAOneTimePreKey() = testServer { _, http ->
        val transport = KtorSecureMessageTransport("", http)
        transport.publishPreKeys(publication(oneTimePreKeys = 0..9))

        val ids = coroutineScope {
            List(20) { async { transport.fetchPreKeyBundle(bob).oneTimePreKey?.id?.value } }.awaitAll()
        }

        assertEquals((0..9).toList(), ids.filterNotNull().sorted())
        assertEquals(10, ids.count { it == null })
    }

    @Test
    fun pathSegmentsAreEncoded() = testServer { storage, http ->
        val odd = DeviceAddress(UserId("bob/with slash"), DeviceId("dev?ice#1"))
        val transport = KtorSecureMessageTransport("", http)
        transport.publishPreKeys(publication().copy(address = odd))
        assertEquals(3, storage.preKeys.oneTimePreKeyCount(odd))
        assertEquals(odd, transport.fetchPreKeyBundle(odd).address)
        assertEquals(0, storage.preKeys.oneTimePreKeyCount(bob))
    }

    @Test
    fun eachSendersEnvelopesArriveInSendOrderOverHttp() = testServer { _, http ->
        val transport = KtorSecureMessageTransport("", http)
        val senders = List(4) { DeviceAddress(UserId("sender-$it"), DeviceId("phone")) }
        val carol = DeviceAddress(UserId("carol"), DeviceId("tablet"))

        // Each sender sends sequentially (as SecureMessageClient.send does);
        // the senders run concurrently, to two recipients.
        coroutineScope {
            senders.map { sender ->
                async {
                    repeat(25) { sequence ->
                        for (recipient in listOf(bob, carol)) {
                            transport.send(
                                EncryptedEnvelope(
                                    id = MessageId("${sender.userId.value}#$sequence"),
                                    sender = sender,
                                    recipient = recipient,
                                    payload = byteArrayOf(sequence.toByte()),
                                ),
                            )
                        }
                    }
                }
            }.awaitAll()
        }

        for (recipient in listOf(bob, carol)) {
            val received = transport.receive(recipient)
            assertEquals(senders.size * 25, received.size)
            for (sender in senders) {
                val stream = received.filter { it.sender == sender }
                assertEquals((0 until 25).map { "${sender.userId.value}#$it" }, stream.map { it.id.value })
                assertContentEquals(byteArrayOf(24), stream.last().payload)
            }
            assertEquals(emptyList(), transport.receive(recipient))
        }
    }
}
