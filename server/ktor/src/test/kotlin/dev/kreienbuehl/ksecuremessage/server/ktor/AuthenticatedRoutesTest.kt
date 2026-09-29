package dev.kreienbuehl.ksecuremessage.server.ktor

import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException.AuthenticationFailure
import dev.kreienbuehl.ksecuremessage.client.ktor.KtorSecureMessageTransport
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.MessageId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.PreKeyFormat
import dev.kreienbuehl.ksecuremessage.protocol.RequestAuthentication
import dev.kreienbuehl.ksecuremessage.protocol.ServerApiPaths
import io.ktor.client.HttpClient
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlin.io.encoding.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes

/**
 * Device authentication of the HTTP API v1 (docs/server-authentication.md):
 * registration, the authentication headers, what the signature binds, the
 * time window, replay protection and the status mapping.
 */
class AuthenticatedRoutesTest {
    private val alice = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val aliceLaptop = DeviceAddress(UserId("alice"), DeviceId("laptop"))
    private val bob = DeviceAddress(UserId("bob"), DeviceId("phone"))

    private fun key(seed: Int, size: Int = PreKeyFormat.PUBLIC_KEY_SIZE) = ByteArray(size) { (seed + it).toByte() }

    private fun b64(bytes: ByteArray) = Base64.encode(bytes)

    private fun registrationBody(publicKey: ByteArray) = """{"publicKey":"${b64(publicKey)}"}""".encodeToByteArray()

    private suspend fun HttpClient.register(device: TestDevice, body: ByteArray = registrationBody(device.keyPair.publicKey), authentication: RequestAuthentication? = device.sign("PUT", ServerApiPaths.REGISTRATION, body)) =
        raw(HttpMethod.Put, ServerApiPaths.device(device.address, ServerApiPaths.REGISTRATION), body, authentication)

    private suspend fun HttpClient.drain(device: TestDevice, authentication: RequestAuthentication? = device.sign("GET", ServerApiPaths.MESSAGES, ByteArray(0))) =
        raw(HttpMethod.Get, ServerApiPaths.device(device.address, ServerApiPaths.MESSAGES), null, authentication)

    private suspend fun HttpResponse.error(): String = bodyAsText()

    private fun envelope(id: String, recipient: DeviceAddress) = EncryptedEnvelope(MessageId(id), bob, recipient, payload = byteArrayOf(1))

    /** A valid publication body with the given fields. */
    private fun preKeyJson(
        identityKey: ByteArray = key(1),
        signedPreKeyId: Int = 0,
        signedPreKey: ByteArray = key(2),
        signature: ByteArray = key(3, PreKeyFormat.SIGNATURE_SIZE),
        oneTimePreKeys: List<Pair<Int, ByteArray>> = listOf(0 to key(100), 1 to key(101)),
    ) = (
        """{"identityKey":"${b64(identityKey)}","signedPreKey":{"id":$signedPreKeyId,"publicKey":"${b64(signedPreKey)}","signature":"${b64(signature)}"},""" +
            """"oneTimePreKeys":[${oneTimePreKeys.joinToString(",") { (id, k) -> """{"id":$id,"publicKey":"${b64(k)}"}""" }}]}"""
        ).encodeToByteArray()

    @Test
    fun registrationStatuses() = testServer(TestDeviceRegistrationAuthorizer.allowAll()) { storage, http ->
        val device = TestDevice(alice)
        val first = http.register(device)
        assertEquals(HttpStatusCode.Created, first.status)
        assertEquals(HttpStatusCode.NoContent, http.register(device).status, "identical retry")
        assertContentEquals(device.keyPair.publicKey, storage.devices.registration(alice)?.publicKey)

        val impostor = TestDevice(alice)
        val conflict = http.register(impostor)
        assertEquals(HttpStatusCode.Conflict, conflict.status)
        assertEquals("""{"error":"device_registration_conflict"}""", conflict.error())
        assertContentEquals(device.keyPair.publicKey, storage.devices.registration(alice)?.publicKey, "never replaced")

        val other = TestDevice(aliceLaptop)
        for (body in listOf("not json", "{}", """{"publicKey":"***"}""", """{"publicKey":"${b64(key(1, 31))}"}""", """{"publicKey":"${b64(other.keyPair.publicKey)}","extra":1}""")) {
            val bytes = body.encodeToByteArray()
            val response = http.register(other, bytes, other.sign("PUT", ServerApiPaths.REGISTRATION, bytes))
            assertEquals(HttpStatusCode.BadRequest, response.status, body)
            assertEquals("""{"error":"invalid_registration"}""", response.error())
        }
        val missing = http.register(other, authentication = null)
        assertEquals(HttpStatusCode.Unauthorized, missing.status)
        assertEquals("""{"error":"missing_authentication"}""", missing.error())
        // Proof of possession: the request must be signed with the key it registers.
        val foreign = http.register(other, authentication = device.sign("PUT", ServerApiPaths.REGISTRATION, registrationBody(other.keyPair.publicKey), address = aliceLaptop))
        assertEquals(HttpStatusCode.Unauthorized, foreign.status)
        assertEquals("""{"error":"invalid_authentication"}""", foreign.error())
        assertNull(storage.devices.registration(aliceLaptop))
    }

    @Test
    fun everyPublicationFieldIsCoveredBySignature() = testServer(TestDeviceRegistrationAuthorizer.allowAll()) { storage, http ->
        val device = TestDevice(alice)
        http.register(device)
        val signed = preKeyJson()
        val authentication = device.sign("PUT", ServerApiPaths.PRE_KEYS, signed)
        val tampered = mapOf(
            "identity key byte" to preKeyJson(identityKey = key(1).also { it[5] = (it[5] + 1).toByte() }),
            "signed prekey ID" to preKeyJson(signedPreKeyId = 1),
            "signed prekey public key" to preKeyJson(signedPreKey = key(9)),
            "signed prekey signature" to preKeyJson(signature = key(4, PreKeyFormat.SIGNATURE_SIZE)),
            "one-time prekey added" to preKeyJson(oneTimePreKeys = listOf(0 to key(100), 1 to key(101), 2 to key(102))),
            "one-time prekey removed" to preKeyJson(oneTimePreKeys = listOf(0 to key(100))),
            "one-time prekey changed" to preKeyJson(oneTimePreKeys = listOf(0 to key(100), 1 to key(77))),
            "whitespace" to (signed.decodeToString() + " ").encodeToByteArray(),
        )
        for ((name, body) in tampered) {
            val response = http.raw(HttpMethod.Put, ServerApiPaths.device(alice, ServerApiPaths.PRE_KEYS), body, authentication)
            assertEquals(HttpStatusCode.Unauthorized, response.status, name)
            assertEquals("""{"error":"invalid_authentication"}""", response.error(), name)
            assertEquals(0, storage.preKeys.oneTimePreKeyCount(alice), name)
            assertNull(storage.preKeys.consumePreKeyBundle(alice), name)
        }
        // The untouched request still goes through: the failures consumed no nonce.
        assertEquals(HttpStatusCode.NoContent, http.raw(HttpMethod.Put, ServerApiPaths.device(alice, ServerApiPaths.PRE_KEYS), signed, authentication).status)
        assertEquals(2, storage.preKeys.oneTimePreKeyCount(alice))
    }

    @Test
    fun signaturesAreBoundToTheDeviceInThePathAndToTheMethod() = testServer(TestDeviceRegistrationAuthorizer.allowAll()) { storage, http ->
        val device = TestDevice(alice)
        val laptop = TestDevice(aliceLaptop)
        val bobDevice = TestDevice(bob)
        listOf(device, laptop, bobDevice).forEach { http.register(it) }
        val body = preKeyJson()
        val authentication = device.sign("PUT", ServerApiPaths.PRE_KEYS, body)

        for (target in listOf(aliceLaptop, bob)) {
            val response = http.raw(HttpMethod.Put, ServerApiPaths.device(target, ServerApiPaths.PRE_KEYS), body, authentication)
            assertEquals(HttpStatusCode.Unauthorized, response.status, "$target")
            assertEquals(0, storage.preKeys.oneTimePreKeyCount(target))
        }

        storage.mailboxes.enqueue(envelope("m1", alice))
        // A PUT signature for the mailbox path does not authenticate a GET of it.
        val asGet = http.drain(device, device.sign("PUT", ServerApiPaths.MESSAGES, ByteArray(0)))
        assertEquals(HttpStatusCode.Unauthorized, asGet.status)
        assertEquals(1, Json.parseToJsonElement(http.drain(device).bodyAsText()).jsonArray.size, "mailbox untouched until then")
    }

    @Test
    fun keysSuppliedWithTheRequestAreNeverUsedForVerification() = testServer(TestDeviceRegistrationAuthorizer.allowAll()) { storage, http ->
        val device = TestDevice(alice)
        http.register(device)
        storage.mailboxes.enqueue(envelope("m1", alice))
        val attacker = TestDevice(alice)
        val body = preKeyJson()
        // The attacker's own key, offered in every way a request could carry one.
        val offered = mapOf(
            "X-KSecureMessage-Public-Key" to b64(attacker.keyPair.publicKey),
            "X-KSecureMessage-Key" to b64(attacker.keyPair.publicKey),
        )
        val drain = http.raw(HttpMethod.Get, ServerApiPaths.device(alice, ServerApiPaths.MESSAGES), null, attacker.sign("GET", ServerApiPaths.MESSAGES, ByteArray(0)), offered)
        assertEquals(HttpStatusCode.Unauthorized, drain.status)
        val publish = http.raw(HttpMethod.Put, ServerApiPaths.device(alice, ServerApiPaths.PRE_KEYS), body, attacker.sign("PUT", ServerApiPaths.PRE_KEYS, body), offered)
        assertEquals(HttpStatusCode.Unauthorized, publish.status)
        // Re-registering with the attacker's key and proof is a conflict, not a replacement.
        assertEquals(HttpStatusCode.Conflict, http.register(attacker).status)
        assertEquals(0, storage.preKeys.oneTimePreKeyCount(alice))
        assertEquals(listOf("m1"), storage.mailboxes.drain(alice).map { it.id.value })
        assertContentEquals(device.keyPair.publicKey, storage.devices.registration(alice)?.publicKey)
    }

    @Test
    fun authenticationHeadersAreStrict() = testServer(TestDeviceRegistrationAuthorizer.allowAll()) { _, http ->
        val device = TestDevice(alice)
        http.register(device)
        val path = ServerApiPaths.device(alice, ServerApiPaths.MESSAGES)
        val valid = device.sign("GET", ServerApiPaths.MESSAGES, ByteArray(0))
        val validHeaders = mapOf(
            AuthHeaders.VERSION to "1",
            AuthHeaders.TIMESTAMP to valid.timestamp.toEpochMilliseconds().toString(),
            AuthHeaders.NONCE to b64(valid.nonce.bytes),
            AuthHeaders.SIGNATURE to b64(valid.signature),
        )
        suspend fun attempt(headers: Map<String, String>) = http.raw(HttpMethod.Get, path, null, null, headers)

        assertEquals("""{"error":"missing_authentication"}""", attempt(emptyMap()).error())
        val broken = listOf(
            validHeaders - AuthHeaders.SIGNATURE,
            validHeaders - AuthHeaders.VERSION,
            validHeaders + (AuthHeaders.VERSION to "2"),
            validHeaders + (AuthHeaders.TIMESTAMP to "-1"),
            validHeaders + (AuthHeaders.TIMESTAMP to "+${valid.timestamp.toEpochMilliseconds()}"),
            validHeaders + (AuthHeaders.TIMESTAMP to "0x10"),
            validHeaders + (AuthHeaders.TIMESTAMP to "9".repeat(19)),
            validHeaders + (AuthHeaders.NONCE to b64(ByteArray(15))),
            validHeaders + (AuthHeaders.NONCE to b64(valid.nonce.bytes).trimEnd('=')),
            validHeaders + (AuthHeaders.NONCE to "not base64!"),
            validHeaders + (AuthHeaders.SIGNATURE to b64(valid.signature.copyOf(63))),
        )
        for (headers in broken) {
            val response = attempt(headers)
            assertEquals(HttpStatusCode.Unauthorized, response.status, "$headers")
            assertEquals("""{"error":"invalid_authentication"}""", response.error(), "$headers")
        }
        assertEquals(HttpStatusCode.OK, attempt(validHeaders).status)
    }

    @Test
    fun timeWindowReplayAndRegistrationOverHttp() {
        val clock = ManualClock()
        testServer(TestDeviceRegistrationAuthorizer.allowAll(), clock) { storage, http ->
            val device = TestDevice(alice, clock)
            val unregistered = http.drain(device)
            assertEquals(HttpStatusCode.Unauthorized, unregistered.status)
            assertEquals("""{"error":"device_not_registered"}""", unregistered.error())
            http.register(device)

            fun at(offset: kotlin.time.Duration) = device.sign("GET", ServerApiPaths.MESSAGES, ByteArray(0), timestamp = clock.now + offset)
            assertEquals(HttpStatusCode.OK, http.drain(device, at(-5.minutes)).status)
            assertEquals(HttpStatusCode.OK, http.drain(device, at(5.minutes)).status)
            for (offset in listOf(-(5.minutes + 1.milliseconds), 5.minutes + 1.milliseconds)) {
                val response = http.drain(device, at(offset))
                assertEquals(HttpStatusCode.Unauthorized, response.status)
                assertEquals("""{"error":"expired_authentication"}""", response.error())
            }

            storage.mailboxes.enqueue(envelope("m1", alice))
            val once = at(0.milliseconds)
            assertEquals(1, Json.parseToJsonElement(http.drain(device, once).bodyAsText()).jsonArray.size)
            storage.mailboxes.enqueue(envelope("m2", alice))
            val replay = http.drain(device, once)
            assertEquals(HttpStatusCode.Unauthorized, replay.status)
            assertEquals("""{"error":"authentication_replay"}""", replay.error())
            assertEquals(listOf("m2"), storage.mailboxes.drain(alice).map { it.id.value }, "the replay drained nothing")
        }
    }

    @Test
    fun concurrentIdenticalDrainsOverHttpExecuteOnce() = testServer(TestDeviceRegistrationAuthorizer.allowAll()) { storage, http ->
        val device = TestDevice(alice)
        http.register(device)
        repeat(5) { storage.mailboxes.enqueue(envelope("m$it", alice)) }
        val authentication = device.sign("GET", ServerApiPaths.MESSAGES, ByteArray(0))
        val responses = coroutineScope { List(8) { async { http.drain(device, authentication) } }.awaitAll() }

        val ok = responses.filter { it.status == HttpStatusCode.OK }
        assertEquals(1, ok.size)
        assertEquals(5, Json.parseToJsonElement(ok.single().bodyAsText()).jsonArray.size)
        for (response in responses - ok.toSet()) {
            assertEquals(HttpStatusCode.Unauthorized, response.status)
            assertEquals("""{"error":"authentication_replay"}""", response.error())
        }
    }

    @Test
    fun clientAdapterReportsAuthenticationFailures() {
        val clock = ManualClock()
        testServer(TestDeviceRegistrationAuthorizer.allowAll(), clock) { storage, http ->
            val transport = KtorSecureMessageTransport("", http)
            val device = TestDevice(alice, clock)
            val notRegistered = assertFailsWith<SecureMessageTransportException.AuthenticationFailed> { transport.receive(alice, device.signer) }
            assertEquals(AuthenticationFailure.NOT_REGISTERED, notRegistered.failure)

            device.register(transport)
            device.register(transport)
            assertFailsWith<SecureMessageTransportException.DeviceRegistrationConflict> { TestDevice(alice, clock).register(transport) }

            val skewed = TestDevice(alice, ManualClock(clock.now + 10.minutes))
            val impostor = assertFailsWith<SecureMessageTransportException.AuthenticationFailed> { transport.receive(alice, skewed.signer) }
            assertEquals(AuthenticationFailure.EXPIRED, impostor.failure)
            val wrongKey = assertFailsWith<SecureMessageTransportException.AuthenticationFailed> { transport.receive(alice, TestDevice(alice, clock).signer) }
            assertEquals(AuthenticationFailure.INVALID, wrongKey.failure)
            assertEquals(emptyList(), transport.receive(alice, device.signer))
            assertContentEquals(device.keyPair.publicKey, storage.devices.registration(alice)?.publicKey)
        }
    }

    @Test
    fun bundleFetchStaysPublicAndSubmissionIsSignedBySender() = testServer(TestDeviceRegistrationAuthorizer.allowAll()) { storage, http ->
        val device = TestDevice(alice)
        http.register(device)
        val bobDevice = TestDevice(bob)
        http.register(bobDevice)
        val body = preKeyJson()
        http.raw(HttpMethod.Put, ServerApiPaths.device(alice, ServerApiPaths.PRE_KEYS), body, device.sign("PUT", ServerApiPaths.PRE_KEYS, body))

        val transport = KtorSecureMessageTransport("", http)
        assertEquals(alice, transport.fetchPreKeyBundle(alice).address) // no authentication headers
        transport.send(envelope("m1", alice), bobDevice.signer)
        assertEquals(listOf("m1"), storage.mailboxes.drain(alice).map { it.id.value })
    }
}
