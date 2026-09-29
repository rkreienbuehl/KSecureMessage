package dev.kreienbuehl.ksecuremessage.server.ktor

import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException
import dev.kreienbuehl.ksecuremessage.client.ktor.KtorSecureMessageTransport
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.MessageId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.ServerApiPaths
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import kotlinx.serialization.json.Json
import kotlin.io.encoding.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * HTTP behavior of the S1 fixes (docs/security-review-remediation.md):
 * host-authorized registration (F1/F2) and signed message submission (F4).
 */
class SecurityRemediationRoutesTest {
    private val alice = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val aliceLaptop = DeviceAddress(UserId("alice"), DeviceId("laptop"))
    private val mallory = DeviceAddress(UserId("alice"), DeviceId("mallory"))
    private val bob = DeviceAddress(UserId("bob"), DeviceId("phone"))

    private fun registrationBody(device: TestDevice) = """{"publicKey":"${Base64.encode(device.keyPair.publicKey)}"}""".encodeToByteArray()

    private suspend fun io.ktor.client.HttpClient.register(device: TestDevice): HttpResponse {
        val body = registrationBody(device)
        return raw(HttpMethod.Put, ServerApiPaths.device(device.address, ServerApiPaths.REGISTRATION), body, device.sign("PUT", ServerApiPaths.REGISTRATION, body))
    }

    private suspend fun io.ktor.client.HttpClient.submit(
        signer: TestDevice,
        envelope: EncryptedEnvelope,
        headers: Map<String, String> = signer.submissionHeaders(),
        signed: Boolean = true,
    ): HttpResponse {
        val body = Json.encodeToString(envelope).encodeToByteArray()
        return raw(HttpMethod.Post, ServerApiPaths.SUBMIT_MESSAGE, body, if (signed) signer.signSubmission(body) else null, headers)
    }

    private suspend fun HttpResponse.assertError(status: HttpStatusCode, error: String) {
        assertEquals(status, this.status)
        assertEquals("""{"error":"$error"}""", bodyAsText())
    }

    private fun envelope(sender: DeviceAddress, recipient: DeviceAddress, id: String = "m1") =
        EncryptedEnvelope(MessageId(id), sender, recipient, payload = byteArrayOf(1))

    // F1/F2

    @Test
    fun f1DeniedRegistrationIs403AndStoresNothing() {
        val authorizer = TestDeviceRegistrationAuthorizer.allowOnly(alice)
        testServer(authorizer) { storage, http ->
            assertEquals(HttpStatusCode.Created, http.register(TestDevice(alice)).status)
            http.register(TestDevice(mallory)).assertError(HttpStatusCode.Forbidden, "registration_not_authorized")
            assertNull(storage.devices.registration(mallory))
            // A request that fails authentication is 401 and never reaches the host.
            val forged = TestDevice(aliceLaptop)
            val body = registrationBody(TestDevice(aliceLaptop))
            http.raw(HttpMethod.Put, ServerApiPaths.device(aliceLaptop, ServerApiPaths.REGISTRATION), body, forged.sign("PUT", ServerApiPaths.REGISTRATION, body))
                .assertError(HttpStatusCode.Unauthorized, "invalid_authentication")
            assertEquals(listOf(alice, mallory), authorizer.requests.map { it.address })
        }
    }

    @Test
    fun f1ClientTransportReportsTheDenial() = testServer(TestDeviceRegistrationAuthorizer.denyAll()) { storage, http ->
        val transport = KtorSecureMessageTransport("", http)
        assertFailsWith<SecureMessageTransportException.DeviceRegistrationNotAuthorized> { TestDevice(alice).register(transport) }
        assertFalse(storage.devices.hasRegisteredDevices(alice.userId))
    }

    @Test
    fun sameKeyRetryIs204WithoutAskingTheHost() {
        val authorizer = TestDeviceRegistrationAuthorizer.allowOnly(alice)
        testServer(authorizer) { _, http ->
            val device = TestDevice(alice)
            assertEquals(HttpStatusCode.Created, http.register(device).status)
            assertEquals(HttpStatusCode.NoContent, http.register(device).status)
            assertEquals(1, authorizer.requests.size)
            http.register(TestDevice(alice)).assertError(HttpStatusCode.Conflict, "device_registration_conflict")
            assertEquals(1, authorizer.requests.size, "a conflict is no authorization question")
        }
    }

    @Test
    fun authorizerFailureIsAGeneric500() = testServer(TestDeviceRegistrationAuthorizer.throwing()) { storage, http ->
        val response = http.register(TestDevice(alice))
        response.assertError(HttpStatusCode.InternalServerError, "internal_error")
        assertFalse(response.bodyAsText().contains("secret"), "no host exception text")
        assertNull(storage.devices.registration(alice))
    }

    @Test
    fun registrationKeyMustBeCanonicalBase64() = testServer(TestDeviceRegistrationAuthorizer.allowAll()) { storage, http ->
        val device = TestDevice(alice)
        // Standard Base64 with its padding removed: lenient decoders accept it, the route does not.
        val body = """{"publicKey":"${Base64.encode(device.keyPair.publicKey).trimEnd('=')}"}""".encodeToByteArray()
        http.raw(HttpMethod.Put, ServerApiPaths.device(alice, ServerApiPaths.REGISTRATION), body, device.sign("PUT", ServerApiPaths.REGISTRATION, body))
            .assertError(HttpStatusCode.BadRequest, "invalid_registration")
        assertNull(storage.devices.registration(alice))
    }

    // F4

    @Test
    fun f4SubmissionWhoseSenderIsNotTheSignerIs403AndQueuesNothing() = testServer(TestDeviceRegistrationAuthorizer.allowAll()) { storage, http ->
        val aliceDevice = TestDevice(alice)
        val malloryDevice = TestDevice(DeviceAddress(UserId("mallory"), DeviceId("phone")))
        http.register(aliceDevice)
        http.register(malloryDevice)
        http.register(TestDevice(bob))
        // Mallory signs as herself, names Alice as the sender.
        http.submit(malloryDevice, envelope(alice, bob)).assertError(HttpStatusCode.Forbidden, "sender_mismatch")
        // Mallory names Alice in the device header, signed with her own key.
        http.submit(malloryDevice, envelope(alice, bob), headers = aliceDevice.submissionHeaders())
            .assertError(HttpStatusCode.Unauthorized, "invalid_authentication")
        assertTrue(storage.mailboxes.drain(bob).isEmpty(), "nothing queued")
        // Alice herself succeeds.
        assertEquals(HttpStatusCode.Accepted, http.submit(aliceDevice, envelope(alice, bob)).status)
        assertEquals(listOf(alice), storage.mailboxes.drain(bob).map { it.sender })
    }

    @Test
    fun unsignedOrUnnamedSubmissionIs401() = testServer(TestDeviceRegistrationAuthorizer.allowAll()) { storage, http ->
        val aliceDevice = TestDevice(alice)
        http.register(aliceDevice)
        http.submit(aliceDevice, envelope(alice, bob), signed = false).assertError(HttpStatusCode.Unauthorized, "missing_authentication")
        http.submit(aliceDevice, envelope(alice, bob), headers = emptyMap()).assertError(HttpStatusCode.Unauthorized, "missing_authentication")
        for (header in listOf("alice", "alice/phone/x", "alice/ph%6Fne", "alice/ph%6fne", "%FF/phone")) {
            http.submit(aliceDevice, envelope(alice, bob), headers = mapOf(AuthHeaders.DEVICE to header))
                .assertError(HttpStatusCode.Unauthorized, "invalid_authentication")
        }
        http.submit(TestDevice(bob), envelope(bob, alice)).assertError(HttpStatusCode.Unauthorized, "device_not_registered")
        assertTrue(storage.mailboxes.drain(bob).isEmpty())
        assertTrue(storage.mailboxes.drain(alice).isEmpty())
    }

    @Test
    fun submissionSignatureCoversTheExactBody() = testServer(TestDeviceRegistrationAuthorizer.allowAll()) { storage, http ->
        val aliceDevice = TestDevice(alice)
        http.register(aliceDevice)
        val signedBody = Json.encodeToString(envelope(alice, bob, "m1")).encodeToByteArray()
        val otherBody = Json.encodeToString(envelope(alice, bob, "m2")).encodeToByteArray()
        http.raw(HttpMethod.Post, ServerApiPaths.SUBMIT_MESSAGE, otherBody, aliceDevice.signSubmission(signedBody), aliceDevice.submissionHeaders())
            .assertError(HttpStatusCode.Unauthorized, "invalid_authentication")
        // A drain signature of the device is no submission signature.
        http.raw(HttpMethod.Post, ServerApiPaths.SUBMIT_MESSAGE, ByteArray(0), aliceDevice.sign("GET", ServerApiPaths.MESSAGES, ByteArray(0)), aliceDevice.submissionHeaders())
            .assertError(HttpStatusCode.Unauthorized, "invalid_authentication")
        assertTrue(storage.mailboxes.drain(bob).isEmpty())
    }

    @Test
    fun f4ClientTransportCannotSubmitAsAnotherDevice() = testServer(TestDeviceRegistrationAuthorizer.allowAll()) { storage, http ->
        val transport = KtorSecureMessageTransport("", http)
        val aliceDevice = TestDevice(alice)
        aliceDevice.register(transport)
        val malloryDevice = TestDevice(DeviceAddress(UserId("mallory"), DeviceId("phone")))
        malloryDevice.register(transport)
        // The transport names the envelope's sender in the header; Mallory's key does not verify for Alice.
        assertFailsWith<SecureMessageTransportException.AuthenticationFailed> { transport.send(envelope(alice, bob), malloryDevice.signer) }
        transport.send(envelope(alice, bob), aliceDevice.signer)
        assertEquals(1, storage.mailboxes.drain(bob).size)
    }
}
