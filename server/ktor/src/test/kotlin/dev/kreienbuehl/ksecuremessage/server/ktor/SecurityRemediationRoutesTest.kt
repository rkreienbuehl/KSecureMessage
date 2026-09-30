package dev.kreienbuehl.ksecuremessage.server.ktor

import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException
import dev.kreienbuehl.ksecuremessage.client.ktor.KtorSecureMessageTransport
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.MessageId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.ServerApiPaths
import io.ktor.client.plugins.DefaultRequest
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import kotlinx.serialization.json.Json
import kotlin.io.encoding.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation as ClientContentNegotiation

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

    private suspend fun io.ktor.client.HttpClient.register(device: TestDevice, principal: String? = null): HttpResponse {
        val body = registrationBody(device)
        val headers = principal?.let { mapOf(TestRegistrationContexts.PRINCIPAL_HEADER to it) } ?: emptyMap()
        return raw(HttpMethod.Put, ServerApiPaths.device(device.address, ServerApiPaths.REGISTRATION), body, device.sign("PUT", ServerApiPaths.REGISTRATION, body), headers)
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
        assertNull(storage.devices.registration(alice))
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

    // N1: the host's authenticated principal reaches the authorizer; nothing else stands in for it.

    @Test
    fun n1RegistrationAuthorizationReceivesTheAuthenticatedApplicationPrincipal() {
        val authorizer = TestDeviceRegistrationAuthorizer.principalOwnsUser()
        testServer(authorizer, registrationContext = TestRegistrationContexts.header) { storage, http ->
            assertEquals(HttpStatusCode.Created, http.register(TestDevice(alice), principal = "alice").status)
            val tablet = DeviceAddress(UserId("alice"), DeviceId("tablet"))
            assertEquals(HttpStatusCode.Created, http.register(TestDevice(tablet), principal = "alice").status)
            assertEquals(listOf(TestRegistrationPrincipal(UserId("alice")), TestRegistrationPrincipal(UserId("alice"))), authorizer.contexts)
            assertEquals(listOf(alice, tablet), authorizer.requests.map { it.address })
            assertTrue(storage.devices.registration(tablet) != null)
        }
    }

    @Test
    fun n1WrongPrincipalCannotRegisterAnotherUsersDevice() {
        val authorizer = TestDeviceRegistrationAuthorizer.principalOwnsUser()
        testServer(authorizer, registrationContext = TestRegistrationContexts.header) { storage, http ->
            // Mallory is properly authenticated by the host, as Mallory.
            http.register(TestDevice(alice), principal = "mallory").assertError(HttpStatusCode.Forbidden, "registration_not_authorized")
            assertNull(storage.devices.registration(alice))
            assertEquals(listOf(TestRegistrationPrincipal(UserId("mallory"))), authorizer.contexts, "decided with Mallory's principal, not the target user")
            // Alice's own device is still free for Alice.
            assertEquals(HttpStatusCode.Created, http.register(TestDevice(alice), principal = "alice").status)
        }
    }

    @Test
    fun n1MissingContextIsDeniedAndRegistersNothing() {
        val authorizer = TestDeviceRegistrationAuthorizer.allowAll()
        testServer(authorizer, registrationContext = TestRegistrationContexts.header) { storage, http ->
            val device = TestDevice(alice)
            http.register(device).assertError(HttpStatusCode.Forbidden, "registration_not_authorized")
            assertNull(storage.devices.registration(alice))
            assertTrue(authorizer.requests.isEmpty(), "no anonymous path reaches even an allow-all authorizer")
            // With the host's authentication it registers; a later retry of the same key needs none.
            assertEquals(HttpStatusCode.Created, http.register(device, principal = "alice").status)
            assertEquals(HttpStatusCode.NoContent, http.register(device).status)
            http.register(TestDevice(alice)).assertError(HttpStatusCode.Conflict, "device_registration_conflict")
            assertEquals(1, authorizer.requests.size)
        }
    }

    @Test
    fun n1HostFailuresLeakNoContext() {
        val secret = "principal alice session=SECRET-CONTEXT-7f3a"
        // The authorizer throws with context text.
        val logger = RecordingLogger()
        testServer(
            TestDeviceRegistrationAuthorizer.throwing(IllegalStateException(secret)),
            registrationContext = TestRegistrationContexts.header,
            logger = logger,
        ) { storage, http ->
            val response = http.register(TestDevice(alice), principal = "alice")
            response.assertError(HttpStatusCode.InternalServerError, "internal_error")
            assertNull(storage.devices.registration(alice), "nothing written")
        }
        // The extractor throws with context text.
        testServer(
            TestDeviceRegistrationAuthorizer.allowAll(),
            registrationContext = DeviceRegistrationContextExtractor { throw IllegalStateException(secret) },
            logger = logger,
        ) { storage, http ->
            http.register(TestDevice(alice)).assertError(HttpStatusCode.InternalServerError, "internal_error")
            assertNull(storage.devices.registration(alice), "nothing written")
        }
        val logged = logger.everything()
        assertTrue(logged.contains("Registration authorization failed"), "the failure is logged")
        assertFalse(logged.contains("SECRET-CONTEXT"), "no host exception text, stack or context in the log")
    }

    @Test
    fun n1ClientWithTheHostsAuthenticationRegistersThroughTheKtorAdapter() {
        val authorizer = TestDeviceRegistrationAuthorizer.principalOwnsUser()
        testServer(authorizer, registrationContext = TestRegistrationContexts.header) { storage, _ ->
            // The application's HTTP client carries its own authentication; KSecureMessage passes it through.
            fun clientAs(user: String) = createClient {
                install(ClientContentNegotiation) { json() }
                install(DefaultRequest) { headers.append(TestRegistrationContexts.PRINCIPAL_HEADER, user) }
            }
            TestDevice(alice).register(KtorSecureMessageTransport("", clientAs("alice")))
            assertTrue(storage.devices.registration(alice) != null)
            assertFailsWith<SecureMessageTransportException.DeviceRegistrationNotAuthorized> {
                TestDevice(aliceLaptop).register(KtorSecureMessageTransport("", clientAs("mallory")))
            }
            assertNull(storage.devices.registration(aliceLaptop))
        }
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
