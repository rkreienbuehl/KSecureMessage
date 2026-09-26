package dev.kreienbuehl.ksecuremessage.server.ktor

import dev.kreienbuehl.ksecuremessage.client.PreKeyConfiguration
import dev.kreienbuehl.ksecuremessage.client.ReceiveResult
import dev.kreienbuehl.ksecuremessage.client.SecureMessageClient
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException.AuthenticationFailure
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException.RotationFailure
import dev.kreienbuehl.ksecuremessage.client.ktor.KtorSecureMessageTransport
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationRotation
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationRotationAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.RequestNonce
import dev.kreienbuehl.ksecuremessage.protocol.ServerApiPaths
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequest
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequestAuthentication
import dev.kreienbuehl.ksecuremessage.protocol.VerificationState
import dev.kreienbuehl.ksecuremessage.storage.ServerStorage
import dev.kreienbuehl.ksecuremessage.storage.client.inmemory.InMemoryClientStorage
import io.ktor.client.HttpClient
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import kotlinx.coroutines.runBlocking
import kotlin.io.encoding.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes

/**
 * Routine device authentication key rotation over HTTP API v1
 * (docs/device-authentication-rotation.md):
 * `PUT /v1/devices/{user}/{device}/registration/rotation` and the signed
 * `GET /v1/devices/{user}/{device}/registration`, their status and error
 * mapping, the client adapter and client against the real routes, lost
 * responses, and rotation on persistent storage across restarts.
 */
class DeviceAuthenticationRotationRoutesTest {
    private val clock = ManualClock()
    private val phone = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val laptop = DeviceAddress(UserId("alice"), DeviceId("laptop"))
    private val bob = DeviceAddress(UserId("bob"), DeviceId("phone"))

    private fun newKey(): DeviceAuthenticationKeyPair = runBlocking { KodiumProtocolEngine().createDeviceAuthenticationKey() }

    private fun b64(bytes: ByteArray) = Base64.encode(bytes)

    private fun json(authorization: DeviceAuthenticationRotationAuthorization): String {
        val statement = authorization.statement
        return """{"currentPublicKey":"${b64(statement.currentPublicKey)}","replacementPublicKey":"${b64(statement.replacementPublicKey)}",""" +
            """"authEpoch":${statement.expectedAuthEpoch},"timestamp":${statement.timestamp.toEpochMilliseconds()},""" +
            """"nonce":"${b64(statement.nonce.bytes)}","authorizationSignature":"${b64(authorization.authorizationSignature)}",""" +
            """"proofOfPossession":"${b64(authorization.proofOfPossession)}"}"""
    }

    private suspend fun HttpClient.rotate(body: String, address: DeviceAddress = phone): HttpResponse =
        raw(HttpMethod.Put, ServerApiPaths.device(address, ServerApiPaths.REGISTRATION_ROTATION), body.encodeToByteArray(), null)

    private suspend fun HttpClient.rotate(authorization: DeviceAuthenticationRotationAuthorization): HttpResponse =
        rotate(json(authorization), authorization.statement.address)

    private fun rotation(
        current: DeviceAuthenticationKeyPair,
        replacement: DeviceAuthenticationKeyPair = newKey(),
        epoch: Long = 1,
        address: DeviceAddress = phone,
        offset: Duration = Duration.ZERO,
        nonce: RequestNonce = RequestNonce.random(),
    ) = DeviceAuthenticationRotation.create(current, replacement, address, epoch, clock.now() + offset, nonce)

    private suspend fun registered(http: HttpClient): Pair<TestDevice, TestDevice> {
        val transport = KtorSecureMessageTransport("", http)
        return (TestDevice(phone, clock) to TestDevice(laptop, clock)).also { (a, b) ->
            a.register(transport)
            b.register(transport)
        }
    }

    private suspend fun HttpClient.signed(
        method: HttpMethod,
        endpoint: String,
        key: DeviceAuthenticationKeyPair,
        address: DeviceAddress = phone,
        nonce: RequestNonce = RequestNonce.random(),
    ): HttpResponse {
        val request = ServerRequest(address, method.value, ServerApiPaths.device(address, endpoint), ByteArray(0))
        return raw(method, request.path, null, ServerRequestAuthentication.sign(key, request, clock.now(), nonce))
    }

    private suspend fun HttpClient.drain(key: DeviceAuthenticationKeyPair, nonce: RequestNonce = RequestNonce.random()) =
        signed(HttpMethod.Get, ServerApiPaths.MESSAGES, key, nonce = nonce)

    private suspend fun HttpClient.registrationState(key: DeviceAuthenticationKeyPair) = signed(HttpMethod.Get, ServerApiPaths.REGISTRATION, key)

    private suspend fun HttpResponse.assertError(status: HttpStatusCode, error: String) {
        assertEquals(status, this.status)
        assertEquals("""{"error":"$error"}""", bodyAsText())
    }

    private suspend fun ServerStorage.assertUnchanged(device: TestDevice) {
        assertContentEquals(device.keyPair.publicKey, devices.registration(device.address)?.publicKey)
        assertEquals(1, devices.registrationState(device.address)?.authEpoch)
    }

    @Test
    fun registrationStateIsSignedAndReturnsTheEpochAndInstallationTime() = testServer(clock) { _, http ->
        val registeredAt = clock.now
        val (phoneDevice) = registered(http)
        clock.now = registeredAt + 3.days
        val response = http.registrationState(phoneDevice.keyPair)
        assertEquals(HttpStatusCode.OK, response.status)
        // Exact shape: epoch and the server time of registration, in epoch milliseconds.
        assertEquals("""{"authEpoch":1,"authKeyInstalledAt":${registeredAt.toEpochMilliseconds()}}""", response.bodyAsText())

        // A rotation installs K2 at the server's time of the rotation.
        val k2 = newKey()
        clock.now = registeredAt + 30.days
        assertEquals(HttpStatusCode.NoContent, http.rotate(rotation(phoneDevice.keyPair, k2)).status)
        clock.now = registeredAt + 31.days
        assertEquals(
            """{"authEpoch":2,"authKeyInstalledAt":${(registeredAt + 30.days).toEpochMilliseconds()}}""",
            http.registrationState(k2).bodyAsText(),
        )
        http.raw(HttpMethod.Get, ServerApiPaths.device(phone, ServerApiPaths.REGISTRATION), null, null)
            .assertError(HttpStatusCode.Unauthorized, "missing_authentication")
        http.registrationState(newKey()).assertError(HttpStatusCode.Unauthorized, "invalid_authentication")
        http.signed(HttpMethod.Get, ServerApiPaths.REGISTRATION, newKey(), address = DeviceAddress(UserId("carol"), DeviceId("x")))
            .assertError(HttpStatusCode.Unauthorized, "device_not_registered")
    }

    @Test
    fun successIsNoContentAndSwitchesTheKeyAtOnce() = testServer(clock) { storage, http ->
        val (phoneDevice, laptopDevice) = registered(http)
        val k2 = newKey()
        val authorization = rotation(phoneDevice.keyPair, k2)
        assertEquals(HttpStatusCode.NoContent, http.rotate(authorization).status)
        assertEquals(HttpStatusCode.NoContent, http.rotate(authorization).status, "an exact retry is idempotent")
        assertEquals(2, storage.devices.registrationState(phone)?.authEpoch)

        // K1 is rejected on every protected endpoint, K2 accepted.
        http.drain(phoneDevice.keyPair).assertError(HttpStatusCode.Unauthorized, "invalid_authentication")
        http.registrationState(phoneDevice.keyPair).assertError(HttpStatusCode.Unauthorized, "invalid_authentication")
        http.signed(HttpMethod.Put, ServerApiPaths.PRE_KEYS, phoneDevice.keyPair).assertError(HttpStatusCode.Unauthorized, "invalid_authentication")
        assertEquals(HttpStatusCode.OK, http.drain(k2).status)
        assertEquals("""{"authEpoch":2,"authKeyInstalledAt":${clock.now.toEpochMilliseconds()}}""", http.registrationState(k2).bodyAsText())
        storage.assertUnchanged(laptopDevice)
    }

    @Test
    fun rejectionsAreMappedAndChangeNothing() = testServer(clock) { storage, http ->
        val (phoneDevice, laptopDevice) = registered(http)
        val k1 = phoneDevice.keyPair
        http.rotate(rotation(k1, epoch = 2)).assertError(HttpStatusCode.Conflict, "device_auth_rotation_conflict")
        http.rotate(rotation(newKey())).assertError(HttpStatusCode.Conflict, "device_auth_rotation_conflict")
        http.rotate(rotation(k1, offset = 5.minutes + 1.milliseconds)).assertError(HttpStatusCode.Unauthorized, "expired_authentication")
        http.rotate(rotation(k1, offset = -(5.minutes + 1.milliseconds))).assertError(HttpStatusCode.Unauthorized, "expired_authentication")
        val valid = rotation(k1)
        val forged = DeviceAuthenticationRotationAuthorization(valid.statement, rotation(newKey()).authorizationSignature, valid.proofOfPossession)
        http.rotate(forged).assertError(HttpStatusCode.Unauthorized, "invalid_device_auth_rotation_proof")
        val badPop = DeviceAuthenticationRotationAuthorization(valid.statement, valid.authorizationSignature, ByteArray(64))
        http.rotate(badPop).assertError(HttpStatusCode.Unauthorized, "invalid_device_auth_rotation_proof")
        val carol = DeviceAddress(UserId("carol"), DeviceId("tablet"))
        http.rotate(rotation(newKey(), address = carol)).assertError(HttpStatusCode.NotFound, "device_auth_rotation_not_registered")
        // The device in the path is part of what was signed: the laptop's registration does not match K1.
        http.rotate(json(valid), address = laptop).assertError(HttpStatusCode.Conflict, "device_auth_rotation_conflict")
        // A nonce the device already used for an ordinary request.
        val used = RequestNonce.random()
        assertEquals(HttpStatusCode.OK, http.drain(k1, used).status)
        http.rotate(rotation(k1, nonce = used)).assertError(HttpStatusCode.Unauthorized, "authentication_replay")
        storage.assertUnchanged(phoneDevice)
        storage.assertUnchanged(laptopDevice)

        assertEquals(HttpStatusCode.NoContent, http.rotate(valid).status, "the rejected attempts claimed nothing")
    }

    @Test
    fun malformedBodiesAreBadRequests() = testServer(clock) { storage, http ->
        val (phoneDevice) = registered(http)
        val k1 = phoneDevice.keyPair
        val authorization = rotation(k1)
        val valid = json(authorization)
        val signature = b64(authorization.authorizationSignature)
        val sameKey = valid.replace(b64(authorization.statement.replacementPublicKey), b64(k1.publicKey))
        val cases = listOf(
            "",
            "{}",
            "not json",
            sameKey,
            valid.replace(signature, signature.dropLast(4)),
            valid.replace("\"nonce\":\"", "\"nonce\":\"AAAA"),
            valid.replace(Regex("\"timestamp\":\\d+"), "\"timestamp\":-1"),
            valid.replace(Regex("\"authEpoch\":\\d+"), "\"authEpoch\":0"),
            valid.replace("\"currentPublicKey\":\"", "\"currentPublicKey\":\" "),
        )
        for (body in cases) {
            assertFalse(body == valid)
            http.rotate(body).assertError(HttpStatusCode.BadRequest, "invalid_device_auth_rotation")
        }
        storage.assertUnchanged(phoneDevice)
        assertEquals(HttpStatusCode.NoContent, http.rotate(valid).status)
    }

    @Test
    fun staleRotationIsRejectedAfterALaterOne() = testServer(clock) { storage, http ->
        val (phoneDevice) = registered(http)
        val k2 = newKey()
        val k3 = newKey()
        val first = rotation(phoneDevice.keyPair, k2)
        assertEquals(HttpStatusCode.NoContent, http.rotate(first).status)
        assertEquals(HttpStatusCode.NoContent, http.rotate(rotation(k2, k3, epoch = 2)).status)
        http.rotate(first).assertError(HttpStatusCode.Conflict, "device_auth_rotation_conflict")
        assertContentEquals(k3.publicKey, storage.devices.registration(phone)?.publicKey)
        assertEquals(3, storage.devices.registrationState(phone)?.authEpoch)
    }

    @Test
    fun clientsRotateThroughTheKtorAdapterAndMessagingIsUnaffected() = testServer(clock) { storage, http ->
        val transport = KtorSecureMessageTransport("", http)
        val engine = KodiumProtocolEngine()
        val phoneStorage = InMemoryClientStorage()
        fun client(address: DeviceAddress, clientStorage: InMemoryClientStorage) =
            SecureMessageClient(address, clientStorage, engine, transport, PreKeyConfiguration(oneTimePreKeyTarget = 3), clock)
        val phoneClient = client(phone, phoneStorage)
        val bobClient = client(bob, InMemoryClientStorage())
        for (device in listOf(phoneClient, bobClient)) {
            device.initialize()
            device.registerDevice()
            device.publishPreKeys()
        }
        bobClient.send(phone, "before".encodeToByteArray())
        assertIs<ReceiveResult.Message>(phoneClient.decrypt(phoneClient.receive().single()))
        bobClient.receive().forEach { bobClient.decrypt(it) } // the ACK
        phoneClient.markRemoteIdentityVerified(phoneClient.safetyNumber(bob))
        val safetyNumber = phoneClient.safetyNumber(bob)
        val k1 = assertNotNull(phoneStorage.deviceAuthentication.keyPair())

        phoneClient.rotateDeviceAuthenticationKey()

        val k2 = assertNotNull(phoneStorage.deviceAuthentication.keyPair())
        assertFalse(k1.publicKey.contentEquals(k2.publicKey))
        assertNull(phoneStorage.deviceAuthentication.pendingRotationKeyPair())
        assertContentEquals(k2.publicKey, storage.devices.registration(phone)?.publicKey)
        assertEquals(2, storage.devices.registrationState(phone)?.authEpoch)
        http.drain(k1).assertError(HttpStatusCode.Unauthorized, "invalid_authentication")
        val status = transport.registrationStatus(phone) { ServerRequestAuthentication.sign(k2, it, clock.now()) }
        assertEquals(2, status.authEpoch)
        assertEquals(storage.devices.registrationState(phone)?.authKeyInstalledAt, status.authKeyInstalledAt)

        // Messaging identity, verification and sessions are unchanged; the new key signs everything.
        assertEquals(VerificationState.VERIFIED, phoneClient.remoteIdentityTrust(bob)?.verification)
        assertEquals(safetyNumber.displayString, phoneClient.safetyNumber(bob).displayString)
        bobClient.send(phone, "after".encodeToByteArray())
        val message = assertIs<ReceiveResult.Message>(phoneClient.decrypt(phoneClient.receive().single()))
        assertEquals("after", message.plaintext.decodeToString())
        phoneClient.publishPreKeys()

        // A second rotation from epoch 2.
        phoneClient.rotateDeviceAuthenticationKey()
        assertEquals(3, storage.devices.registrationState(phone)?.authEpoch)

        // Error mapping of the adapter.
        val stale = assertFailsWith<SecureMessageTransportException.DeviceAuthenticationRotationRejected> {
            transport.rotateDeviceAuthenticationKey(rotation(k1, epoch = 1))
        }
        assertEquals(RotationFailure.CONFLICT, stale.reason)
        val carol = DeviceAddress(UserId("carol"), DeviceId("tablet"))
        val unknown = assertFailsWith<SecureMessageTransportException.DeviceAuthenticationRotationRejected> {
            transport.rotateDeviceAuthenticationKey(rotation(newKey(), address = carol))
        }
        assertEquals(RotationFailure.NOT_REGISTERED, unknown.reason)
        val oldKey = assertFailsWith<SecureMessageTransportException.AuthenticationFailed> {
            transport.registrationStatus(phone) { ServerRequestAuthentication.sign(k1, it, clock.now()) }
        }
        assertEquals(AuthenticationFailure.INVALID, oldKey.failure)
    }

    @Test
    fun lostResponseIsResolvedByTheClient() = testServer(clock) { storage, http ->
        val transport = KtorSecureMessageTransport("", http)
        val phoneStorage = InMemoryClientStorage()
        val phoneClient = SecureMessageClient(phone, phoneStorage, KodiumProtocolEngine(), transport, PreKeyConfiguration(oneTimePreKeyTarget = 1), clock)
        phoneClient.initialize()
        phoneClient.registerDevice()
        phoneClient.prepareDeviceAuthenticationRotation()
        val k1 = assertNotNull(phoneStorage.deviceAuthentication.keyPair())
        val k2 = assertNotNull(phoneStorage.deviceAuthentication.pendingRotationKeyPair())
        // The request reached the server and was applied; the client never saw the response.
        assertEquals(HttpStatusCode.NoContent, http.rotate(rotation(k1, k2)).status)
        assertContentEquals(k1.publicKey, phoneStorage.deviceAuthentication.keyPair()?.publicKey, "not promoted yet")

        phoneClient.completeDeviceAuthenticationRotation()

        assertContentEquals(k2.publicKey, phoneStorage.deviceAuthentication.keyPair()?.publicKey)
        assertNull(phoneStorage.deviceAuthentication.pendingRotationKeyPair())
        assertEquals(2, storage.devices.registrationState(phone)?.authEpoch, "resolved without a second transition")
        assertTrue(phoneClient.receive().isEmpty())
    }

    @Test
    fun rotationPersistsAcrossServerRestarts() = ReopenableServerStorage().use { persistent ->
        testServer(persistent, clock) { server, http ->
            val (phoneDevice) = registered(http)
            val k1 = phoneDevice.keyPair
            val k2 = newKey()
            val first = rotation(k1, k2)
            val rotatedAt = clock.now
            assertEquals(HttpStatusCode.NoContent, http.rotate(first).status)

            server.restart()
            clock.now = rotatedAt + 2.minutes
            http.drain(k1).assertError(HttpStatusCode.Unauthorized, "invalid_authentication")
            assertEquals(HttpStatusCode.OK, http.drain(k2).status)
            val expected = """{"authEpoch":2,"authKeyInstalledAt":${rotatedAt.toEpochMilliseconds()}}"""
            assertEquals(expected, http.registrationState(k2).bodyAsText())
            assertEquals(HttpStatusCode.NoContent, http.rotate(first).status, "lost-response retry after a restart")
            server.restart()
            assertEquals(expected, http.registrationState(k2).bodyAsText(), "the retry kept the installation time")

            val k3 = newKey()
            assertEquals(HttpStatusCode.NoContent, http.rotate(rotation(k2, k3, epoch = 2)).status)
            server.restart()
            http.rotate(first).assertError(HttpStatusCode.Conflict, "device_auth_rotation_conflict")
            assertContentEquals(k3.publicKey, server.devices.registration(phone)?.publicKey)
            assertEquals(3, server.devices.registrationState(phone)?.authEpoch)
            assertEquals(HttpStatusCode.OK, http.drain(k3).status)
        }
    }

    @Test
    fun storageFailureIsAGenericServerError() = ReopenableServerStorage().use { persistent ->
        testServer(persistent, clock) { server, http ->
            val (phoneDevice) = registered(http)
            server.driver.execute(null, "DROP TABLE authentication_nonce", 0)
            val response = http.rotate(rotation(phoneDevice.keyPair))
            response.assertError(HttpStatusCode.InternalServerError, "internal_error")
            assertContentEquals(phoneDevice.keyPair.publicKey, server.devices.registration(phone)?.publicKey)
            assertEquals(1, server.devices.registrationState(phone)?.authEpoch)
        }
    }
}
