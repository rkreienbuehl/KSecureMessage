package dev.kreienbuehl.ksecuremessage.server.ktor

import dev.kreienbuehl.ksecuremessage.client.LastDeviceRecoveryKeyRevocationResult
import dev.kreienbuehl.ksecuremessage.client.LastDeviceRecoveryKeyRotationResult
import dev.kreienbuehl.ksecuremessage.client.PreKeyConfiguration
import dev.kreienbuehl.ksecuremessage.client.ReceiveResult
import dev.kreienbuehl.ksecuremessage.client.SecureMessageClient
import dev.kreienbuehl.ksecuremessage.client.SecureMessageClientException
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransport
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException.RecoveryKeyFailure
import dev.kreienbuehl.ksecuremessage.client.ServerRequestSigner
import dev.kreienbuehl.ksecuremessage.client.ktor.KtorSecureMessageTransport
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.LastDeviceRecoveryKeyStatus
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecovery
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryKey
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRevocation
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRevocationAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRotation
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRotationAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.RequestNonce
import dev.kreienbuehl.ksecuremessage.protocol.ServerApiPaths
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
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes

/**
 * Recovery key rotation and revocation over HTTP API v1
 * (docs/recovery-key-lifecycle.md): the signed `GET …/last-device-recovery/key`,
 * `PUT …/key/rotation` and `PUT …/key/revocation`, their status and error
 * mapping, the client adapter and client against the real routes, lost
 * responses, persistence across restarts and `internal_error`.
 */
class RecoveryKeyLifecycleRoutesTest {
    private val clock = ManualClock()
    private val phone = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val laptop = DeviceAddress(UserId("alice"), DeviceId("laptop"))
    private val bob = DeviceAddress(UserId("bob"), DeviceId("phone"))
    private val engine = KodiumProtocolEngine()

    private fun newRecoveryKey(): LastDeviceRecoveryKey = runBlocking { engine.createLastDeviceRecoveryKey() }
    private val r1 = newRecoveryKey()
    private val r2 = newRecoveryKey()
    private val r3 = newRecoveryKey()

    private fun b64(bytes: ByteArray) = Base64.encode(bytes)

    private fun json(authorization: RecoveryKeyRotationAuthorization): String {
        val s = authorization.statement
        return """{"currentPublicKey":"${b64(s.currentPublicKey)}","newPublicKey":"${b64(s.newPublicKey)}",""" +
            """"recoveryKeyEpoch":${s.expectedEpoch},"timestamp":${s.timestamp.toEpochMilliseconds()},"nonce":"${b64(s.nonce.bytes)}",""" +
            """"currentKeySignature":"${b64(authorization.currentKeySignature)}","newKeyProofOfPossession":"${b64(authorization.newKeyProofOfPossession)}"}"""
    }

    private fun json(authorization: RecoveryKeyRevocationAuthorization): String {
        val s = authorization.statement
        return """{"publicKey":"${b64(s.currentPublicKey)}","recoveryKeyEpoch":${s.expectedEpoch},""" +
            """"timestamp":${s.timestamp.toEpochMilliseconds()},"nonce":"${b64(s.nonce.bytes)}","signature":"${b64(authorization.signature)}"}"""
    }

    private suspend fun HttpClient.signed(device: TestDevice?, method: HttpMethod, endpoint: String, body: String?, address: DeviceAddress = device!!.address): HttpResponse {
        val bytes = body?.encodeToByteArray()
        return raw(method, ServerApiPaths.device(address, endpoint), bytes, device?.sign(method.value, endpoint, bytes ?: ByteArray(0), address))
    }

    private suspend fun HttpClient.status(device: TestDevice?) =
        signed(device, HttpMethod.Get, ServerApiPaths.LAST_DEVICE_RECOVERY_KEY, null, device?.address ?: phone)

    private suspend fun HttpClient.rotate(device: TestDevice?, body: String, address: DeviceAddress = device!!.address) =
        signed(device, HttpMethod.Put, ServerApiPaths.LAST_DEVICE_RECOVERY_KEY_ROTATION, body, address)

    private suspend fun HttpClient.revoke(device: TestDevice?, body: String, address: DeviceAddress = device!!.address) =
        signed(device, HttpMethod.Put, ServerApiPaths.LAST_DEVICE_RECOVERY_KEY_REVOCATION, body, address)

    private suspend fun HttpClient.registerKey(device: TestDevice, key: LastDeviceRecoveryKey): HttpResponse {
        val registration = LastDeviceRecovery.registerKey(key, device.address.userId)
        return signed(
            device, HttpMethod.Put, ServerApiPaths.LAST_DEVICE_RECOVERY_KEY,
            """{"publicKey":"${b64(registration.publicKey)}","proofOfPossession":"${b64(registration.proofOfPossession)}"}""",
        )
    }

    private suspend fun HttpResponse.assertError(status: HttpStatusCode, error: String) {
        assertEquals(status, this.status)
        assertEquals("""{"error":"$error"}""", bodyAsText())
    }

    private fun rotation(current: LastDeviceRecoveryKey = r1, new: LastDeviceRecoveryKey = r2, epoch: Long = 1, authorizer: DeviceAddress = phone, nonce: RequestNonce = RequestNonce.random()) =
        RecoveryKeyRotation.authorize(current, new, authorizer, epoch, clock.now(), nonce)

    private fun revocation(current: LastDeviceRecoveryKey = r1, epoch: Long = 1, authorizer: DeviceAddress = phone) =
        RecoveryKeyRevocation.authorize(current, authorizer, epoch, clock.now())

    /** Phone, laptop and Bob registered; the phone registered R1 (unless not wanted). */
    private suspend fun registered(http: HttpClient, withRecoveryKey: Boolean = true): Triple<TestDevice, TestDevice, TestDevice> {
        val transport = KtorSecureMessageTransport("", http)
        val devices = Triple(TestDevice(phone, clock), TestDevice(laptop, clock), TestDevice(bob, clock))
        devices.toList().forEach { it.register(transport) }
        if (withRecoveryKey) assertEquals(HttpStatusCode.Created, http.registerKey(devices.first, r1).status)
        return devices
    }

    @Test
    fun statusIsSignedAndMinimal() = testServer(clock) { _, http ->
        val (phoneDevice, laptopDevice, bobDevice) = registered(http, withRecoveryKey = false)
        http.status(null).assertError(HttpStatusCode.Unauthorized, "missing_authentication")
        val unconfigured = """{"state":"unconfigured","recoveryKeyEpoch":null,"installedAt":null,"revokedAt":null,"activePublicKey":null}"""
        assertEquals(unconfigured, http.status(phoneDevice).bodyAsText())

        assertEquals(HttpStatusCode.Created, http.registerKey(phoneDevice, r1).status)
        val t = clock.now.toEpochMilliseconds()
        val active = """{"state":"active","recoveryKeyEpoch":1,"installedAt":$t,"revokedAt":null,"activePublicKey":"${b64(r1.publicKey)}"}"""
        assertEquals(active, http.status(laptopDevice).bodyAsText(), "every registered device of the user")
        assertEquals(unconfigured, http.status(bobDevice).bodyAsText(), "per user")

        clock.now += 1.minutes
        assertEquals(HttpStatusCode.NoContent, http.revoke(phoneDevice, json(revocation())).status)
        val revoked = """{"state":"revoked","recoveryKeyEpoch":2,"installedAt":null,"revokedAt":${clock.now.toEpochMilliseconds()},"activePublicKey":null}"""
        assertEquals(revoked, http.status(phoneDevice).bodyAsText())
    }

    @Test
    fun rotationIsSignedAndCarriesBothProofs() = testServer(clock) { storage, http ->
        val (phoneDevice, laptopDevice, bobDevice) = registered(http)
        val authorization = rotation()
        http.rotate(null, json(authorization), phone).assertError(HttpStatusCode.Unauthorized, "missing_authentication")
        // The authorizing device is the route's: the phone's statement submitted by the laptop names the laptop, so R1's signature fails.
        http.rotate(laptopDevice, json(authorization)).assertError(HttpStatusCode.Unauthorized, "recovery_key_rotation_invalid_proof")
        http.rotate(bobDevice, json(RecoveryKeyRotation.authorize(r1, r2, bob, 1, clock.now())))
            .assertError(HttpStatusCode.NotFound, "recovery_key_not_configured")
        val forged = RecoveryKeyRotationAuthorization(authorization.statement, authorization.currentKeySignature, authorization.currentKeySignature)
        http.rotate(phoneDevice, json(forged)).assertError(HttpStatusCode.Unauthorized, "recovery_key_rotation_invalid_proof")
        http.rotate(phoneDevice, json(rotation(current = r3))).assertError(HttpStatusCode.Conflict, "recovery_key_rotation_conflict")
        http.rotate(phoneDevice, json(rotation(epoch = 2))).assertError(HttpStatusCode.Conflict, "recovery_key_rotation_conflict")
        clock.now += 5.minutes + 1.milliseconds
        http.rotate(phoneDevice, json(authorization)).assertError(HttpStatusCode.Unauthorized, "recovery_key_rotation_expired")
        clock.now -= 5.minutes + 1.milliseconds
        assertContentEquals(r1.publicKey, storage.lastDeviceRecovery.recoveryKey(phone.userId))

        assertEquals(HttpStatusCode.NoContent, http.rotate(phoneDevice, json(authorization)).status)
        assertContentEquals(r2.publicKey, storage.lastDeviceRecovery.recoveryKey(phone.userId))
        // The response was lost: the identical body again, with a fresh ServerAuth nonce, even much later.
        clock.now += 1.days
        assertEquals(HttpStatusCode.NoContent, http.rotate(phoneDevice, json(authorization)).status)
        assertEquals(2, storage.lastDeviceRecovery.recoveryKeyState(phone.userId)?.epoch)

        // A statement nonce is single-use.
        val nonce = RequestNonce.random()
        assertEquals(HttpStatusCode.NoContent, http.rotate(phoneDevice, json(rotation(r2, r3, epoch = 2, nonce = nonce))).status)
        http.rotate(phoneDevice, json(rotation(r3, r1, epoch = 3, nonce = nonce))).assertError(HttpStatusCode.Unauthorized, "recovery_key_rotation_replay")
        clock.now -= 1.days
        http.rotate(phoneDevice, json(authorization)).assertError(HttpStatusCode.Conflict, "recovery_key_rotation_conflict")
        assertContentEquals(r3.publicKey, storage.lastDeviceRecovery.recoveryKey(phone.userId))
    }

    @Test
    fun malformedRotationAndRevocationBodiesAreBadRequests() = testServer(clock) { storage, http ->
        val (phoneDevice, _, _) = registered(http)
        val good = json(rotation())
        for (body in listOf(
            "{",
            good.replace("\"recoveryKeyEpoch\":1", "\"recoveryKeyEpoch\":0"),
            good.replace(b64(r2.publicKey), b64(r1.publicKey)), // same key
            good.replace(b64(r2.publicKey), b64(r2.publicKey).dropLast(1)),
            good.replace("\"timestamp\":", "\"timestamp\":-"),
        )) {
            http.rotate(phoneDevice, body).assertError(HttpStatusCode.BadRequest, "invalid_recovery_key_rotation")
        }
        val revoke = json(revocation())
        for (body in listOf("[]", revoke.replace("\"recoveryKeyEpoch\":1", "\"recoveryKeyEpoch\":-1"), revoke.replace(b64(r1.publicKey), "AAAA"))) {
            http.revoke(phoneDevice, body).assertError(HttpStatusCode.BadRequest, "invalid_recovery_key_revocation")
        }
        assertEquals(1, storage.lastDeviceRecovery.recoveryKeyState(phone.userId)?.epoch)
    }

    @Test
    fun revocationEndsRecoveryUntilANewKeyIsRegistered() = testServer(clock) { storage, http ->
        val (phoneDevice, laptopDevice, _) = registered(http)
        val authorization = revocation()
        http.revoke(null, json(authorization), phone).assertError(HttpStatusCode.Unauthorized, "missing_authentication")
        http.revoke(phoneDevice, json(RecoveryKeyRevocationAuthorization(authorization.statement, revocation(r2).signature)))
            .assertError(HttpStatusCode.Unauthorized, "recovery_key_revocation_invalid_proof")
        http.revoke(phoneDevice, json(revocation(epoch = 2))).assertError(HttpStatusCode.Conflict, "recovery_key_revocation_conflict")
        val challenge = raw(http, HttpMethod.Post, ServerApiPaths.LAST_DEVICE_RECOVERY_CHALLENGE)
        assertEquals(HttpStatusCode.OK, challenge.status)

        assertEquals(HttpStatusCode.NoContent, http.revoke(phoneDevice, json(authorization)).status)
        assertEquals(HttpStatusCode.NoContent, http.revoke(phoneDevice, json(authorization)).status, "lost-response retry")
        raw(http, HttpMethod.Post, ServerApiPaths.LAST_DEVICE_RECOVERY_CHALLENGE).assertError(HttpStatusCode.NotFound, "last_device_recovery_not_configured")
        http.revoke(laptopDevice, json(revocation(epoch = 2, authorizer = laptop))).assertError(HttpStatusCode.NotFound, "recovery_key_not_configured")

        assertEquals(HttpStatusCode.Created, http.registerKey(laptopDevice, r3).status)
        assertEquals(3, storage.lastDeviceRecovery.recoveryKeyState(phone.userId)?.epoch)
        assertEquals(HttpStatusCode.OK, raw(http, HttpMethod.Post, ServerApiPaths.LAST_DEVICE_RECOVERY_CHALLENGE).status)
    }

    private suspend fun raw(http: HttpClient, method: HttpMethod, endpoint: String): HttpResponse =
        http.raw(method, ServerApiPaths.device(phone, endpoint), null, null)

    @Test
    fun clientUsesTheRoutesThroughTheKtorAdapter() = testServer(clock) { storage, http ->
        val transport = KtorSecureMessageTransport("", http)
        // Applies the phone's rotation on the server, then loses the response once.
        var loseNextResponse = false
        val losing = object : SecureMessageTransport by transport {
            override suspend fun rotateLastDeviceRecoveryKey(authorization: RecoveryKeyRotationAuthorization, signer: ServerRequestSigner) {
                transport.rotateLastDeviceRecoveryKey(authorization, signer)
                if (loseNextResponse) {
                    loseNextResponse = false
                    throw SecureMessageTransportException.UnexpectedResponse(504)
                }
            }
        }
        fun client(address: DeviceAddress, via: SecureMessageTransport = transport) =
            SecureMessageClient(address, InMemoryClientStorage(), engine, via, PreKeyConfiguration(oneTimePreKeyTarget = 2), clock)
        val phoneClient = client(phone, losing)
        val laptopClient = client(laptop)
        val bobClient = client(bob)
        for (device in listOf(phoneClient, laptopClient, bobClient)) {
            device.initialize()
            device.registerDevice()
            device.publishPreKeys()
        }
        assertEquals(LastDeviceRecoveryKeyStatus.Unconfigured, phoneClient.lastDeviceRecoveryKeyStatus())
        phoneClient.registerLastDeviceRecoveryKey(r1)
        bobClient.send(phone, "hi".encodeToByteArray())
        assertIs<ReceiveResult.Message>(phoneClient.decrypt(phoneClient.receive().single()))

        // The rotation reached the server, but the client never saw the response; calling again resolves it.
        loseNextResponse = true
        assertFailsWith<SecureMessageTransportException.UnexpectedResponse> { phoneClient.rotateLastDeviceRecoveryKey(r1, r2) }
        assertEquals(LastDeviceRecoveryKeyRotationResult.ALREADY_ACTIVE, phoneClient.rotateLastDeviceRecoveryKey(r1, r2))
        val active = assertIs<LastDeviceRecoveryKeyStatus.Active>(laptopClient.lastDeviceRecoveryKeyStatus())
        assertEquals(2, active.epoch)
        assertTrue(active.isKey(r2.publicKey))

        assertEquals(LastDeviceRecoveryKeyRotationResult.ROTATED, laptopClient.rotateLastDeviceRecoveryKey(r2, r3))
        assertFailsWith<SecureMessageClientException.LastDeviceRecoveryKeyMismatch> { phoneClient.rotateLastDeviceRecoveryKey(r2, r1) }

        assertEquals(LastDeviceRecoveryKeyRevocationResult.REVOKED, laptopClient.revokeLastDeviceRecoveryKey(r3))
        assertEquals(LastDeviceRecoveryKeyRevocationResult.ALREADY_REVOKED, phoneClient.revokeLastDeviceRecoveryKey(r3))
        assertFailsWith<SecureMessageClientException.LastDeviceRecoveryKeyNotConfigured> { phoneClient.rotateLastDeviceRecoveryKey(r3, r1) }

        phoneClient.registerLastDeviceRecoveryKey(r1)
        assertEquals(5, assertIs<LastDeviceRecoveryKeyStatus.Active>(phoneClient.lastDeviceRecoveryKeyStatus()).epoch, "the epoch continues")
        assertEquals(1, storage.devices.registrationState(phone)?.authEpoch, "device authentication untouched")
        bobClient.receive().forEach { bobClient.decrypt(it) }
        bobClient.send(phone, "still here".encodeToByteArray())
        assertIs<ReceiveResult.Message>(phoneClient.decrypt(phoneClient.receive().single()))
    }

    @Test
    fun lifecyclePersistsAcrossServerRestarts() = ReopenableServerStorage().use { persistent ->
        testServer(persistent, clock) { server, http ->
            val (phoneDevice, laptopDevice, _) = registered(http)
            val oldChallenge = raw(http, HttpMethod.Post, ServerApiPaths.LAST_DEVICE_RECOVERY_CHALLENGE).bodyAsText()
            val first = rotation()
            assertEquals(HttpStatusCode.NoContent, http.rotate(phoneDevice, json(first)).status)
            server.restart()
            assertContentEquals(r2.publicKey, server.lastDeviceRecovery.recoveryKey(phone.userId))
            assertEquals(HttpStatusCode.NoContent, http.rotate(phoneDevice, json(first)).status, "exact retry after a restart")
            assertTrue(oldChallenge != raw(http, HttpMethod.Post, ServerApiPaths.LAST_DEVICE_RECOVERY_CHALLENGE).bodyAsText(), "the old challenge is gone")
            http.rotate(phoneDevice, json(rotation(r1, r3))).assertError(HttpStatusCode.Conflict, "recovery_key_rotation_conflict")

            clock.now += 1.minutes
            assertEquals(HttpStatusCode.NoContent, http.revoke(laptopDevice, json(revocation(r2, epoch = 2, authorizer = laptop))).status)
            server.restart()
            assertIs<LastDeviceRecoveryKeyStatus.Revoked>(KtorSecureMessageTransport("", http).lastDeviceRecoveryKeyStatus(phone, phoneDevice.signer))
            raw(http, HttpMethod.Post, ServerApiPaths.LAST_DEVICE_RECOVERY_CHALLENGE).assertError(HttpStatusCode.NotFound, "last_device_recovery_not_configured")

            assertEquals(HttpStatusCode.Created, http.registerKey(phoneDevice, r3).status)
            server.restart()
            val state = server.lastDeviceRecovery.recoveryKeyState(phone.userId)
            assertEquals(4, state?.epoch, "monotonic across restarts")
            assertContentEquals(r3.publicKey, state?.publicKey)
            http.rotate(phoneDevice, json(first)).assertError(HttpStatusCode.Conflict, "recovery_key_rotation_conflict")
            assertEquals(1, server.devices.registrationState(phone)?.authEpoch)
        }
    }

    @Test
    fun epochExhaustionIsReported() = ReopenableServerStorage().use { persistent ->
        testServer(persistent, clock) { server, http ->
            val (phoneDevice, _, _) = registered(http)
            server.driver.execute(null, "UPDATE last_device_recovery_key_state SET epoch = ${Long.MAX_VALUE - 1}", 0)
            assertEquals(HttpStatusCode.NoContent, http.revoke(phoneDevice, json(revocation(epoch = Long.MAX_VALUE - 1))).status)
            http.registerKey(phoneDevice, r2).assertError(HttpStatusCode.Conflict, "recovery_key_epoch_exhausted")
            val rejected = assertFailsWith<SecureMessageTransportException.LastDeviceRecoveryKeyRejected> {
                KtorSecureMessageTransport("", http).registerLastDeviceRecoveryKey(phone, LastDeviceRecovery.registerKey(r2, phone.userId), phoneDevice.signer)
            }
            assertEquals(RecoveryKeyFailure.EPOCH_EXHAUSTED, rejected.reason)

            server.driver.execute(null, "UPDATE last_device_recovery_key_state SET state = 1, public_key = X'${r1.publicKey.toHex()}', installed_at = 0, revocation_id = NULL", 0)
            http.rotate(phoneDevice, json(rotation(epoch = Long.MAX_VALUE))).assertError(HttpStatusCode.Conflict, "recovery_key_epoch_exhausted")
        }
    }

    @Test
    fun storageFailureIsAGenericServerError() = ReopenableServerStorage().use { persistent ->
        testServer(persistent, clock) { server, http ->
            val (phoneDevice, _, _) = registered(http)
            server.driver.execute(null, "DROP TABLE last_device_recovery_key_state", 0)
            http.status(phoneDevice).assertError(HttpStatusCode.InternalServerError, "internal_error")
            http.rotate(phoneDevice, json(rotation())).assertError(HttpStatusCode.InternalServerError, "internal_error")
            http.revoke(phoneDevice, json(revocation())).assertError(HttpStatusCode.InternalServerError, "internal_error")
        }
    }

    private fun ByteArray.toHex(): String = joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }
}
