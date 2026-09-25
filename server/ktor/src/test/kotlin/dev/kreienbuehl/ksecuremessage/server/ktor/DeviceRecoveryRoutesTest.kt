package dev.kreienbuehl.ksecuremessage.server.ktor

import dev.kreienbuehl.ksecuremessage.client.PreKeyConfiguration
import dev.kreienbuehl.ksecuremessage.client.ReceiveResult
import dev.kreienbuehl.ksecuremessage.client.SecureMessageClient
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException.RecoveryFailure
import dev.kreienbuehl.ksecuremessage.client.ktor.KtorSecureMessageTransport
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecovery
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecoveryAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.ServerApiPaths
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequest
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequestAuthentication
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
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes

/**
 * Device recovery over HTTP API v1 (docs/device-recovery.md):
 * `PUT /v1/devices/{user}/{device}/registration/recovery`, its status and
 * error mapping, the client adapter against the real routes, and recovery on
 * persistent storage across restarts.
 */
class DeviceRecoveryRoutesTest {
    private val clock = ManualClock()
    private val laptop = DeviceAddress(UserId("alice"), DeviceId("laptop"))
    private val phone = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val bob = DeviceAddress(UserId("bob"), DeviceId("phone"))

    private fun newKey(): DeviceAuthenticationKeyPair = runBlocking { KodiumProtocolEngine().createDeviceAuthenticationKey() }

    private fun b64(bytes: ByteArray) = Base64.encode(bytes)

    private fun path(target: DeviceAddress = laptop) = ServerApiPaths.device(target, ServerApiPaths.REGISTRATION_RECOVERY)

    private fun json(authorization: DeviceRecoveryAuthorization): String {
        val request = authorization.request
        return """{"authorizer":{"userId":"${request.authorizer.userId.value}","deviceId":"${request.authorizer.deviceId.value}"},""" +
            """"replacementPublicKey":"${b64(request.replacementPublicKey)}","timestamp":${request.timestamp.toEpochMilliseconds()},""" +
            """"nonce":"${b64(request.nonce.bytes)}","proofOfPossession":"${b64(request.proofOfPossession)}",""" +
            """"authorizerSignature":"${b64(authorization.authorizerSignature)}"}"""
    }

    private suspend fun HttpClient.recover(body: String, target: DeviceAddress = laptop): HttpResponse =
        raw(HttpMethod.Put, path(target), body.encodeToByteArray(), null)

    private suspend fun HttpClient.recover(authorization: DeviceRecoveryAuthorization): HttpResponse =
        recover(json(authorization), authorization.request.target)

    private fun authorize(
        authorizer: TestDevice,
        replacement: DeviceAuthenticationKeyPair = newKey(),
        target: DeviceAddress = laptop,
        offset: Duration = Duration.ZERO,
    ) = DeviceRecovery.authorize(authorizer.keyPair, DeviceRecovery.prepare(replacement, target, authorizer.address, clock.now() + offset))

    /** Registers laptop, phone and Bob; returns them. */
    private suspend fun registered(http: HttpClient): Triple<TestDevice, TestDevice, TestDevice> {
        val transport = KtorSecureMessageTransport("", http)
        return Triple(TestDevice(laptop, clock), TestDevice(phone, clock), TestDevice(bob, clock)).also { (a, b, c) ->
            a.register(transport)
            b.register(transport)
            c.register(transport)
        }
    }

    /** A mailbox drain of [device]'s address signed with [key]. */
    private suspend fun HttpClient.drain(device: TestDevice, key: DeviceAuthenticationKeyPair = device.keyPair): HttpResponse {
        val address = device.address
        val request = ServerRequest(address, "GET", ServerApiPaths.device(address, ServerApiPaths.MESSAGES), ByteArray(0))
        return raw(HttpMethod.Get, request.path, null, ServerRequestAuthentication.sign(key, request, clock.now()))
    }

    private suspend fun HttpResponse.assertError(status: HttpStatusCode, error: String) {
        assertEquals(status, this.status)
        assertEquals("""{"error":"$error"}""", bodyAsText())
    }

    private suspend fun ServerStorage.assertUnchanged(device: TestDevice) {
        assertContentEquals(device.keyPair.publicKey, devices.registration(device.address)?.publicKey)
        assertEquals(1, devices.registrationState(device.address)?.authEpoch)
    }

    @Test
    fun successIsNoContentAndSwitchesTheKeyAtOnce() = testServer(clock) { storage, http ->
        val (laptopDevice, phoneDevice) = registered(http)
        val replacement = newKey()
        val authorization = authorize(phoneDevice, replacement)
        assertEquals(HttpStatusCode.NoContent, http.recover(authorization).status)
        assertEquals(HttpStatusCode.NoContent, http.recover(authorization).status, "a retry is idempotent")
        assertEquals(2, storage.devices.registrationState(laptop)?.authEpoch)

        http.drain(laptopDevice).assertError(HttpStatusCode.Unauthorized, "invalid_authentication")
        assertEquals(HttpStatusCode.OK, http.drain(laptopDevice, replacement).status)
    }

    @Test
    fun rejectionsAreMappedAndChangeNothing() = testServer(clock) { storage, http ->
        val (laptopDevice, phoneDevice, bobDevice) = registered(http)
        http.recover(authorize(bobDevice)).assertError(HttpStatusCode.Forbidden, "recovery_cross_user")
        http.recover(authorize(laptopDevice)).assertError(HttpStatusCode.Forbidden, "recovery_self_authorization")
        http.recover(authorize(TestDevice(DeviceAddress(UserId("alice"), DeviceId("tablet")), clock)))
            .assertError(HttpStatusCode.Unauthorized, "recovery_authorizer_not_registered")
        http.recover(authorize(phoneDevice, target = DeviceAddress(UserId("alice"), DeviceId("desktop"))))
            .assertError(HttpStatusCode.NotFound, "recovery_target_not_registered")
        http.recover(authorize(phoneDevice, offset = 5.minutes + 1.minutes)).assertError(HttpStatusCode.Unauthorized, "expired_authentication")
        val forged = DeviceRecoveryAuthorization(authorize(phoneDevice).request, authorize(TestDevice(phone, clock)).authorizerSignature)
        http.recover(forged).assertError(HttpStatusCode.Unauthorized, "invalid_recovery_proof")
        // The target in the path is part of what was signed.
        http.recover(json(authorize(phoneDevice, target = laptop)), target = DeviceAddress(UserId("alice"), DeviceId("phone2")))
            .assertError(HttpStatusCode.NotFound, "recovery_target_not_registered")
        storage.assertUnchanged(laptopDevice)

        val first = authorize(phoneDevice)
        assertEquals(HttpStatusCode.NoContent, http.recover(first).status)
        val k3 = newKey()
        assertEquals(HttpStatusCode.NoContent, http.recover(authorize(phoneDevice, k3)).status)
        http.recover(first).assertError(HttpStatusCode.Unauthorized, "authentication_replay")
        // A new recovery for the key that is already registered.
        http.recover(authorize(phoneDevice, k3)).assertError(HttpStatusCode.Conflict, "recovery_conflict")
        assertContentEquals(k3.publicKey, storage.devices.registration(laptop)?.publicKey)
        assertEquals(3, storage.devices.registrationState(laptop)?.authEpoch)
    }

    @Test
    fun malformedBodiesAreBadRequests() = testServer(clock) { storage, http ->
        val (laptopDevice, phoneDevice) = registered(http)
        val authorization = authorize(phoneDevice)
        val valid = json(authorization)
        val signature = b64(authorization.authorizerSignature)
        val cases = listOf(
            "",
            "{}",
            "not json",
            valid.replace(signature, signature.dropLast(4)),
            valid.replace("\"nonce\":\"", "\"nonce\":\"AAAA"),
            valid.replace(Regex("\"timestamp\":\\d+"), "\"timestamp\":-1"),
            valid.replace("\"replacementPublicKey\":\"", "\"replacementPublicKey\":\" "),
        )
        for (body in cases) {
            assertFalse(body == valid)
            http.recover(body).assertError(HttpStatusCode.BadRequest, "invalid_recovery")
        }
        storage.assertUnchanged(laptopDevice)
        assertEquals(HttpStatusCode.NoContent, http.recover(valid).status)
    }

    @Test
    fun clientsRecoverThroughTheKtorAdapter() = testServer(clock) { storage, http ->
        val transport = KtorSecureMessageTransport("", http)
        val engine = KodiumProtocolEngine()
        val laptopStorage = InMemoryClientStorage()
        fun client(address: DeviceAddress, clientStorage: InMemoryClientStorage) =
            SecureMessageClient(address, clientStorage, engine, transport, PreKeyConfiguration(oneTimePreKeyTarget = 3), clock)
        val laptopClient = client(laptop, laptopStorage)
        val phoneClient = client(phone, InMemoryClientStorage())
        val bobClient = client(bob, InMemoryClientStorage())
        for (device in listOf(laptopClient, phoneClient, bobClient)) {
            device.initialize()
            device.registerDevice()
        }
        laptopClient.publishPreKeys()
        bobClient.send(laptop, "queued".encodeToByteArray())
        val old = assertNotNull(laptopStorage.deviceAuthentication.keyPair())

        val request = laptopClient.prepareDeviceAuthenticationRecovery(phone)
        laptopClient.completeDeviceAuthenticationRecovery(phoneClient.authorizeDeviceRecovery(request))
        assertContentEquals(request.replacementPublicKey, storage.devices.registration(laptop)?.publicKey)
        assertContentEquals(request.replacementPublicKey, laptopStorage.deviceAuthentication.keyPair()?.publicKey)
        http.drain(TestDevice(laptop, clock), old).assertError(HttpStatusCode.Unauthorized, "invalid_authentication")

        val message = assertIs<ReceiveResult.Message>(laptopClient.decrypt(laptopClient.receive().single()))
        assertEquals("queued", message.plaintext.decodeToString())
        laptopClient.publishPreKeys()

        // Error mapping of the adapter.
        val cross = assertFailsWith<SecureMessageTransportException.DeviceRecoveryRejected> {
            transport.recoverDevice(authorize(TestDevice(bob, clock)))
        }
        assertEquals(RecoveryFailure.CROSS_USER, cross.reason)
        val replay = assertFailsWith<SecureMessageTransportException.DeviceRecoveryRejected> {
            transport.recoverDevice(DeviceRecoveryAuthorization(request, ByteArray(64)))
        }
        assertEquals(RecoveryFailure.INVALID_PROOF, replay.reason)
    }

    @Test
    fun recoveryPersistsAcrossServerRestarts() = ReopenableServerStorage().use { persistent ->
        testServer(persistent, clock) { server, http ->
            val (laptopDevice, phoneDevice) = registered(http)
            val k2 = newKey()
            val first = authorize(phoneDevice, k2)
            assertEquals(HttpStatusCode.NoContent, http.recover(first).status)

            server.restart()
            http.drain(laptopDevice).assertError(HttpStatusCode.Unauthorized, "invalid_authentication")
            assertEquals(HttpStatusCode.OK, http.drain(laptopDevice, k2).status)
            assertEquals(HttpStatusCode.NoContent, http.recover(first).status, "lost-response retry after a restart")

            val k3 = newKey()
            assertEquals(HttpStatusCode.NoContent, http.recover(authorize(phoneDevice, k3)).status)
            server.restart()
            http.recover(first).assertError(HttpStatusCode.Unauthorized, "authentication_replay")
            assertContentEquals(k3.publicKey, server.devices.registration(laptop)?.publicKey)
            assertEquals(3, server.devices.registrationState(laptop)?.authEpoch)
        }
    }

    @Test
    fun storageFailureIsAGenericServerError() = ReopenableServerStorage().use { persistent ->
        testServer(persistent, clock) { server, http ->
            val (laptopDevice, phoneDevice) = registered(http)
            server.driver.execute(null, "DROP TABLE authentication_nonce", 0)
            http.recover(authorize(phoneDevice)).assertError(HttpStatusCode.InternalServerError, "internal_error")
            assertContentEquals(laptopDevice.keyPair.publicKey, server.devices.registration(laptop)?.publicKey)
        }
    }
}
