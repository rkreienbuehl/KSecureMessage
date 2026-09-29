package dev.kreienbuehl.ksecuremessage.server.ktor

import dev.kreienbuehl.ksecuremessage.client.PreKeyConfiguration
import dev.kreienbuehl.ksecuremessage.client.SecureMessageClient
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException.LastDeviceRecoveryFailure
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException.RecoveryKeyFailure
import dev.kreienbuehl.ksecuremessage.client.ktor.KtorSecureMessageTransport
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecovery
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryKey
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryKeyRegistration
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
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlin.io.encoding.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes

/**
 * Last-device recovery over HTTP API v1 (docs/last-device-recovery.md):
 * `PUT …/last-device-recovery/key` (ServerAuth-signed),
 * `POST …/last-device-recovery/challenge` and `PUT …/last-device-recovery`
 * (both public), their status and error mapping, the client adapter and
 * client against the real routes, and recovery on persistent storage across
 * restarts.
 */
class LastDeviceRecoveryRoutesTest {
    private val clock = ManualClock()
    private val phone = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val bob = DeviceAddress(UserId("bob"), DeviceId("phone"))
    private val engine = KodiumProtocolEngine()

    private fun newKey(): DeviceAuthenticationKeyPair = runBlocking { engine.createDeviceAuthenticationKey() }
    private val recoveryKey: LastDeviceRecoveryKey = runBlocking { engine.createLastDeviceRecoveryKey() }

    private fun b64(bytes: ByteArray) = Base64.encode(bytes)

    private fun keyJson(registration: LastDeviceRecoveryKeyRegistration) =
        """{"publicKey":"${b64(registration.publicKey)}","proofOfPossession":"${b64(registration.proofOfPossession)}"}"""

    private fun json(authorization: LastDeviceRecoveryAuthorization): String {
        val statement = authorization.statement
        val challenge = statement.challenge
        return """{"recoveryPublicKey":"${b64(statement.recoveryPublicKey)}","challengeId":"${b64(challenge.id.bytes)}",""" +
            """"challengeNonce":"${b64(challenge.nonce)}","authEpoch":${challenge.authEpoch},"expiresAt":${challenge.expiresAt.toEpochMilliseconds()},""" +
            """"replacementPublicKey":"${b64(statement.replacementPublicKey)}","recoverySignature":"${b64(authorization.recoverySignature)}",""" +
            """"proofOfPossession":"${b64(authorization.proofOfPossession)}"}"""
    }

    private suspend fun HttpClient.registerKey(body: String, key: DeviceAuthenticationKeyPair?, address: DeviceAddress = phone): HttpResponse {
        val bytes = body.encodeToByteArray()
        val request = ServerRequest(address, "PUT", ServerApiPaths.device(address, ServerApiPaths.LAST_DEVICE_RECOVERY_KEY), bytes)
        return raw(HttpMethod.Put, request.path, bytes, key?.let { ServerRequestAuthentication.sign(it, request, clock.now()) })
    }

    private suspend fun HttpClient.challenge(address: DeviceAddress = phone): HttpResponse =
        raw(HttpMethod.Post, ServerApiPaths.device(address, ServerApiPaths.LAST_DEVICE_RECOVERY_CHALLENGE), null, null)

    private suspend fun HttpClient.recover(body: String, address: DeviceAddress = phone): HttpResponse =
        raw(HttpMethod.Put, ServerApiPaths.device(address, ServerApiPaths.LAST_DEVICE_RECOVERY), body.encodeToByteArray(), null)

    private suspend fun HttpClient.recover(authorization: LastDeviceRecoveryAuthorization): HttpResponse =
        recover(json(authorization), authorization.statement.target)

    private suspend fun HttpClient.drain(key: DeviceAuthenticationKeyPair, address: DeviceAddress = phone): HttpResponse {
        val request = ServerRequest(address, "GET", ServerApiPaths.device(address, ServerApiPaths.MESSAGES), ByteArray(0))
        return raw(HttpMethod.Get, request.path, null, ServerRequestAuthentication.sign(key, request, clock.now()))
    }

    private suspend fun HttpResponse.assertError(status: HttpStatusCode, error: String) {
        assertEquals(status, this.status)
        assertEquals("""{"error":"$error"}""", bodyAsText())
    }

    /** Phone and Bob registered; the phone registered alice's recovery key. */
    private suspend fun registered(http: HttpClient, withRecoveryKey: Boolean = true): TestDevice {
        val transport = KtorSecureMessageTransport("", http)
        val phoneDevice = TestDevice(phone, clock).also { it.register(transport) }
        TestDevice(bob, clock).register(transport)
        if (withRecoveryKey) {
            assertEquals(HttpStatusCode.Created, http.registerKey(keyJson(LastDeviceRecovery.registerKey(recoveryKey, phone.userId)), phoneDevice.keyPair).status)
        }
        return phoneDevice
    }

    private suspend fun authorization(http: HttpClient, replacement: DeviceAuthenticationKeyPair = newKey(), key: LastDeviceRecoveryKey = recoveryKey) =
        LastDeviceRecovery.authorize(key, replacement, KtorSecureMessageTransport("", http).lastDeviceRecoveryChallenge(phone))

    private suspend fun ServerStorage.assertUnchanged(device: TestDevice) {
        assertContentEquals(device.keyPair.publicKey, devices.registration(device.address)?.publicKey)
        assertEquals(1, devices.registrationState(device.address)?.authEpoch)
    }

    @Test
    fun recoveryKeyRegistrationIsSignedAndNeverReplaced() = testServer(TestDeviceRegistrationAuthorizer.allowAll(), clock) { storage, http ->
        val phoneDevice = registered(http, withRecoveryKey = false)
        val registration = keyJson(LastDeviceRecovery.registerKey(recoveryKey, phone.userId))
        http.registerKey(registration, null).assertError(HttpStatusCode.Unauthorized, "missing_authentication")
        http.registerKey(registration, newKey()).assertError(HttpStatusCode.Unauthorized, "invalid_authentication")
        http.registerKey("{", phoneDevice.keyPair).assertError(HttpStatusCode.BadRequest, "invalid_last_device_recovery_key")
        val other = runBlocking { engine.createLastDeviceRecoveryKey() }
        // A proof of possession for another user or key is refused.
        http.registerKey(keyJson(LastDeviceRecovery.registerKey(recoveryKey, bob.userId)), phoneDevice.keyPair)
            .assertError(HttpStatusCode.BadRequest, "invalid_last_device_recovery_key")
        val forged = LastDeviceRecoveryKeyRegistration(phone.userId, other.publicKey, LastDeviceRecovery.registerKey(recoveryKey, phone.userId).proofOfPossession)
        http.registerKey(keyJson(forged), phoneDevice.keyPair).assertError(HttpStatusCode.BadRequest, "invalid_last_device_recovery_key")
        assertNull(storage.lastDeviceRecovery.recoveryKey(phone.userId))

        assertEquals(HttpStatusCode.Created, http.registerKey(registration, phoneDevice.keyPair).status)
        assertEquals(HttpStatusCode.NoContent, http.registerKey(registration, phoneDevice.keyPair).status)
        http.registerKey(keyJson(LastDeviceRecovery.registerKey(other, phone.userId)), phoneDevice.keyPair)
            .assertError(HttpStatusCode.Conflict, "last_device_recovery_key_conflict")
        assertContentEquals(recoveryKey.publicKey, storage.lastDeviceRecovery.recoveryKey(phone.userId))

        // Through the adapter.
        val transport = KtorSecureMessageTransport("", http)
        transport.registerLastDeviceRecoveryKey(phone, LastDeviceRecovery.registerKey(recoveryKey, phone.userId), phoneDevice.signer)
        val conflict = assertFailsWith<SecureMessageTransportException.LastDeviceRecoveryKeyRejected> {
            transport.registerLastDeviceRecoveryKey(phone, LastDeviceRecovery.registerKey(other, phone.userId), phoneDevice.signer)
        }
        assertEquals(RecoveryKeyFailure.CONFLICT, conflict.reason)
    }

    @Test
    fun challengeIsPublicAndStableWhileValid() = testServer(TestDeviceRegistrationAuthorizer.allowAll(), clock) { _, http ->
        http.challenge().assertError(HttpStatusCode.NotFound, "last_device_recovery_target_not_registered")
        registered(http, withRecoveryKey = false)
        http.challenge().assertError(HttpStatusCode.NotFound, "last_device_recovery_not_configured")
        // An unsigned key registration is refused, so there is still no challenge.
        http.registerKey(keyJson(LastDeviceRecovery.registerKey(recoveryKey, phone.userId)), null)
            .assertError(HttpStatusCode.Unauthorized, "missing_authentication")
        http.challenge().assertError(HttpStatusCode.NotFound, "last_device_recovery_not_configured")
    }

    @Test
    fun challengeResponseCarriesOnlyPublicFields() = testServer(TestDeviceRegistrationAuthorizer.allowAll(), clock) { _, http ->
        registered(http)
        val response = http.challenge()
        assertEquals(HttpStatusCode.OK, response.status)
        val body = Json.parseToJsonElement(response.bodyAsText()).jsonObject
        assertEquals(setOf("challengeId", "challengeNonce", "authEpoch", "expiresAt"), body.keys)
        assertEquals(1, body.getValue("authEpoch").jsonPrimitive.long)
        assertEquals((clock.now + LastDeviceRecovery.CHALLENGE_LIFETIME).toEpochMilliseconds(), body.getValue("expiresAt").jsonPrimitive.long)
        assertEquals(16, Base64.decode(body.getValue("challengeId").jsonPrimitive.content).size)
        assertEquals(32, Base64.decode(body.getValue("challengeNonce").jsonPrimitive.content).size)
        assertEquals(response.bodyAsText().length, http.challenge().bodyAsText().length)
        val again = Json.parseToJsonElement(http.challenge().bodyAsText()).jsonObject
        assertEquals(body, again, "the same challenge while it is valid")
        http.challenge(bob).assertError(HttpStatusCode.NotFound, "last_device_recovery_not_configured")
    }

    @Test
    fun successIsNoContentAndSwitchesTheKeyAtOnce() = testServer(TestDeviceRegistrationAuthorizer.allowAll(), clock) { storage, http ->
        val phoneDevice = registered(http)
        val k2 = newKey()
        val authorization = authorization(http, k2)
        assertEquals(HttpStatusCode.NoContent, http.recover(authorization).status)
        assertContentEquals(k2.publicKey, storage.devices.registration(phone)?.publicKey)
        assertEquals(2, storage.devices.registrationState(phone)?.authEpoch)
        http.drain(phoneDevice.keyPair).assertError(HttpStatusCode.Unauthorized, "invalid_authentication")
        assertEquals(HttpStatusCode.OK, http.drain(k2).status)
        assertEquals(HttpStatusCode.NoContent, http.recover(authorization).status, "an exact retry is idempotent")
        assertEquals(2, storage.devices.registrationState(phone)?.authEpoch)
        // The consumed challenge never works for another key.
        val reuse = LastDeviceRecovery.authorize(recoveryKey, newKey(), authorization.statement.challenge)
        http.recover(reuse).assertError(HttpStatusCode.Unauthorized, "last_device_recovery_challenge_invalid")
    }

    @Test
    fun rejectionsAreMappedAndChangeNothing() = testServer(TestDeviceRegistrationAuthorizer.allowAll(), clock) { storage, http ->
        val phoneDevice = registered(http)
        val valid = authorization(http)
        val otherKey = runBlocking { engine.createLastDeviceRecoveryKey() }
        http.recover(LastDeviceRecovery.authorize(otherKey, newKey(), valid.statement.challenge))
            .assertError(HttpStatusCode.Unauthorized, "last_device_recovery_proof_invalid")
        http.recover(LastDeviceRecoveryAuthorization(valid.statement, valid.recoverySignature, valid.recoverySignature))
            .assertError(HttpStatusCode.Unauthorized, "last_device_recovery_proof_invalid")
        // The target is the route's device: a body sent to another device's route is a statement for that device.
        http.recover(json(valid), bob).assertError(HttpStatusCode.NotFound, "last_device_recovery_not_configured")
        val watch = DeviceAddress(UserId("alice"), DeviceId("watch"))
        http.challenge(watch).assertError(HttpStatusCode.NotFound, "last_device_recovery_target_not_registered")
        clock.now += LastDeviceRecovery.CHALLENGE_LIFETIME + 1.milliseconds
        http.recover(valid).assertError(HttpStatusCode.Unauthorized, "last_device_recovery_expired")
        http.recover(valid).assertError(HttpStatusCode.Unauthorized, "last_device_recovery_expired")
        storage.assertUnchanged(phoneDevice)

        val transport = KtorSecureMessageTransport("", http)
        val expired = assertFailsWith<SecureMessageTransportException.LastDeviceRecoveryRejected> { transport.recoverLastDevice(valid) }
        assertEquals(LastDeviceRecoveryFailure.EXPIRED, expired.reason)
        val notConfigured = assertFailsWith<SecureMessageTransportException.LastDeviceRecoveryRejected> { transport.lastDeviceRecoveryChallenge(bob) }
        assertEquals(LastDeviceRecoveryFailure.NOT_CONFIGURED, notConfigured.reason)
        val notRegistered = assertFailsWith<SecureMessageTransportException.LastDeviceRecoveryRejected> { transport.lastDeviceRecoveryChallenge(watch) }
        assertEquals(LastDeviceRecoveryFailure.TARGET_NOT_REGISTERED, notRegistered.reason)
        // A conflicting state: the challenge was issued, then the key changed by another recovery.
        val first = authorization(http)
        val second = LastDeviceRecovery.authorize(recoveryKey, newKey(), first.statement.challenge)
        assertEquals(HttpStatusCode.NoContent, http.recover(first).status)
        http.recover(second).assertError(HttpStatusCode.Unauthorized, "last_device_recovery_challenge_invalid")
        // A challenge issued for epoch 2, then the registration changes (a routine rotation elsewhere would do the same).
        val beforeChange = authorization(http)
        assertEquals(HttpStatusCode.NoContent, http.recover(LastDeviceRecovery.authorize(recoveryKey, newKey(), beforeChange.statement.challenge)).status)
        http.recover(beforeChange).assertError(HttpStatusCode.Unauthorized, "last_device_recovery_challenge_invalid")
        // The registered key as replacement conflicts.
        val k = newKey()
        assertEquals(HttpStatusCode.NoContent, http.recover(authorization(http, k)).status)
        http.recover(authorization(http, k)).assertError(HttpStatusCode.Conflict, "last_device_recovery_conflict")
    }

    @Test
    fun malformedBodiesAreBadRequests() = testServer(TestDeviceRegistrationAuthorizer.allowAll(), clock) { storage, http ->
        val phoneDevice = registered(http)
        val valid = json(authorization(http))
        val bodies = listOf(
            "",
            "{",
            "{}",
            valid.replace(""""authEpoch":1""", """"authEpoch":0"""),
            valid.replace(""""expiresAt":""", """"expiresAt":-"""),
            valid.replaceFirst("=\"", "\""), // non-canonical Base64 somewhere
            valid.replace(""""challengeNonce":"""", """"challengeNonce":"AAAA"""),
        )
        for (body in bodies) {
            http.recover(body).assertError(HttpStatusCode.BadRequest, "invalid_last_device_recovery")
        }
        val recoveryAsReplacement = valid.replace(
            Regex(""""replacementPublicKey":"[^"]+""""),
            """"replacementPublicKey":"${b64(recoveryKey.publicKey)}"""",
        )
        http.recover(recoveryAsReplacement).assertError(HttpStatusCode.BadRequest, "invalid_last_device_recovery")
        storage.assertUnchanged(phoneDevice)
    }

    @Test
    fun clientRecoversThroughTheKtorAdapterAndMessagingIsUnaffected() = testServer(TestDeviceRegistrationAuthorizer.allowAll(), clock) { storage, http ->
        val transport = KtorSecureMessageTransport("", http)
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
        val offline = phoneClient.createLastDeviceRecoveryKey()
        phoneClient.registerLastDeviceRecoveryKey(offline)
        bobClient.send(phone, "before".encodeToByteArray())
        phoneClient.accept(phoneClient.receive().single())
        bobClient.receive().forEach { bobClient.decrypt(it) } // the ACK
        phoneClient.markRemoteIdentityVerified(phoneClient.safetyNumber(bob))
        val safetyNumber = phoneClient.safetyNumber(bob)
        val k1 = assertNotNull(phoneStorage.deviceAuthentication.keyPair())
        bobClient.send(phone, "queued".encodeToByteArray())

        // The offline key goes through its text form, as after a paper backup.
        phoneClient.recoverLastDevice(LastDeviceRecoveryKey.decode(offline.encode()))

        val k2 = assertNotNull(phoneStorage.deviceAuthentication.keyPair())
        assertFalse(k1.publicKey.contentEquals(k2.publicKey))
        assertNull(phoneStorage.deviceAuthentication.pendingLastDeviceRecoveryKeyPair())
        assertContentEquals(k2.publicKey, storage.devices.registration(phone)?.publicKey)
        assertEquals(2, storage.devices.registrationState(phone)?.authEpoch)
        http.drain(k1).assertError(HttpStatusCode.Unauthorized, "invalid_authentication")
        assertEquals(VerificationState.VERIFIED, phoneClient.remoteIdentityTrust(bob)?.verification)
        assertEquals(safetyNumber.displayString, phoneClient.safetyNumber(bob).displayString)
        val message = phoneClient.accept(phoneClient.receive().single())
        assertEquals("queued", message.plaintext.decodeToString(), "the mailbox was kept")
        phoneClient.publishPreKeys()
        phoneClient.rotateDeviceAuthenticationKey()
        assertEquals(3, storage.devices.registrationState(phone)?.authEpoch)
    }

    @Test
    fun lostResponseIsResolvedByTheClient() = testServer(TestDeviceRegistrationAuthorizer.allowAll(), clock) { storage, http ->
        val transport = KtorSecureMessageTransport("", http)
        val phoneStorage = InMemoryClientStorage()
        val phoneClient = SecureMessageClient(phone, phoneStorage, engine, transport, PreKeyConfiguration(oneTimePreKeyTarget = 1), clock)
        phoneClient.initialize()
        phoneClient.registerDevice()
        phoneClient.registerLastDeviceRecoveryKey(recoveryKey)
        phoneClient.prepareLastDeviceRecovery()
        val k2 = assertNotNull(phoneStorage.deviceAuthentication.pendingLastDeviceRecoveryKeyPair())
        // The request reached the server and was applied; the client never saw the response.
        assertEquals(HttpStatusCode.NoContent, http.recover(authorization(http, k2)).status)

        phoneClient.completeLastDeviceRecovery(recoveryKey)

        assertContentEquals(k2.publicKey, phoneStorage.deviceAuthentication.keyPair()?.publicKey)
        assertNull(phoneStorage.deviceAuthentication.pendingLastDeviceRecoveryKeyPair())
        assertEquals(2, storage.devices.registrationState(phone)?.authEpoch, "resolved without a second transition")
        assertTrue(phoneClient.receive().isEmpty())
    }

    @Test
    fun recoveryPersistsAcrossServerRestarts() = ReopenableServerStorage().use { persistent ->
        testServer(TestDeviceRegistrationAuthorizer.allowAll(), persistent, clock) { server, http ->
            val phoneDevice = registered(http)
            val challenge = Json.parseToJsonElement(http.challenge().bodyAsText())
            server.restart()
            assertEquals(challenge, Json.parseToJsonElement(http.challenge().bodyAsText()), "the challenge survived the restart")
            assertContentEquals(recoveryKey.publicKey, server.lastDeviceRecovery.recoveryKey(phone.userId))

            clock.now += 2.minutes
            val k2 = newKey()
            val first = authorization(http, k2)
            assertEquals(HttpStatusCode.NoContent, http.recover(first).status)
            val recoveredAt = clock.now
            server.restart()
            http.drain(phoneDevice.keyPair).assertError(HttpStatusCode.Unauthorized, "invalid_authentication")
            assertEquals(HttpStatusCode.OK, http.drain(k2).status)
            assertEquals(recoveredAt, server.devices.registrationState(phone)?.authKeyInstalledAt)
            assertEquals(HttpStatusCode.NoContent, http.recover(first).status, "lost-response retry after a restart")
            server.restart()
            assertEquals(2, server.devices.registrationState(phone)?.authEpoch)

            // A later recovery, then the old one again: stale.
            val k3 = newKey()
            assertEquals(HttpStatusCode.NoContent, http.recover(authorization(http, k3)).status)
            server.restart()
            http.recover(first).assertError(HttpStatusCode.Unauthorized, "last_device_recovery_challenge_invalid")
            assertContentEquals(k3.publicKey, server.devices.registration(phone)?.publicKey)
            assertEquals(3, server.devices.registrationState(phone)?.authEpoch)
        }
    }

    @Test
    fun storageFailureIsAGenericServerError() = ReopenableServerStorage().use { persistent ->
        testServer(TestDeviceRegistrationAuthorizer.allowAll(), persistent, clock) { server, http ->
            val phoneDevice = registered(http)
            val authorization = authorization(http)
            server.driver.execute(null, "DROP TABLE last_device_recovery_challenge", 0)
            http.recover(authorization).assertError(HttpStatusCode.InternalServerError, "internal_error")
            http.challenge().assertError(HttpStatusCode.InternalServerError, "internal_error")
            assertContentEquals(phoneDevice.keyPair.publicKey, server.devices.registration(phone)?.publicKey)
            assertEquals(1, server.devices.registrationState(phone)?.authEpoch)
        }
    }
}
