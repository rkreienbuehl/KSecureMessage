package dev.kreienbuehl.ksecuremessage.server.ktor

import dev.kreienbuehl.ksecuremessage.client.LastDeviceRecoveryKeyResetCancellationResult
import dev.kreienbuehl.ksecuremessage.client.LastDeviceRecoveryKeyResetResult
import dev.kreienbuehl.ksecuremessage.client.PreKeyConfiguration
import dev.kreienbuehl.ksecuremessage.client.SecureMessageClient
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransport
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransportException.RecoveryKeyResetFailure
import dev.kreienbuehl.ksecuremessage.client.ServerRequestSigner
import dev.kreienbuehl.ksecuremessage.client.ktor.KtorSecureMessageTransport
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.LastDeviceRecoveryKeyStatus
import dev.kreienbuehl.ksecuremessage.model.RecoveryKeyResetStatus
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecovery
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryKey
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyReset
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyResetCancellationAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyResetCompletionAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyResetStatusQuery
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRotation
import dev.kreienbuehl.ksecuremessage.protocol.ServerApiPaths
import dev.kreienbuehl.ksecuremessage.server.RecoveryKeyResetPolicy
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
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes

/**
 * Delayed recovery key reset over HTTP API v1 (docs/recovery-key-reset.md):
 * the signed device routes (request, status, completion, cancellation), the
 * two user-scoped routes authorized by the current recovery key (status
 * query, cancellation), status JSON, error mapping, malformed bodies, the
 * client adapter and client against the real routes, lost responses,
 * persistence of the pending reset and its timing across restarts, and
 * `internal_error`.
 */
class RecoveryKeyResetRoutesTest {
    private val clock = ManualClock()
    private val phone = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val laptop = DeviceAddress(UserId("alice"), DeviceId("laptop"))
    private val bob = DeviceAddress(UserId("bob"), DeviceId("phone"))
    private val engine = KodiumProtocolEngine()
    private val delay = 3.days
    private val policy = RecoveryKeyResetPolicy(delay)

    private fun newRecoveryKey(): LastDeviceRecoveryKey = runBlocking { engine.createLastDeviceRecoveryKey() }
    private val r1 = newRecoveryKey()
    private val r2 = newRecoveryKey()
    private val r3 = newRecoveryKey()

    private fun b64(bytes: ByteArray) = Base64.encode(bytes)

    private fun json(authorization: RecoveryKeyResetCompletionAuthorization): String {
        val s = authorization.statement
        return """{"resetId":"${b64(s.resetId.bytes)}","currentPublicKey":"${b64(s.currentPublicKey)}","newPublicKey":"${b64(s.newPublicKey)}",""" +
            """"recoveryKeyEpoch":${s.expectedEpoch},"requestedAt":${s.requestedAt.toEpochMilliseconds()},"eligibleAt":${s.eligibleAt.toEpochMilliseconds()},""" +
            """"newKeyProofOfPossession":"${b64(authorization.newKeyProofOfPossession)}"}"""
    }

    private fun json(authorization: RecoveryKeyResetCancellationAuthorization): String {
        val s = authorization.statement
        return """{"resetId":"${b64(s.resetId.bytes)}","publicKey":"${b64(s.currentPublicKey)}","recoveryKeyEpoch":${s.expectedEpoch},""" +
            """"requestedAt":${s.requestedAt.toEpochMilliseconds()},"eligibleAt":${s.eligibleAt.toEpochMilliseconds()},"signature":"${b64(authorization.signature)}"}"""
    }

    private fun json(query: RecoveryKeyResetStatusQuery) =
        """{"publicKey":"${b64(query.statement.currentPublicKey)}","timestamp":${query.statement.timestamp.toEpochMilliseconds()},"signature":"${b64(query.signature)}"}"""

    private suspend fun HttpClient.signed(device: TestDevice?, method: HttpMethod, endpoint: String, body: String?, address: DeviceAddress = device!!.address): HttpResponse {
        val bytes = body?.encodeToByteArray()
        return raw(method, ServerApiPaths.device(address, endpoint), bytes, device?.sign(method.value, endpoint, bytes ?: ByteArray(0), address))
    }

    private suspend fun HttpClient.request(device: TestDevice?, address: DeviceAddress = device!!.address) =
        signed(device, HttpMethod.Put, ServerApiPaths.LAST_DEVICE_RECOVERY_KEY_RESET, null, address)

    private suspend fun HttpClient.resetStatus(device: TestDevice?, address: DeviceAddress = device!!.address) =
        signed(device, HttpMethod.Get, ServerApiPaths.LAST_DEVICE_RECOVERY_KEY_RESET, null, address)

    private suspend fun HttpClient.complete(device: TestDevice?, body: String, address: DeviceAddress = device!!.address) =
        signed(device, HttpMethod.Put, ServerApiPaths.LAST_DEVICE_RECOVERY_KEY_RESET_COMPLETION, body, address)

    private suspend fun HttpClient.cancel(device: TestDevice?, body: String, address: DeviceAddress = device!!.address) =
        signed(device, HttpMethod.Put, ServerApiPaths.LAST_DEVICE_RECOVERY_KEY_RESET_CANCELLATION, body, address)

    private suspend fun HttpClient.query(body: String, user: UserId = phone.userId) =
        raw(HttpMethod.Post, ServerApiPaths.user(user, ServerApiPaths.LAST_DEVICE_RECOVERY_KEY_RESET_STATUS), body.encodeToByteArray(), null)

    private suspend fun HttpClient.cancelByKey(body: String, user: UserId = phone.userId) =
        raw(HttpMethod.Put, ServerApiPaths.user(user, ServerApiPaths.LAST_DEVICE_RECOVERY_KEY_RESET_CANCELLATION), body.encodeToByteArray(), null)

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

    /** Phone, laptop and Bob registered; the phone registered R1. */
    private suspend fun registered(http: HttpClient): Triple<TestDevice, TestDevice, TestDevice> {
        val transport = KtorSecureMessageTransport("", http)
        val devices = Triple(TestDevice(phone, clock), TestDevice(laptop, clock), TestDevice(bob, clock))
        devices.toList().forEach { it.register(transport) }
        assertEquals(HttpStatusCode.Created, http.registerKey(devices.first, r1).status)
        return devices
    }

    private fun pendingJson(reset: RecoveryKeyResetStatus.Pending) =
        """{"state":"pending","resetId":"${b64(reset.resetId.bytes)}","requestedByDevice":"${reset.requestedBy.deviceId.value}",""" +
            """"requestedAt":${reset.requestedAt.toEpochMilliseconds()},"eligibleAt":${reset.eligibleAt.toEpochMilliseconds()},""" +
            """"recoveryKeyEpoch":${reset.recoveryKeyEpoch},"recoveryPublicKey":"${b64(reset.recoveryPublicKey)}"}"""

    private val none = """{"state":"none","resetId":null,"requestedByDevice":null,"requestedAt":null,"eligibleAt":null,"recoveryKeyEpoch":null,"recoveryPublicKey":null}"""

    @Test
    fun requestAndStatusAreSignedAndVisibleToTheUsersDevicesOnly() = testServer(TestDeviceRegistrationAuthorizer.allowAll(), clock, policy) { storage, http ->
        val (phoneDevice, laptopDevice, bobDevice) = registered(http)
        http.request(null, phone).assertError(HttpStatusCode.Unauthorized, "missing_authentication")
        http.resetStatus(null, phone).assertError(HttpStatusCode.Unauthorized, "missing_authentication")
        assertEquals(none, http.resetStatus(laptopDevice).bodyAsText())

        val created = http.request(phoneDevice)
        assertEquals(HttpStatusCode.Created, created.status)
        val reset = assertIs<RecoveryKeyResetStatus.Pending>(storage.lastDeviceRecovery.pendingRecoveryKeyReset(phone.userId))
        assertEquals(clock.now, reset.requestedAt)
        assertEquals(clock.now + delay, reset.eligibleAt)
        assertEquals(pendingJson(reset), created.bodyAsText())
        assertEquals(pendingJson(reset), http.resetStatus(laptopDevice).bodyAsText(), "every device of the user")
        assertEquals(none, http.resetStatus(bobDevice).bodyAsText(), "per user")
        // Bob's key cannot read alice's route.
        http.resetStatus(bobDevice, phone).assertError(HttpStatusCode.Unauthorized, "invalid_authentication")

        // A repeated request, later and from another device: 200 with the same reset, timing unchanged.
        clock.now += 1.days
        val again = http.request(laptopDevice)
        assertEquals(HttpStatusCode.OK, again.status)
        assertEquals(pendingJson(reset), again.bodyAsText())
        // A body cannot choose any timing: the route takes none (and a signed body is ignored).
        clock.now += 5.days
        assertEquals(pendingJson(reset), http.request(phoneDevice).bodyAsText())
    }

    @Test
    fun withoutAPolicyRequestsAreNotAvailable() = testServer(TestDeviceRegistrationAuthorizer.allowAll(), clock) { _, http ->
        val (phoneDevice, _, _) = registered(http)
        http.request(phoneDevice).assertError(HttpStatusCode.NotFound, "recovery_key_reset_not_available")
        assertEquals(none, http.resetStatus(phoneDevice).bodyAsText())
    }

    @Test
    fun completionErrorsAndSuccess() = testServer(TestDeviceRegistrationAuthorizer.allowAll(), clock, policy) { storage, http ->
        val (phoneDevice, laptopDevice, bobDevice) = registered(http)
        http.request(bobDevice).let { assertEquals(HttpStatusCode.NotFound, it.status) } // bob has no recovery key
        http.request(phoneDevice)
        val reset = assertIs<RecoveryKeyResetStatus.Pending>(storage.lastDeviceRecovery.pendingRecoveryKeyReset(phone.userId))
        val completion = RecoveryKeyReset.complete(r2, reset, laptop)

        http.complete(null, json(completion), laptop).assertError(HttpStatusCode.Unauthorized, "missing_authentication")
        http.complete(laptopDevice, json(completion)).assertError(HttpStatusCode.Conflict, "recovery_key_reset_not_yet_eligible")
        clock.now = reset.eligibleAt - 1.milliseconds
        http.complete(laptopDevice, json(completion)).assertError(HttpStatusCode.Conflict, "recovery_key_reset_not_yet_eligible")
        clock.now = reset.eligibleAt
        // The completing device is the route's: the laptop's statement sent by the phone does not verify.
        http.complete(phoneDevice, json(completion)).assertError(HttpStatusCode.Unauthorized, "recovery_key_reset_invalid_proof")
        val forged = RecoveryKeyResetCompletionAuthorization(completion.statement, RecoveryKeyReset.complete(r3, reset, laptop).newKeyProofOfPossession)
        http.complete(laptopDevice, json(forged)).assertError(HttpStatusCode.Unauthorized, "recovery_key_reset_invalid_proof")
        val otherTimes = RecoveryKeyResetStatus.Pending(reset.resetId, reset.requestedBy, reset.requestedAt, reset.eligibleAt - 1.days, 1, r1.publicKey)
        http.complete(laptopDevice, json(RecoveryKeyReset.complete(r2, otherTimes, laptop))).assertError(HttpStatusCode.Conflict, "recovery_key_reset_conflict")
        assertContentEquals(r1.publicKey, storage.lastDeviceRecovery.recoveryKey(phone.userId))

        assertEquals(HttpStatusCode.NoContent, http.complete(laptopDevice, json(completion)).status)
        assertContentEquals(r2.publicKey, storage.lastDeviceRecovery.recoveryKey(phone.userId))
        assertEquals(none, http.resetStatus(phoneDevice).bodyAsText())
        // Lost response: the identical body again (fresh ServerAuth nonce), later.
        clock.now += 1.days
        assertEquals(HttpStatusCode.NoContent, http.complete(laptopDevice, json(completion)).status)
        assertEquals(2, storage.lastDeviceRecovery.recoveryKeyState(phone.userId)?.epoch)
        http.complete(phoneDevice, json(RecoveryKeyReset.complete(r3, reset, phone))).assertError(HttpStatusCode.NotFound, "recovery_key_reset_not_pending")
    }

    @Test
    fun cancellationByADeviceAndByTheRecoveryKey() = testServer(TestDeviceRegistrationAuthorizer.allowAll(), clock, policy) { storage, http ->
        val (phoneDevice, laptopDevice, bobDevice) = registered(http)
        http.request(laptopDevice)
        val reset = assertIs<RecoveryKeyResetStatus.Pending>(storage.lastDeviceRecovery.pendingRecoveryKeyReset(phone.userId))
        val body = """{"resetId":"${b64(reset.resetId.bytes)}"}"""
        http.cancel(null, body, phone).assertError(HttpStatusCode.Unauthorized, "missing_authentication")
        http.cancel(bobDevice, body).assertError(HttpStatusCode.NotFound, "recovery_key_reset_not_pending")
        assertEquals(HttpStatusCode.NoContent, http.cancel(phoneDevice, body).status)
        assertEquals(none, http.resetStatus(phoneDevice).bodyAsText())
        http.cancel(phoneDevice, body).assertError(HttpStatusCode.NotFound, "recovery_key_reset_not_pending")
        assertContentEquals(r1.publicKey, storage.lastDeviceRecovery.recoveryKey(phone.userId))

        // A new request gets a fresh reset; R1 alone (no device, no ServerAuth) cancels it.
        clock.now += 1.days
        assertEquals(HttpStatusCode.Created, http.request(laptopDevice).status)
        val next = assertIs<RecoveryKeyResetStatus.Pending>(storage.lastDeviceRecovery.pendingRecoveryKeyReset(phone.userId))
        assertFalse(next.resetId == reset.resetId)
        assertEquals(clock.now + delay, next.eligibleAt)
        val genuine = RecoveryKeyReset.cancel(r1, next)
        http.cancelByKey(json(RecoveryKeyResetCancellationAuthorization(genuine.statement, RecoveryKeyReset.cancel(r1, reset).signature)))
            .assertError(HttpStatusCode.Unauthorized, "recovery_key_reset_invalid_proof")
        http.cancelByKey(json(genuine), user = bob.userId).assertError(HttpStatusCode.NotFound, "recovery_key_reset_not_pending")
        http.cancelByKey(json(RecoveryKeyReset.cancel(r1, reset))).assertError(HttpStatusCode.NotFound, "recovery_key_reset_not_pending")
        assertEquals(HttpStatusCode.NoContent, http.cancelByKey(json(genuine)).status)
        assertNull(storage.lastDeviceRecovery.pendingRecoveryKeyReset(phone.userId))
        http.cancelByKey(json(genuine)).assertError(HttpStatusCode.NotFound, "recovery_key_reset_not_pending")
    }

    @Test
    fun theRecoveryKeyQueriesTheStatusWithoutADevice() = testServer(TestDeviceRegistrationAuthorizer.allowAll(), clock, policy) { storage, http ->
        val (phoneDevice, _, _) = registered(http)
        assertEquals(none, http.query(json(RecoveryKeyReset.statusQuery(r1, phone.userId, clock.now))).bodyAsText())
        http.request(phoneDevice)
        val reset = assertIs<RecoveryKeyResetStatus.Pending>(storage.lastDeviceRecovery.pendingRecoveryKeyReset(phone.userId))
        assertEquals(pendingJson(reset), http.query(json(RecoveryKeyReset.statusQuery(r1, phone.userId, clock.now))).bodyAsText())
        // Nothing leaks without the registered key's valid signature.
        http.query(json(RecoveryKeyReset.statusQuery(r2, phone.userId, clock.now))).assertError(HttpStatusCode.Unauthorized, "recovery_key_reset_invalid_proof")
        val genuine = RecoveryKeyReset.statusQuery(r1, phone.userId, clock.now)
        http.query(json(RecoveryKeyResetStatusQuery(genuine.statement, ByteArray(64)))).assertError(HttpStatusCode.Unauthorized, "recovery_key_reset_invalid_proof")
        http.query(json(RecoveryKeyReset.statusQuery(r1, phone.userId, clock.now - 5.minutes - 1.milliseconds)))
            .assertError(HttpStatusCode.Unauthorized, "recovery_key_reset_expired")
        http.query(json(RecoveryKeyReset.statusQuery(r1, bob.userId, clock.now)), user = bob.userId)
            .assertError(HttpStatusCode.NotFound, "recovery_key_not_configured")
        // The public M18 challenge endpoint reveals nothing about resets.
        val challenge = http.raw(HttpMethod.Post, ServerApiPaths.device(phone, ServerApiPaths.LAST_DEVICE_RECOVERY_CHALLENGE), null, null).bodyAsText()
        assertFalse(challenge.contains("reset") || challenge.contains(b64(reset.resetId.bytes)))
    }

    @Test
    fun malformedBodiesAreBadRequests() = testServer(TestDeviceRegistrationAuthorizer.allowAll(), clock, policy) { storage, http ->
        val (phoneDevice, laptopDevice, _) = registered(http)
        http.request(phoneDevice)
        val reset = assertIs<RecoveryKeyResetStatus.Pending>(storage.lastDeviceRecovery.pendingRecoveryKeyReset(phone.userId))
        clock.now = reset.eligibleAt
        val good = json(RecoveryKeyReset.complete(r2, reset, laptop))
        for (body in listOf(
            "{",
            good.replace("\"recoveryKeyEpoch\":1", "\"recoveryKeyEpoch\":0"),
            good.replace(b64(r2.publicKey), b64(r1.publicKey)), // same key
            good.replace(b64(reset.resetId.bytes), "AAAA"),
            good.replace("\"eligibleAt\":${reset.eligibleAt.toEpochMilliseconds()}", "\"eligibleAt\":${reset.requestedAt.toEpochMilliseconds()}"),
        )) {
            http.complete(laptopDevice, body).assertError(HttpStatusCode.BadRequest, "invalid_recovery_key_reset")
        }
        http.cancel(phoneDevice, """{"resetId":"AA=="}""").assertError(HttpStatusCode.BadRequest, "invalid_recovery_key_reset")
        http.cancelByKey("[]").assertError(HttpStatusCode.BadRequest, "invalid_recovery_key_reset")
        http.query("""{"publicKey":"AA==","timestamp":1,"signature":"AA=="}""").assertError(HttpStatusCode.BadRequest, "invalid_recovery_key_reset")
        assertEquals(1, storage.lastDeviceRecovery.recoveryKeyState(phone.userId)?.epoch)
        assertEquals(reset, storage.lastDeviceRecovery.pendingRecoveryKeyReset(phone.userId))
    }

    @Test
    fun rotationRemovesAPendingReset() = testServer(TestDeviceRegistrationAuthorizer.allowAll(), clock, policy) { storage, http ->
        val (phoneDevice, _, _) = registered(http)
        http.request(phoneDevice)
        val reset = assertIs<RecoveryKeyResetStatus.Pending>(storage.lastDeviceRecovery.pendingRecoveryKeyReset(phone.userId))
        val transport = KtorSecureMessageTransport("", http)
        transport.rotateLastDeviceRecoveryKey(RecoveryKeyRotation.authorize(r1, r3, phone, 1, clock.now), phoneDevice.signer)
        assertEquals(none, http.resetStatus(phoneDevice).bodyAsText())
        clock.now = reset.eligibleAt
        http.complete(phoneDevice, json(RecoveryKeyReset.complete(r2, reset, phone))).assertError(HttpStatusCode.NotFound, "recovery_key_reset_not_pending")
        assertContentEquals(r3.publicKey, storage.lastDeviceRecovery.recoveryKey(phone.userId))
    }

    @Test
    fun clientUsesTheRoutesThroughTheKtorAdapter() = testServer(TestDeviceRegistrationAuthorizer.allowAll(), clock, policy) { storage, http ->
        val transport = KtorSecureMessageTransport("", http)
        var loseNextCompletion = false
        val losing = object : SecureMessageTransport by transport {
            override suspend fun completeLastDeviceRecoveryKeyReset(authorization: RecoveryKeyResetCompletionAuthorization, signer: ServerRequestSigner) {
                transport.completeLastDeviceRecoveryKeyReset(authorization, signer)
                if (loseNextCompletion) {
                    loseNextCompletion = false
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
        phoneClient.registerLastDeviceRecoveryKey(r1)
        bobClient.send(phone, "hi".encodeToByteArray())
        phoneClient.accept(phoneClient.receive().single())

        val reset = phoneClient.requestLastDeviceRecoveryKeyReset()
        assertEquals(reset, laptopClient.lastDeviceRecoveryKeyResetStatus())
        assertSame(RecoveryKeyResetStatus.None, bobClient.lastDeviceRecoveryKeyResetStatus())
        assertEquals(reset, laptopClient.requestLastDeviceRecoveryKeyReset())
        // The holder of R1 sees it through the user-scoped route, without a device.
        val offline = client(phone)
        assertEquals(reset, offline.lastDeviceRecoveryKeyResetStatusByRecoveryKey(r1))

        val early = assertFailsWith<SecureMessageTransportException.RecoveryKeyResetRejected> { laptopClient.completeLastDeviceRecoveryKeyReset(r2) }
        assertEquals(RecoveryKeyResetFailure.NOT_YET_ELIGIBLE, early.reason)
        assertEquals(
            LastDeviceRecoveryKeyResetCancellationResult.Cancelled,
            offline.cancelLastDeviceRecoveryKeyResetByRecoveryKey(r1, reset),
        )
        val late = assertIs<LastDeviceRecoveryKeyResetCancellationResult.NotPending>(laptopClient.cancelLastDeviceRecoveryKeyReset(reset))
        assertEquals(1, assertIs<LastDeviceRecoveryKeyStatus.Active>(late.recoveryKeyStatus).epoch)

        val second = phoneClient.requestLastDeviceRecoveryKeyReset()
        clock.now = second.eligibleAt
        loseNextCompletion = true
        assertFailsWith<SecureMessageTransportException.UnexpectedResponse> { phoneClient.completeLastDeviceRecoveryKeyReset(r2) }
        assertEquals(LastDeviceRecoveryKeyResetResult.ALREADY_ACTIVE, phoneClient.completeLastDeviceRecoveryKeyReset(r2))
        val active = assertIs<LastDeviceRecoveryKeyStatus.Active>(laptopClient.lastDeviceRecoveryKeyStatus())
        assertEquals(2, active.epoch)
        assertTrue(active.isKey(r2.publicKey))
        assertEquals(1, storage.devices.registrationState(phone)?.authEpoch, "device authentication untouched")
        bobClient.receive().forEach { bobClient.decrypt(it) }
        bobClient.send(phone, "still here".encodeToByteArray())
        phoneClient.accept(phoneClient.receive().single())
    }

    @Test
    fun aPendingResetAndItsTimingPersistAcrossServerRestarts() = ReopenableServerStorage().use { persistent ->
        testServer(TestDeviceRegistrationAuthorizer.allowAll(), persistent, clock, policy) { server, http ->
            val (phoneDevice, laptopDevice, _) = registered(http)
            val requested = http.request(phoneDevice).bodyAsText()
            val reset = assertIs<RecoveryKeyResetStatus.Pending>(server.lastDeviceRecovery.pendingRecoveryKeyReset(phone.userId))
            server.restart()
            clock.now += 1.days
            assertEquals(requested, http.resetStatus(laptopDevice).bodyAsText(), "same ID and timing after a restart")
            assertEquals(requested, http.request(laptopDevice).bodyAsText(), "the delay never restarts")
            server.restart()
            clock.now = reset.eligibleAt
            val completion = json(RecoveryKeyReset.complete(r2, reset, laptop))
            assertEquals(HttpStatusCode.NoContent, http.complete(laptopDevice, completion).status)
            server.restart()
            assertEquals(HttpStatusCode.NoContent, http.complete(laptopDevice, completion).status, "exact retry after a restart")
            val state = server.lastDeviceRecovery.recoveryKeyState(phone.userId)
            assertEquals(2, state?.epoch)
            assertEquals(reset.eligibleAt, state?.installedAt)

            // Request, restart, cancel: the key stays.
            assertEquals(HttpStatusCode.Created, http.request(phoneDevice).status)
            val next = assertIs<RecoveryKeyResetStatus.Pending>(server.lastDeviceRecovery.pendingRecoveryKeyReset(phone.userId))
            server.restart()
            assertEquals(HttpStatusCode.NoContent, http.cancelByKey(json(RecoveryKeyReset.cancel(r2, next))).status)
            assertEquals(2, server.lastDeviceRecovery.recoveryKeyState(phone.userId)?.epoch)
            assertEquals(1, server.devices.registrationState(phone)?.authEpoch)
        }
    }

    @Test
    fun storageFailureIsAGenericServerError() = ReopenableServerStorage().use { persistent ->
        testServer(TestDeviceRegistrationAuthorizer.allowAll(), persistent, clock, policy) { server, http ->
            val (phoneDevice, laptopDevice, _) = registered(http)
            http.request(phoneDevice)
            val reset = assertIs<RecoveryKeyResetStatus.Pending>(server.lastDeviceRecovery.pendingRecoveryKeyReset(phone.userId))
            server.driver.execute(null, "DROP TABLE last_device_recovery_key_reset", 0)
            http.request(phoneDevice).assertError(HttpStatusCode.InternalServerError, "internal_error")
            http.resetStatus(phoneDevice).assertError(HttpStatusCode.InternalServerError, "internal_error")
            http.complete(laptopDevice, json(RecoveryKeyReset.complete(r2, reset, laptop))).assertError(HttpStatusCode.InternalServerError, "internal_error")
            http.cancel(phoneDevice, """{"resetId":"${b64(reset.resetId.bytes)}"}""").assertError(HttpStatusCode.InternalServerError, "internal_error")
            http.query(json(RecoveryKeyReset.statusQuery(r1, phone.userId, clock.now))).assertError(HttpStatusCode.InternalServerError, "internal_error")
            http.cancelByKey(json(RecoveryKeyReset.cancel(r1, reset))).assertError(HttpStatusCode.InternalServerError, "internal_error")
        }
    }
}
