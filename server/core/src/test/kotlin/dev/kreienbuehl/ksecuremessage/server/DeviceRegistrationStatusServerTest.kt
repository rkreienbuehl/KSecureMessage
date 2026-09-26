package dev.kreienbuehl.ksecuremessage.server

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceAuthenticationRegistrationStatus
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.DeviceRegistration
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationRotation
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecovery
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.ServerApiPaths
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequest
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequestAuthentication
import dev.kreienbuehl.ksecuremessage.storage.server.inmemory.InMemoryServerStorage
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/**
 * The key installation time (docs/device-authentication-rotation.md) through
 * [SecureMessageServer]: always the server clock's time of the transition
 * that installed the key, never a client-supplied timestamp, and never
 * refreshed by a retry. Exposed only through [SecureMessageServer.registrationStatus].
 */
class DeviceRegistrationStatusServerTest {
    private class ManualClock(var now: Instant) : Clock {
        override fun now(): Instant = now
    }

    private val phone = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val laptop = DeviceAddress(UserId("alice"), DeviceId("laptop"))
    private val t1 = Instant.fromEpochMilliseconds(1_767_225_600_123)
    private val clock = ManualClock(t1)
    private val server = SecureMessageServer(InMemoryServerStorage(), clock)

    private fun newKey(): DeviceAuthenticationKeyPair = runBlocking { KodiumProtocolEngine().createDeviceAuthenticationKey() }

    private suspend fun register(address: DeviceAddress, key: DeviceAuthenticationKeyPair): Boolean {
        val body = key.publicKey
        val request = ServerRequest(address, "PUT", ServerApiPaths.device(address, ServerApiPaths.REGISTRATION), body)
        return server.registerDevice(DeviceRegistration(address, key.publicKey), body, ServerRequestAuthentication.sign(key, request, clock.now()))
    }

    private suspend fun status(address: DeviceAddress, key: DeviceAuthenticationKeyPair): DeviceAuthenticationRegistrationStatus {
        val request = ServerRequest(address, "GET", ServerApiPaths.device(address, ServerApiPaths.REGISTRATION), ByteArray(0))
        val device = server.authenticate(
            address, ProtectedEndpoint.READ_REGISTRATION, ByteArray(0), ServerRequestAuthentication.sign(key, request, clock.now()),
        )
        return server.registrationStatus(device)
    }

    @Test
    fun installationTimeFollowsRegistrationRecoveryAndRotationButNoRetry() = runTest {
        val k1 = newKey()
        val laptopKey = newKey()
        register(phone, k1)
        register(laptop, laptopKey)
        assertEquals(DeviceAuthenticationRegistrationStatus(1, t1), status(phone, k1))

        // Registration retry (a lost response, or the recovery/rotation probe) later: unchanged.
        clock.now = t1 + 20.days
        assertFalse(register(phone, k1))
        assertEquals(DeviceAuthenticationRegistrationStatus(1, t1), status(phone, k1))

        // Recovery at t3: the recovered key's age starts at the server's time, not the request's.
        val t3 = t1 + 100.days
        clock.now = t3
        val k2 = newKey()
        val recovery = DeviceRecovery.authorize(laptopKey, DeviceRecovery.prepare(k2, phone, laptop, t3 - 4.minutes))
        assertEquals(DeviceRecoveryOutcome.REPLACED, server.recoverDevice(recovery))
        assertEquals(DeviceAuthenticationRegistrationStatus(2, t3), status(phone, k2))
        clock.now = t3 + 1.minutes
        assertEquals(DeviceRecoveryOutcome.ALREADY_APPLIED, server.recoverDevice(recovery))
        assertEquals(DeviceAuthenticationRegistrationStatus(2, t3), status(phone, k2), "recovery retry")

        // Rotation at t4, with a statement stamped earlier by the client: the server's time counts.
        val t4 = t3 + 30.days
        clock.now = t4
        val k3 = newKey()
        val rotation = DeviceAuthenticationRotation.create(k2, k3, phone, 2, t4 - 4.minutes)
        assertEquals(DeviceAuthenticationRotationOutcome.ROTATED, server.rotateDeviceAuthenticationKey(phone, rotation))
        assertEquals(DeviceAuthenticationRegistrationStatus(3, t4), status(phone, k3))

        // Exact retry at t5 and the rotation probe: unchanged.
        clock.now = t4 + 1.minutes
        assertEquals(DeviceAuthenticationRotationOutcome.ALREADY_APPLIED, server.rotateDeviceAuthenticationKey(phone, rotation))
        assertFalse(register(phone, k3))
        assertEquals(DeviceAuthenticationRegistrationStatus(3, t4), status(phone, k3))
        assertEquals(DeviceAuthenticationRegistrationStatus(1, t1), status(laptop, laptopKey), "the authorizer keeps its own")
    }

    @Test
    fun installationTimeHasMillisecondPrecision() = runTest {
        clock.now = Instant.fromEpochSeconds(1_767_225_600, 123_456_789)
        val key = newKey()
        register(phone, key)
        assertEquals(Instant.fromEpochMilliseconds(1_767_225_600_123), status(phone, key).authKeyInstalledAt)
    }

    @Test
    fun statusNeedsTheRegistrationEndpoint() = runTest {
        val key = newKey()
        register(phone, key)
        val request = ServerRequest(phone, "GET", ServerApiPaths.device(phone, ServerApiPaths.MESSAGES), ByteArray(0))
        val drain = server.authenticate(phone, ProtectedEndpoint.DRAIN_MAILBOX, ByteArray(0), ServerRequestAuthentication.sign(key, request, clock.now()))
        assertFailsWith<IllegalArgumentException> { server.registrationStatus(drain) }
    }
}
