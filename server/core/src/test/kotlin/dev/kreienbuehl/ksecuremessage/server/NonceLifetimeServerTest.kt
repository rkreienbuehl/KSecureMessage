package dev.kreienbuehl.ksecuremessage.server

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.DeviceRegistration
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.RequestAuthentication
import dev.kreienbuehl.ksecuremessage.protocol.RequestNonce
import dev.kreienbuehl.ksecuremessage.protocol.ServerApiPaths
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequest
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequestAuthentication
import dev.kreienbuehl.ksecuremessage.storage.server.inmemory.InMemoryServerStorage
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Instant

/**
 * Nonce lifetime at the request-authentication window edge (S1, finding F8;
 * docs/server-authentication.md, "Nonce lifetime"). The server accepts
 * `now - W <= ts <= now + W`, so a request with timestamp `ts` can be replayed
 * at any server time up to `ts + W`; its nonce must be refused for that whole
 * time, whatever other requests prune in between.
 */
class NonceLifetimeServerTest {
    private class ManualClock(var now: Instant) : Clock {
        override fun now(): Instant = now
    }

    private val window = DeviceAuthenticator.WINDOW
    private val t0 = Instant.fromEpochMilliseconds(1_767_225_600_000)
    private val clock = ManualClock(t0)
    private val alice = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val bob = DeviceAddress(UserId("bob"), DeviceId("phone"))

    private fun newKey(): DeviceAuthenticationKeyPair = runBlocking { KodiumProtocolEngine().createDeviceAuthenticationKey() }

    private val aliceKey = newKey()
    private val bobKey = newKey()

    private suspend fun server(): SecureMessageServer {
        val server = SecureMessageServer(InMemoryServerStorage(), clock, TestDeviceRegistrationAuthorizer.allowAll())
        for ((address, key) in listOf(alice to aliceKey, bob to bobKey)) {
            val body = key.publicKey
            val request = ServerRequest(address, "PUT", ServerApiPaths.device(address, ServerApiPaths.REGISTRATION), body)
            server.registerDevice(DeviceRegistration(address, key.publicKey), body, ServerRequestAuthentication.sign(key, request, clock.now))
        }
        return server
    }

    private fun drainRequest(address: DeviceAddress, key: DeviceAuthenticationKeyPair, timestamp: Instant): RequestAuthentication =
        ServerRequestAuthentication.sign(
            key,
            ServerRequest(address, "GET", ServerApiPaths.device(address, ServerApiPaths.MESSAGES), ByteArray(0)),
            timestamp,
            RequestNonce.random(),
        )

    private suspend fun SecureMessageServer.drain(address: DeviceAddress, authentication: RequestAuthentication) =
        receive(authenticate(address, ProtectedEndpoint.DRAIN_MAILBOX, ByteArray(0), authentication))

    @Test
    fun f8ReplayAfterAConcurrentPruneAtTheWindowEdgeIsRejected() = runTest {
        val server = server()
        val ts = t0
        val copied = drainRequest(alice, aliceKey, ts)
        server.drain(alice, copied)

        // Another request is checked 1 ms after the copied one's window ended and prunes.
        clock.now = ts + window + 1.milliseconds
        server.drain(bob, drainRequest(bob, bobKey, clock.now))
        // The replay read the clock just before, at ts + W, where it is still fresh.
        clock.now = ts + window
        assertFailsWith<DeviceAuthenticationException.AuthenticationReplay> { server.drain(alice, copied) }
    }

    @Test
    fun f8NonceIsRefusedAtEveryServerTimeItsRequestIsFresh() = runTest {
        // Earliest valid (ts = now - W), current and latest valid (future-dated, ts = now + W) timestamps.
        for (offset in listOf(-window, Duration.ZERO, window)) {
            clock.now = t0
            val server = server()
            val copied = drainRequest(alice, aliceKey, t0 + offset)
            server.drain(alice, copied)
            val lastFresh = t0 + offset + window
            for (serverTime in listOf(t0, lastFresh - 1.milliseconds, lastFresh)) {
                if (serverTime < t0) continue
                clock.now = serverTime
                assertFailsWith<DeviceAuthenticationException.AuthenticationReplay>("offset $offset at ${serverTime - t0}") {
                    server.drain(alice, copied)
                }
            }
            // One millisecond later the request is stale anyway.
            clock.now = lastFresh + 1.milliseconds
            assertFailsWith<DeviceAuthenticationException.ExpiredAuthentication> { server.drain(alice, copied) }
        }
    }

    @Test
    fun f8FreshRequestsAtTheBoundaryAreStillAccepted() = runTest {
        val server = server()
        clock.now = t0 + 10.milliseconds
        // Exactly W old, and exactly W in the future: both accepted once.
        server.drain(alice, drainRequest(alice, aliceKey, clock.now - window))
        server.drain(bob, drainRequest(bob, bobKey, clock.now + window))
    }
}
