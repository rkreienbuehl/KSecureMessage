package dev.kreienbuehl.ksecuremessage.server

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.DeviceRegistration
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.MessageId
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication
import dev.kreienbuehl.ksecuremessage.model.PublicOneTimePreKey
import dev.kreienbuehl.ksecuremessage.model.PublicSignedPreKey
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.PreKeyFormat
import dev.kreienbuehl.ksecuremessage.protocol.RequestAuthentication
import dev.kreienbuehl.ksecuremessage.protocol.RequestNonce
import dev.kreienbuehl.ksecuremessage.protocol.ServerApiPaths
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequest
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequestAuthentication
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationException
import dev.kreienbuehl.ksecuremessage.storage.PreKeyPublicationException
import dev.kreienbuehl.ksecuremessage.storage.inmemory.InMemoryServerStorage
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.nanoseconds
import kotlin.time.Instant

/**
 * Device registration, request authentication, replay protection and the
 * protected operations of [SecureMessageServer] (docs/server-authentication.md).
 */
class DeviceAuthenticationServerTest {
    private class ManualClock(var now: Instant) : Clock {
        override fun now(): Instant = now
    }

    private val alice = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val aliceLaptop = DeviceAddress(UserId("alice"), DeviceId("laptop"))
    private val bob = DeviceAddress(UserId("bob"), DeviceId("phone"))
    private val clock = ManualClock(Instant.fromEpochMilliseconds(1_767_225_600_000))
    private val storage = InMemoryServerStorage()
    private val server = SecureMessageServer(storage, clock)
    private val aliceKey = newKey()
    private val otherKey = newKey()

    private fun newKey(): DeviceAuthenticationKeyPair = runBlocking { KodiumProtocolEngine().createDeviceAuthenticationKey() }

    private fun key(seed: Int, size: Int = PreKeyFormat.PUBLIC_KEY_SIZE) = ByteArray(size) { (seed + it).toByte() }

    private fun publication(address: DeviceAddress = alice, oneTimePreKeys: IntRange = 0..2, identitySeed: Int = 1) = PreKeyPublication(
        address = address,
        identityKey = key(identitySeed),
        signedPreKey = PublicSignedPreKey(SignedPreKeyId(0), key(2), key(3, PreKeyFormat.SIGNATURE_SIZE)),
        oneTimePreKeys = oneTimePreKeys.map { PublicOneTimePreKey(OneTimePreKeyId(it), key(100 + it)) },
    )

    private val body = "exact request body".encodeToByteArray()

    private fun sign(
        keyPair: DeviceAuthenticationKeyPair,
        address: DeviceAddress,
        method: String,
        endpoint: String,
        body: ByteArray,
        offset: Duration = Duration.ZERO,
        nonce: RequestNonce = RequestNonce.random(),
    ): RequestAuthentication =
        ServerRequestAuthentication.sign(keyPair, ServerRequest(address, method, ServerApiPaths.device(address, endpoint), body), clock.now + offset, nonce)

    private fun registration(address: DeviceAddress, keyPair: DeviceAuthenticationKeyPair) = DeviceRegistration(address, keyPair.publicKey)

    private fun registrationBody(keyPair: DeviceAuthenticationKeyPair) = "register".encodeToByteArray() + keyPair.publicKey

    private suspend fun register(address: DeviceAddress, keyPair: DeviceAuthenticationKeyPair, nonce: RequestNonce = RequestNonce.random()): Boolean {
        val body = registrationBody(keyPair)
        return server.registerDevice(registration(address, keyPair), body, sign(keyPair, address, "PUT", ServerApiPaths.REGISTRATION, body, nonce = nonce))
    }

    private fun drainAuthentication(keyPair: DeviceAuthenticationKeyPair = aliceKey, address: DeviceAddress = alice, offset: Duration = Duration.ZERO) =
        sign(keyPair, address, "GET", ServerApiPaths.MESSAGES, ByteArray(0), offset)

    private fun publishAuthentication(keyPair: DeviceAuthenticationKeyPair = aliceKey, address: DeviceAddress = alice, body: ByteArray = this.body) =
        sign(keyPair, address, "PUT", ServerApiPaths.PRE_KEYS, body)

    private suspend fun drain(authentication: RequestAuthentication?, address: DeviceAddress = alice) =
        server.receive(server.authenticate(address, ProtectedEndpoint.DRAIN_MAILBOX, ByteArray(0), authentication))

    private suspend fun publish(authentication: RequestAuthentication?, publication: PreKeyPublication = publication(), body: ByteArray = this.body) =
        server.publishPreKeys(server.authenticate(publication.address, ProtectedEndpoint.PUBLISH_PRE_KEYS, body, authentication), publication)

    private fun envelope(sequence: Int, recipient: DeviceAddress = alice) =
        EncryptedEnvelope(MessageId("m$sequence"), bob, recipient, payload = byteArrayOf(sequence.toByte()))

    // Registration

    @Test
    fun firstRegistrationRetryAndConflict() = runTest {
        assertTrue(register(alice, aliceKey))
        assertContentEquals(aliceKey.publicKey, storage.devices.registration(alice)?.publicKey)
        assertFalse(register(alice, aliceKey), "identical retry")
        assertFailsWith<DeviceRegistrationException.Conflict> { register(alice, otherKey) }
        assertContentEquals(aliceKey.publicKey, storage.devices.registration(alice)?.publicKey, "never replaced")
        assertTrue(register(aliceLaptop, otherKey), "each device registers on its own")
    }

    @Test
    fun malformedKeysAreRejected() = runTest {
        for (size in listOf(0, 31, 33, 64)) {
            val keyPair = DeviceAuthenticationKeyPair(ByteArray(size) { 7 }, aliceKey.privateKey)
            assertFailsWith<DeviceRegistrationException.InvalidRegistration> {
                server.registerDevice(registration(alice, keyPair), body, sign(aliceKey, alice, "PUT", ServerApiPaths.REGISTRATION, body))
            }
        }
        // 32 bytes that are not a usable Ed25519 key never verify.
        val bogus = DeviceAuthenticationKeyPair(ByteArray(32) { 0xFF.toByte() }, aliceKey.privateKey)
        assertFailsWith<DeviceAuthenticationException.InvalidAuthentication> {
            server.registerDevice(registration(alice, bogus), body, sign(aliceKey, alice, "PUT", ServerApiPaths.REGISTRATION, body))
        }
        assertNull(storage.devices.registration(alice))
    }

    @Test
    fun registrationNeedsProofOfPossession() = runTest {
        val body = registrationBody(aliceKey)
        suspend fun attempt(authentication: RequestAuthentication?) = server.registerDevice(registration(alice, aliceKey), body, authentication)

        assertFailsWith<DeviceAuthenticationException.MissingAuthentication> { attempt(null) }
        // Signed by someone else than the holder of the key being registered.
        assertFailsWith<DeviceAuthenticationException.InvalidAuthentication> { attempt(sign(otherKey, alice, "PUT", ServerApiPaths.REGISTRATION, body)) }
        // Signed by the right key, for another request.
        assertFailsWith<DeviceAuthenticationException.InvalidAuthentication> { attempt(sign(aliceKey, alice, "PUT", ServerApiPaths.PRE_KEYS, body)) }
        assertFailsWith<DeviceAuthenticationException.InvalidAuthentication> { attempt(sign(aliceKey, aliceLaptop, "PUT", ServerApiPaths.REGISTRATION, body)) }
        assertFailsWith<DeviceAuthenticationException.InvalidAuthentication> { attempt(sign(aliceKey, alice, "PUT", ServerApiPaths.REGISTRATION, body + 0)) }
        assertFailsWith<DeviceAuthenticationException.ExpiredAuthentication> {
            attempt(sign(aliceKey, alice, "PUT", ServerApiPaths.REGISTRATION, body, offset = -(5.minutes + 1.milliseconds)))
        }
        assertNull(storage.devices.registration(alice))

        val nonce = RequestNonce.random()
        assertTrue(register(alice, aliceKey, nonce))
        assertFailsWith<DeviceAuthenticationException.AuthenticationReplay> { register(alice, aliceKey, nonce) }
    }

    @Test
    fun concurrentIdenticalRegistrationsConverge() = runTest {
        val results = withContext(Dispatchers.Default) { List(32) { async { register(alice, aliceKey) } }.awaitAll() }
        assertEquals(1, results.count { it })
        assertContentEquals(aliceKey.publicKey, storage.devices.registration(alice)?.publicKey)
    }

    @Test
    fun concurrentConflictingRegistrationsHaveOneWinner() = runTest {
        val keys = List(16) { newKey() }
        val outcomes = withContext(Dispatchers.Default) {
            keys.map { keyPair ->
                async {
                    try {
                        register(alice, keyPair)
                        keyPair
                    } catch (e: DeviceRegistrationException.Conflict) {
                        null
                    }
                }
            }.awaitAll()
        }
        val winner = outcomes.filterNotNull().single()
        assertContentEquals(winner.publicKey, storage.devices.registration(alice)?.publicKey)
        for (keyPair in keys - winner) assertFailsWith<DeviceRegistrationException.Conflict> { register(alice, keyPair) }
        assertContentEquals(winner.publicKey, storage.devices.registration(alice)?.publicKey)
    }

    // Time window and replay

    @Test
    fun timestampWindowIsInclusiveToTheMillisecond() = runTest {
        register(alice, aliceKey)
        drain(drainAuthentication(offset = -5.minutes))
        drain(drainAuthentication(offset = 5.minutes))
        assertFailsWith<DeviceAuthenticationException.ExpiredAuthentication> { drain(drainAuthentication(offset = -(5.minutes + 1.milliseconds))) }
        assertFailsWith<DeviceAuthenticationException.ExpiredAuthentication> { drain(drainAuthentication(offset = 5.minutes + 1.milliseconds)) }
        // The server clock is truncated to milliseconds like the timestamps.
        clock.now += 999_999.nanoseconds
        drain(drainAuthentication(offset = -5.minutes))
    }

    @Test
    fun replayIsRejectedPerDevice() = runTest {
        register(alice, aliceKey)
        register(bob, otherKey)
        val nonce = RequestNonce.random()
        val first = sign(aliceKey, alice, "GET", ServerApiPaths.MESSAGES, ByteArray(0), nonce = nonce)
        drain(first)
        assertFailsWith<DeviceAuthenticationException.AuthenticationReplay> { drain(first) }
        assertFailsWith<DeviceAuthenticationException.AuthenticationReplay> {
            drain(sign(aliceKey, alice, "GET", ServerApiPaths.MESSAGES, ByteArray(0), offset = 1.milliseconds, nonce = nonce))
        }
        // The same nonce is independent for another device.
        drain(sign(otherKey, bob, "GET", ServerApiPaths.MESSAGES, ByteArray(0), nonce = nonce), address = bob)
        // A replay far in the future is refused by the window before it reaches the nonce store.
        clock.now += 10.minutes
        assertFailsWith<DeviceAuthenticationException.ExpiredAuthentication> { drain(first) }
    }

    @Test
    fun failedAuthenticationDoesNotConsumeTheNonce() = runTest {
        register(alice, aliceKey)
        val nonce = RequestNonce.random()
        val forged = sign(otherKey, alice, "GET", ServerApiPaths.MESSAGES, ByteArray(0), nonce = nonce)
        assertFailsWith<DeviceAuthenticationException.InvalidAuthentication> { drain(forged) }
        drain(sign(aliceKey, alice, "GET", ServerApiPaths.MESSAGES, ByteArray(0), nonce = nonce))
    }

    @Test
    fun concurrentIdenticalDrainsExecuteOnce() = runTest {
        register(alice, aliceKey)
        repeat(20) { round ->
            repeat(10) { server.relay(envelope(round * 10 + it)) }
            val authentication = drainAuthentication()
            val results = withContext(Dispatchers.Default) {
                List(16) {
                    async {
                        try {
                            drain(authentication)
                        } catch (e: DeviceAuthenticationException.AuthenticationReplay) {
                            null
                        }
                    }
                }.awaitAll()
            }
            val succeeded = results.filterNotNull()
            assertEquals(1, succeeded.size, "one authenticated execution")
            assertEquals((0 until 10).map { "m${round * 10 + it}" }, succeeded.single().map { it.id.value })
        }
    }

    @Test
    fun concurrentIdenticalPublicationsExecuteOnce() = runTest {
        register(alice, aliceKey)
        val authentication = publishAuthentication()
        val results = withContext(Dispatchers.Default) {
            List(16) {
                async {
                    try {
                        publish(authentication)
                        true
                    } catch (e: DeviceAuthenticationException.AuthenticationReplay) {
                        false
                    }
                }
            }.awaitAll()
        }
        assertEquals(1, results.count { it })
        assertEquals(3, storage.preKeys.oneTimePreKeyCount(alice))
    }

    // Protected operations

    @Test
    fun authenticatedPublicationSucceeds() = runTest {
        register(alice, aliceKey)
        publish(publishAuthentication())
        assertEquals(3, storage.preKeys.oneTimePreKeyCount(alice))
        // The existing publication semantics apply after authentication.
        assertFailsWith<PreKeyPublicationException.IdentityKeyConflict> { publish(publishAuthentication(), publication(identitySeed = 9)) }
        publish(publishAuthentication(), publication(oneTimePreKeys = 0..4))
        assertEquals(5, storage.preKeys.oneTimePreKeyCount(alice))
        // The bundle stays public and consumes one one-time prekey.
        assertEquals(OneTimePreKeyId(0), server.fetchPreKeyBundle(alice)?.oneTimePreKey?.id)
        assertEquals(4, storage.preKeys.oneTimePreKeyCount(alice))
    }

    @Test
    fun unauthenticatedPublicationChangesNothing() = runTest {
        register(alice, aliceKey)
        register(aliceLaptop, otherKey)
        val replayed = publishAuthentication()
        publish(replayed, publication(oneTimePreKeys = 0..0))
        val attempts: List<Pair<String, suspend () -> Unit>> = listOf(
            "missing" to { publish(null) },
            "wrong key" to { publish(publishAuthentication(keyPair = otherKey)) },
            "other device's signature" to { publish(publishAuthentication(keyPair = otherKey, address = aliceLaptop)) },
            "other body" to { publish(publishAuthentication(), body = body + 1) },
            "drain signature" to { publish(drainAuthentication()) },
            "expired" to { publish(sign(aliceKey, alice, "PUT", ServerApiPaths.PRE_KEYS, body, offset = -(6.minutes))) },
            "replayed" to { publish(replayed) },
            "unregistered" to { publish(sign(aliceKey, bob, "PUT", ServerApiPaths.PRE_KEYS, body), publication(address = bob)) },
        )
        for ((name, attempt) in attempts) {
            assertFailsWith<DeviceAuthenticationException>(name) { attempt() }
            assertEquals(1, storage.preKeys.oneTimePreKeyCount(alice), name)
            assertEquals(0, storage.preKeys.oneTimePreKeyCount(bob), name)
        }
        assertFailsWith<DeviceAuthenticationException.DeviceNotRegistered> {
            publish(sign(aliceKey, bob, "PUT", ServerApiPaths.PRE_KEYS, body), publication(address = bob))
        }
    }

    @Test
    fun authenticatedDeviceIsBoundToItsEndpointAndAddress() = runTest {
        register(alice, aliceKey)
        val forDrain = server.authenticate(alice, ProtectedEndpoint.DRAIN_MAILBOX, ByteArray(0), drainAuthentication())
        assertFailsWith<IllegalArgumentException> { server.publishPreKeys(forDrain, publication()) }
        val forPublish = server.authenticate(alice, ProtectedEndpoint.PUBLISH_PRE_KEYS, body, publishAuthentication())
        assertFailsWith<IllegalArgumentException> { server.receive(forPublish) }
        assertFailsWith<IllegalArgumentException> { server.publishPreKeys(forPublish, publication(address = bob)) }
        assertEquals(0, storage.preKeys.oneTimePreKeyCount(bob))
        assertEquals(0, storage.preKeys.oneTimePreKeyCount(alice))
    }

    @Test
    fun unauthenticatedDrainLeavesTheMailboxUntouched() = runTest {
        register(alice, aliceKey)
        register(aliceLaptop, otherKey)
        repeat(3) { server.relay(envelope(it)) }
        val attempts: List<Pair<String, suspend () -> Unit>> = listOf(
            "missing" to { drain(null) },
            "wrong key" to { drain(drainAuthentication(keyPair = otherKey)) },
            "user substituted" to { drain(sign(aliceKey, bob, "GET", ServerApiPaths.MESSAGES, ByteArray(0))) },
            "device substituted" to { drain(sign(otherKey, aliceLaptop, "GET", ServerApiPaths.MESSAGES, ByteArray(0))) },
            "PUT as GET" to { drain(sign(aliceKey, alice, "PUT", ServerApiPaths.MESSAGES, ByteArray(0))) },
            "with a body" to { drain(sign(aliceKey, alice, "GET", ServerApiPaths.MESSAGES, body)) },
            "expired" to { drain(drainAuthentication(offset = -(5.minutes + 1.milliseconds))) },
            "future" to { drain(drainAuthentication(offset = 5.minutes + 1.milliseconds)) },
        )
        for ((name, attempt) in attempts) {
            assertFailsWith<DeviceAuthenticationException>(name) { attempt() }
        }
        assertEquals(listOf("m0", "m1", "m2"), drain(drainAuthentication()).map { it.id.value })
        val replayed = drainAuthentication()
        server.relay(envelope(3))
        drain(replayed)
        server.relay(envelope(4))
        assertFailsWith<DeviceAuthenticationException.AuthenticationReplay> { drain(replayed) }
        assertEquals(listOf("m4"), drain(drainAuthentication()).map { it.id.value })
    }

    @Test
    fun relayAndBundleFetchStayPublic() = runTest {
        register(alice, aliceKey)
        publish(publishAuthentication())
        server.relay(envelope(1)) // no authentication of the sender
        assertEquals(OneTimePreKeyId(0), server.fetchPreKeyBundle(alice)?.oneTimePreKey?.id)
        assertNull(server.fetchPreKeyBundle(bob))
        assertEquals(listOf("m1"), drain(drainAuthentication()).map { it.id.value })
    }
}
