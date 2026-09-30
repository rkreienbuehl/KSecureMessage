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
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecovery
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecovery
import dev.kreienbuehl.ksecuremessage.protocol.PreKeyFormat
import dev.kreienbuehl.ksecuremessage.protocol.RequestNonce
import dev.kreienbuehl.ksecuremessage.protocol.ServerApiPaths
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequest
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequestAuthentication
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationException
import dev.kreienbuehl.ksecuremessage.storage.server.inmemory.InMemoryServerStorage
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlin.time.Instant

/**
 * Host-authorized device registration (S1, findings F1/F2; S1.1, finding
 * N1; docs/security-review-remediation.md): knowing a user ID, a device ID
 * and holding a device key is not enough to become one of the user's
 * devices, and the host decides with its own authenticated principal.
 */
class DeviceRegistrationAuthorizationTest {
    private class ManualClock(var now: Instant) : Clock {
        override fun now(): Instant = now
    }

    private val engine = KodiumProtocolEngine()
    private val clock = ManualClock(Instant.fromEpochMilliseconds(1_767_225_600_000))
    private val alicePhone = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val aliceLaptop = DeviceAddress(UserId("alice"), DeviceId("laptop"))
    private val aliceTablet = DeviceAddress(UserId("alice"), DeviceId("tablet"))
    private val mallory = DeviceAddress(UserId("alice"), DeviceId("mallory"))
    private val malloryOwn = DeviceAddress(UserId("mallory"), DeviceId("phone"))

    private val alicePrincipal = TestRegistrationPrincipal(UserId("alice"))
    private val malloryPrincipal = TestRegistrationPrincipal(UserId("mallory"))

    private fun newKey(): DeviceAuthenticationKeyPair = runBlocking { engine.createDeviceAuthenticationKey() }

    private val phoneKey = newKey()
    private val laptopKey = newKey()
    private val malloryKey = newKey()

    private suspend fun SecureMessageServer<TestRegistrationPrincipal>.register(
        address: DeviceAddress,
        key: DeviceAuthenticationKeyPair,
        principal: TestRegistrationPrincipal? = TestRegistrationPrincipal(address.userId),
    ): Boolean {
        val body = "register".encodeToByteArray() + key.publicKey
        val request = ServerRequest(address, "PUT", ServerApiPaths.device(address, ServerApiPaths.REGISTRATION), body)
        return registerDevice(principal, DeviceRegistration(address, key.publicKey), body, ServerRequestAuthentication.sign(key, request, clock.now, RequestNonce.random()))
    }

    private suspend fun SecureMessageServer<TestRegistrationPrincipal>.signed(address: DeviceAddress, key: DeviceAuthenticationKeyPair, endpoint: ProtectedEndpoint, body: ByteArray = ByteArray(0)) =
        authenticate(address, endpoint, body, ServerRequestAuthentication.sign(key, ServerRequest(address, endpoint.method, endpoint.path(address), body), clock.now))

    private fun publication(address: DeviceAddress) = PreKeyPublication(
        address,
        ByteArray(PreKeyFormat.PUBLIC_KEY_SIZE) { 1 },
        PublicSignedPreKey(SignedPreKeyId(0), ByteArray(PreKeyFormat.PUBLIC_KEY_SIZE) { 2 }, ByteArray(PreKeyFormat.SIGNATURE_SIZE) { 3 }),
        listOf(PublicOneTimePreKey(OneTimePreKeyId(0), ByteArray(PreKeyFormat.PUBLIC_KEY_SIZE) { 4 })),
    )

    /** Everything a denied registration must leave unchanged. */
    private suspend fun InMemoryServerStorage.snapshot(): List<Any?> = listOf(
        devices.registration(mallory)?.publicKey?.toList(),
        devices.registrationState(alicePhone)?.let { listOf(it.registration.publicKey.toList(), it.authEpoch, it.authKeyInstalledAt) },
        devices.registration(aliceLaptop)?.publicKey?.toList(),
        lastDeviceRecovery.recoveryKeyState(alicePhone.userId)?.let { listOf(it.epoch, it.status) },
        lastDeviceRecovery.pendingRecoveryKeyReset(alicePhone.userId)?.resetId,
        preKeys.oneTimePreKeyCount(alicePhone),
        preKeys.oneTimePreKeyCount(mallory),
    )

    @Test
    fun f1FakeDeviceCannotJoinAnExistingUser() = runTest {
        val storage = InMemoryServerStorage()
        val authorizer = TestDeviceRegistrationAuthorizer.allowOnly(alicePhone, aliceLaptop)
        val server = SecureMessageServer(storage, clock, authorizer)
        assertTrue(server.register(alicePhone, phoneKey))
        assertTrue(server.register(aliceLaptop, laptopKey))
        server.publishPreKeys(server.signed(alicePhone, phoneKey, ProtectedEndpoint.PUBLISH_PRE_KEYS), publication(alicePhone))
        storage.mailboxes.enqueue(EncryptedEnvelope(MessageId("m1"), aliceLaptop, alicePhone, payload = byteArrayOf(1)))
        val before = storage.snapshot()

        // Mallory knows the user ID, picks a device ID and proves possession of her own key.
        assertFailsWith<DeviceRegistrationException.NotAuthorized> { server.register(mallory, malloryKey, malloryPrincipal) }
        assertEquals(before, storage.snapshot(), "no partial membership")
        assertNull(storage.devices.registration(mallory))
        val asked = authorizer.requests.last()
        assertEquals(mallory, asked.address)
        assertContentEquals(malloryKey.publicKey, asked.proposedAuthenticationPublicKey)

        // So she has no device authority of the user: every signed request fails.
        for (endpoint in ProtectedEndpoint.entries) {
            assertFailsWith<DeviceAuthenticationException.DeviceNotRegistered>(endpoint.name) { server.signed(mallory, malloryKey, endpoint) }
        }
        // She cannot authorize a device recovery (M14) of Alice's phone ...
        assertFailsWith<DeviceRecoveryException.AuthorizerNotRegistered> {
            server.recoverDevice(DeviceRecovery.authorize(malloryKey, DeviceRecovery.prepare(newKey(), alicePhone, mallory, clock.now)))
        }
        // ... provision the user's offline recovery key (M18), which needs a signed device ...
        assertFailsWith<DeviceAuthenticationException.DeviceNotRegistered> {
            server.signed(mallory, malloryKey, ProtectedEndpoint.REGISTER_LAST_DEVICE_RECOVERY_KEY)
        }
        assertNull(storage.lastDeviceRecovery.recoveryKey(alicePhone.userId))
        // ... drain Alice's mailbox or publish her prekeys.
        assertFailsWith<DeviceAuthenticationException.InvalidAuthentication> { server.signed(alicePhone, malloryKey, ProtectedEndpoint.DRAIN_MAILBOX) }
        assertFailsWith<DeviceAuthenticationException.InvalidAuthentication> { server.signed(alicePhone, malloryKey, ProtectedEndpoint.PUBLISH_PRE_KEYS) }
        assertEquals(listOf("m1"), server.receive(server.signed(alicePhone, phoneKey, ProtectedEndpoint.DRAIN_MAILBOX)).map { it.id.value })
        assertEquals(before, storage.snapshot().let { it })
    }

    @Test
    fun f1FakeFirstDeviceOfAUserIsDenied() = runTest {
        val storage = InMemoryServerStorage()
        val authorizer = TestDeviceRegistrationAuthorizer.principalOwnsUser()
        val server = SecureMessageServer(storage, clock, authorizer)
        // Alice has no device yet: being first is no authority (S1.1, N2).
        assertFailsWith<DeviceRegistrationException.NotAuthorized> { server.register(mallory, malloryKey, malloryPrincipal) }
        assertNull(storage.devices.registration(mallory), "first writer does not win")
        assertEquals(listOf(malloryPrincipal), authorizer.contexts)
    }

    @Test
    fun f2AuthorizedSecondDeviceParticipatesInSameUserFlows() = runTest {
        val storage = InMemoryServerStorage()
        val server = SecureMessageServer(storage, clock, TestDeviceRegistrationAuthorizer.principalOwnsUser())
        assertTrue(server.register(alicePhone, phoneKey, alicePrincipal))
        assertTrue(server.register(aliceLaptop, laptopKey, alicePrincipal))
        // The host-authorized laptop registers the recovery key and recovers the phone.
        val recoveryKey = engine.createLastDeviceRecoveryKey()
        assertTrue(
            server.registerLastDeviceRecoveryKey(
                server.signed(aliceLaptop, laptopKey, ProtectedEndpoint.REGISTER_LAST_DEVICE_RECOVERY_KEY),
                LastDeviceRecovery.registerKey(recoveryKey, alicePhone.userId),
            ),
        )
        val replacement = newKey()
        assertEquals(
            DeviceRecoveryOutcome.REPLACED,
            server.recoverDevice(DeviceRecovery.authorize(laptopKey, DeviceRecovery.prepare(replacement, alicePhone, aliceLaptop, clock.now))),
        )
        assertContentEquals(replacement.publicKey, storage.devices.registration(alicePhone)?.publicKey)
    }

    // N1: the authorizer decides with the host's authenticated principal.

    @Test
    fun n1RegistrationAuthorizationReceivesTheAuthenticatedApplicationPrincipal() = runTest {
        val storage = InMemoryServerStorage()
        val authorizer = TestDeviceRegistrationAuthorizer.principalOwnsUser()
        val server = SecureMessageServer(storage, clock, authorizer)
        // A principal object that is not derived from the address: identity, not equality, is checked.
        val principal = TestRegistrationPrincipal(UserId("alice"))
        assertTrue(server.register(alicePhone, phoneKey, principal))
        assertTrue(server.register(aliceTablet, laptopKey, principal))
        assertEquals(2, authorizer.contexts.size)
        authorizer.contexts.forEach { assertSame(principal, it, "exactly the host's context object") }
        assertEquals(listOf(alicePhone, aliceTablet), authorizer.requests.map { it.address })
        assertContentEquals(phoneKey.publicKey, storage.devices.registration(alicePhone)?.publicKey)
        assertContentEquals(laptopKey.publicKey, storage.devices.registration(aliceTablet)?.publicKey)
    }

    @Test
    fun n1WrongPrincipalCannotRegisterAnotherUsersDevice() = runTest {
        val storage = InMemoryServerStorage()
        val authorizer = TestDeviceRegistrationAuthorizer.principalOwnsUser()
        val server = SecureMessageServer(storage, clock, authorizer)
        // Mallory authenticated as herself claims Alice's (unregistered) phone with a key she holds.
        assertFailsWith<DeviceRegistrationException.NotAuthorized> { server.register(alicePhone, malloryKey, malloryPrincipal) }
        assertNull(storage.devices.registration(alicePhone))
        assertEquals(listOf(malloryPrincipal), authorizer.contexts, "the boundary was reached with Mallory's principal")
        // Her own user is fine.
        assertTrue(server.register(malloryOwn, malloryKey, malloryPrincipal))
        // Alice's real device is still free for Alice.
        assertTrue(server.register(alicePhone, phoneKey, alicePrincipal))
    }

    @Test
    fun n1MissingContextIsDeniedAndRegistersNothing() = runTest {
        val storage = InMemoryServerStorage()
        val authorizer = TestDeviceRegistrationAuthorizer.allowAll()
        val server = SecureMessageServer(storage, clock, authorizer)
        assertFailsWith<DeviceRegistrationException.NotAuthorized> { server.register(alicePhone, phoneKey, principal = null) }
        assertNull(storage.devices.registration(alicePhone))
        assertTrue(authorizer.requests.isEmpty(), "no anonymous path reaches even an allow-all authorizer")
    }

    @Test
    fun n1MalloryCannotBecomeAlicesRecoveryAuthority() = runTest {
        val storage = InMemoryServerStorage()
        val server = SecureMessageServer(storage, clock, TestDeviceRegistrationAuthorizer.principalOwnsUser())
        assertTrue(server.register(alicePhone, phoneKey, alicePrincipal))
        assertTrue(server.register(malloryOwn, malloryKey, malloryPrincipal))
        val before = storage.snapshot()
        // Through registration: denied, so no device of Alice's user.
        val malloryKey2 = newKey()
        assertFailsWith<DeviceRegistrationException.NotAuthorized> { server.register(mallory, malloryKey2, malloryPrincipal) }
        assertFailsWith<DeviceRecoveryException.AuthorizerNotRegistered> {
            server.recoverDevice(DeviceRecovery.authorize(malloryKey2, DeviceRecovery.prepare(newKey(), alicePhone, mallory, clock.now)))
        }
        // Through her own registered device: another user.
        assertFailsWith<DeviceRecoveryException.CrossUser> {
            server.recoverDevice(DeviceRecovery.authorize(malloryKey, DeviceRecovery.prepare(newKey(), alicePhone, malloryOwn, clock.now)))
        }
        assertEquals(before, storage.snapshot())
        assertContentEquals(phoneKey.publicKey, storage.devices.registration(alicePhone)?.publicKey)
    }

    @Test
    fun sameKeyRetryIsIdempotentWithoutAskingTheHost() = runTest {
        val storage = InMemoryServerStorage()
        var allow = true
        val authorizer = TestDeviceRegistrationAuthorizer.principalOwnsUser()
        val server = SecureMessageServer(
            storage,
            clock,
            DeviceRegistrationAuthorizer<TestRegistrationPrincipal> { context, request ->
                if (allow) authorizer.authorize(context, request) else DeviceRegistrationAuthorizationResult.Denied
            },
        )
        assertTrue(server.register(alicePhone, phoneKey, alicePrincipal))
        assertEquals(1, authorizer.requests.size)
        // The host would now deny, but exactly this device and key are registered: no membership change.
        allow = false
        assertFalse(server.register(alicePhone, phoneKey, alicePrincipal))
        // Also without any context (a lost-response retry or a recovery/rotation probe).
        assertFalse(server.register(alicePhone, phoneKey, principal = null))
        assertEquals(1, authorizer.requests.size, "the authorizer is not asked for a retry")
        // A different key for the registered address is a conflict, never an authorization question.
        assertFailsWith<DeviceRegistrationException.Conflict> { server.register(alicePhone, malloryKey, alicePrincipal) }
        assertContentEquals(phoneKey.publicKey, storage.devices.registration(alicePhone)?.publicKey)
        // A new device of the same user is asked about (and here denied).
        assertFailsWith<DeviceRegistrationException.NotAuthorized> { server.register(aliceLaptop, laptopKey, alicePrincipal) }
        assertNull(storage.devices.registration(aliceLaptop))
    }

    @Test
    fun authorizerFailureRegistersNothing() = runTest {
        val storage = InMemoryServerStorage()
        val failure = IllegalStateException("host account service unavailable: secret detail")
        val server = SecureMessageServer(storage, clock, TestDeviceRegistrationAuthorizer.throwing(failure))
        val thrown = assertFailsWith<DeviceRegistrationAuthorizationFailedException> { server.register(alicePhone, phoneKey, alicePrincipal) }
        assertSame(failure, thrown.cause, "kept for the host's own diagnostics")
        assertFalse(thrown.message.orEmpty().contains("secret"), "the fixed message carries no host text")
        assertNull(storage.devices.registration(alicePhone))
    }

    // N4 (S1.2): errors thrown by host code are wrapped like exceptions; only cancellation and VM errors pass.

    @Test
    fun n4AuthorizerErrorIsWrappedWithoutMessage() = runTest {
        val failures = listOf<Throwable>(
            IllegalStateException("SECRET-A"),
            NotImplementedError("SECRET-B"),
            AssertionError("SECRET-C"),
            object : RuntimeException("SECRET-D") {},
        )
        for (failure in failures) {
            val storage = InMemoryServerStorage()
            val server = SecureMessageServer(storage, clock, TestDeviceRegistrationAuthorizer.throwing(failure))
            val thrown = assertFailsWith<DeviceRegistrationAuthorizationFailedException>("${failure::class}") {
                server.register(alicePhone, phoneKey, alicePrincipal)
            }
            assertSame(failure, thrown.cause)
            assertFalse(thrown.message.orEmpty().contains("SECRET"), "the fixed message carries no host text")
            assertNull(storage.devices.registration(alicePhone), "nothing registered")
        }
    }

    @Test
    fun n4CancellationIsRethrown() = runTest {
        val storage = InMemoryServerStorage()
        val cancellation = CancellationException("host call cancelled")
        val server = SecureMessageServer(storage, clock, TestDeviceRegistrationAuthorizer.throwing(cancellation))
        val thrown = assertFailsWith<CancellationException> { server.register(alicePhone, phoneKey, alicePrincipal) }
        assertSame(cancellation, thrown, "cancellation propagates unchanged, never wrapped")
        assertNull(storage.devices.registration(alicePhone))
    }

    @Test
    fun n4VirtualMachineErrorIsNotWrapped() = runTest {
        val storage = InMemoryServerStorage()
        // A harmless stand-in: constructing a VirtualMachineError subclass does not affect the JVM.
        val fatal = object : VirtualMachineError("simulated VM condition") {}
        val server = SecureMessageServer(storage, clock, TestDeviceRegistrationAuthorizer.throwing(fatal))
        val thrown = assertFailsWith<VirtualMachineError> { server.register(alicePhone, phoneKey, alicePrincipal) }
        assertSame(fatal, thrown, "process conditions are not turned into an ordinary server failure")
        assertNull(storage.devices.registration(alicePhone))
    }

    @Test
    fun n4BoundaryPolicy() {
        val cancellation = CancellationException("c")
        assertSame(cancellation, assertFailsWith<CancellationException> { runHostRegistrationBoundary { throw cancellation } })
        val error = AssertionError("SECRET")
        assertSame(error, assertFailsWith<DeviceRegistrationAuthorizationFailedException> { runHostRegistrationBoundary { throw error } }.cause)
        assertEquals(7, runHostRegistrationBoundary { 7 })
    }

    @Test
    fun authenticationFailsBeforeTheHostIsAsked() = runTest {
        val storage = InMemoryServerStorage()
        val authorizer = TestDeviceRegistrationAuthorizer.allowOnly(alicePhone)
        val server = SecureMessageServer(storage, clock, authorizer)
        val body = "register".encodeToByteArray()
        // Signed with another key than the one registered: no proof of possession.
        val request = ServerRequest(alicePhone, "PUT", ServerApiPaths.device(alicePhone, ServerApiPaths.REGISTRATION), body)
        assertFailsWith<DeviceAuthenticationException.InvalidAuthentication> {
            server.registerDevice(alicePrincipal, DeviceRegistration(alicePhone, phoneKey.publicKey), body, ServerRequestAuthentication.sign(malloryKey, request, clock.now))
        }
        assertTrue(authorizer.requests.isEmpty())
        assertNull(storage.devices.registration(alicePhone))
    }

    // N2: nothing the authorizer sees depends on KSecureMessage's registrations.

    @Test
    fun n2NoAuthorizationInputDependsOnExistingDevices() = runTest {
        // The request carries the address and the proposed key, nothing about existing devices.
        assertEquals(setOf("address", "key"), DeviceRegistrationAuthorizationRequest::class.java.declaredFields.map { it.name }.toSet())

        val storage = InMemoryServerStorage()
        val authorizer = TestDeviceRegistrationAuthorizer.principalOwnsUser()
        val server = SecureMessageServer(storage, clock, authorizer)
        // A user without devices and a user with devices get the same decision for the same principal.
        val carolFirst = DeviceAddress(UserId("carol"), DeviceId("first"))
        assertFailsWith<DeviceRegistrationException.NotAuthorized> { server.register(carolFirst, newKey(), malloryPrincipal) }
        assertTrue(server.register(alicePhone, phoneKey, alicePrincipal))
        assertFailsWith<DeviceRegistrationException.NotAuthorized> { server.register(aliceLaptop, newKey(), malloryPrincipal) }
        assertTrue(server.register(carolFirst, newKey(), TestRegistrationPrincipal(UserId("carol"))))
        assertTrue(server.register(aliceLaptop, laptopKey, alicePrincipal))
        assertEquals(setOf(alicePhone, aliceLaptop, carolFirst), setOfNotNull(
            storage.devices.registration(alicePhone)?.address,
            storage.devices.registration(aliceLaptop)?.address,
            storage.devices.registration(carolFirst)?.address,
        ))
    }
}
