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
 * Host-authorized device registration (S1, findings F1/F2;
 * docs/security-review-remediation.md): knowing a user ID, a device ID and
 * holding a device key is not enough to become one of the user's devices.
 */
class DeviceRegistrationAuthorizationTest {
    private class ManualClock(var now: Instant) : Clock {
        override fun now(): Instant = now
    }

    private val engine = KodiumProtocolEngine()
    private val clock = ManualClock(Instant.fromEpochMilliseconds(1_767_225_600_000))
    private val alicePhone = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val aliceLaptop = DeviceAddress(UserId("alice"), DeviceId("laptop"))
    private val mallory = DeviceAddress(UserId("alice"), DeviceId("mallory"))

    private fun newKey(): DeviceAuthenticationKeyPair = runBlocking { engine.createDeviceAuthenticationKey() }

    private val phoneKey = newKey()
    private val laptopKey = newKey()
    private val malloryKey = newKey()

    private suspend fun SecureMessageServer.register(address: DeviceAddress, key: DeviceAuthenticationKeyPair): Boolean {
        val body = "register".encodeToByteArray() + key.publicKey
        val request = ServerRequest(address, "PUT", ServerApiPaths.device(address, ServerApiPaths.REGISTRATION), body)
        return registerDevice(DeviceRegistration(address, key.publicKey), body, ServerRequestAuthentication.sign(key, request, clock.now, RequestNonce.random()))
    }

    private suspend fun SecureMessageServer.signed(address: DeviceAddress, key: DeviceAuthenticationKeyPair, endpoint: ProtectedEndpoint, body: ByteArray = ByteArray(0)) =
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
        devices.hasRegisteredDevices(alicePhone.userId),
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
        assertFailsWith<DeviceRegistrationException.NotAuthorized> { server.register(mallory, malloryKey) }
        assertEquals(before, storage.snapshot(), "no partial membership")
        assertNull(storage.devices.registration(mallory))
        val asked = authorizer.requests.last()
        assertEquals(mallory, asked.address)
        assertEquals(DeviceRegistrationUserState.USER_HAS_REGISTERED_DEVICES, asked.userState)
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
        val authorizer = TestDeviceRegistrationAuthorizer.denyAll()
        val server = SecureMessageServer(storage, clock, authorizer)
        assertFailsWith<DeviceRegistrationException.NotAuthorized> { server.register(mallory, malloryKey) }
        assertFalse(storage.devices.hasRegisteredDevices(mallory.userId), "first writer does not win")
        assertEquals(DeviceRegistrationUserState.USER_HAS_NO_REGISTERED_DEVICES, authorizer.requests.single().userState)
    }

    @Test
    fun f2AuthorizedSecondDeviceParticipatesInSameUserFlows() = runTest {
        val storage = InMemoryServerStorage()
        val server = SecureMessageServer(storage, clock, TestDeviceRegistrationAuthorizer.allowOnly(alicePhone, aliceLaptop))
        assertTrue(server.register(alicePhone, phoneKey))
        assertTrue(server.register(aliceLaptop, laptopKey))
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

    @Test
    fun sameKeyRetryIsIdempotentWithoutAskingTheHost() = runTest {
        val storage = InMemoryServerStorage()
        var allow = true
        val authorizer = TestDeviceRegistrationAuthorizer.allowOnly(alicePhone)
        val server = SecureMessageServer(
            storage,
            clock,
            DeviceRegistrationAuthorizer { request -> if (allow) authorizer.authorize(request) else DeviceRegistrationAuthorizationResult.Denied },
        )
        assertTrue(server.register(alicePhone, phoneKey))
        assertEquals(1, authorizer.requests.size)
        // The host would now deny, but exactly this device and key are registered: no membership change.
        allow = false
        assertFalse(server.register(alicePhone, phoneKey))
        assertEquals(1, authorizer.requests.size, "the authorizer is not asked for a retry")
        // A different key for the registered address is a conflict, never an authorization question.
        assertFailsWith<DeviceRegistrationException.Conflict> { server.register(alicePhone, malloryKey) }
        assertContentEquals(phoneKey.publicKey, storage.devices.registration(alicePhone)?.publicKey)
        // A new device of the same user is asked about (and here denied).
        assertFailsWith<DeviceRegistrationException.NotAuthorized> { server.register(aliceLaptop, laptopKey) }
        assertNull(storage.devices.registration(aliceLaptop))
    }

    @Test
    fun authorizerFailureRegistersNothing() = runTest {
        val storage = InMemoryServerStorage()
        val failure = IllegalStateException("host account service unavailable: secret detail")
        val server = SecureMessageServer(storage, clock, TestDeviceRegistrationAuthorizer.throwing(failure))
        val thrown = assertFailsWith<IllegalStateException> { server.register(alicePhone, phoneKey) }
        assertSame(failure, thrown)
        assertNull(storage.devices.registration(alicePhone))
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
            server.registerDevice(DeviceRegistration(alicePhone, phoneKey.publicKey), body, ServerRequestAuthentication.sign(malloryKey, request, clock.now))
        }
        assertTrue(authorizer.requests.isEmpty())
        assertNull(storage.devices.registration(alicePhone))
    }
}
