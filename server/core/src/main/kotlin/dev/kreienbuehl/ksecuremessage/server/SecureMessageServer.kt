package dev.kreienbuehl.ksecuremessage.server

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceAuthenticationRegistrationStatus
import dev.kreienbuehl.ksecuremessage.model.DeviceRegistration
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationRotationAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecoveryAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.RequestAuthentication
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequestAuthentication
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationException
import dev.kreienbuehl.ksecuremessage.storage.MailboxRepository
import dev.kreienbuehl.ksecuremessage.storage.PreKeyPublicationException
import dev.kreienbuehl.ksecuremessage.storage.ServerStorage
import kotlin.time.Clock
import kotlin.time.Instant

/**
 * Blind relay: stores public prekeys and queues opaque envelopes. Never
 * decrypts payloads and never holds client secrets.
 *
 * Device-scoped operations need the device's authentication
 * (docs/server-authentication.md): a device registers its authentication key
 * once ([registerDevice]); publishing prekeys and draining the mailbox then
 * take an [AuthenticatedDevice] from [authenticate]. Fetching a prekey bundle
 * and relaying an envelope stay open to anyone. [clock] is the server time
 * that request timestamps are checked against and that is recorded as the
 * installation time of registered device authentication keys.
 */
class SecureMessageServer(
    private val storage: ServerStorage,
    private val clock: Clock = Clock.System,
) {
    private val preKeys = PreKeyService(storage.preKeys)
    private val authenticator = DeviceAuthenticator(storage.devices, storage.authenticationNonces, clock)
    private val recovery = DeviceRecoveryService(storage.devices, clock)
    private val rotation = DeviceAuthenticationRotationService(storage.devices, clock)

    /**
     * Registers the device authentication key of [registration]'s address.
     * [body] is the exact HTTP body the request carried and [authentication]
     * must be signed with the key being registered. Returns `true` for a
     * first registration, `false` if exactly this key was registered before.
     *
     * A first registration records [clock]'s time as the key's installation
     * time; a repeated registration of the same key keeps the recorded one.
     *
     * Throws [DeviceRegistrationException.InvalidRegistration] for a key of
     * the wrong size, [DeviceAuthenticationException] if the request is not
     * authenticated with that key (nothing is registered), and
     * [DeviceRegistrationException.Conflict] if another key is registered;
     * a registered key is never replaced.
     *
     * First registration is trust on first registration: whoever registers
     * an unregistered address first owns it. There is no reset; only
     * [recoverDevice] and [rotateDeviceAuthenticationKey] replace a
     * registered key.
     */
    suspend fun registerDevice(
        registration: DeviceRegistration,
        body: ByteArray,
        authentication: RequestAuthentication?,
    ): Boolean {
        if (registration.publicKey.size != ServerRequestAuthentication.PUBLIC_KEY_SIZE) {
            throw DeviceRegistrationException.InvalidRegistration("Device authentication key has an invalid size")
        }
        authenticator.authenticateRegistration(registration.address, registration.publicKey, body, authentication)
        return storage.devices.register(registration, installedAt = Instant.fromEpochMilliseconds(clock.now().toEpochMilliseconds()))
    }

    /**
     * Replaces the registered device authentication key of
     * [authorization]'s target with its replacement key, authorized by
     * another registered device of the same user and proven by the
     * replacement key (docs/device-recovery.md). Throws
     * [DeviceRecoveryException] and changes nothing if any check fails.
     *
     * From the moment this returns [DeviceRecoveryOutcome.REPLACED], only
     * the replacement key authenticates the target; the old key is rejected.
     * The target's messaging identity, prekeys and mailbox are not touched.
     * A retry of the same recovery returns [DeviceRecoveryOutcome.ALREADY_APPLIED].
     */
    suspend fun recoverDevice(authorization: DeviceRecoveryAuthorization): DeviceRecoveryOutcome =
        recovery.recover(authorization)

    /**
     * Replaces [address]'s registered device authentication key K1 with the
     * statement's replacement key K2 in a routine rotation
     * (docs/device-authentication-rotation.md): authorized by K1 (the
     * registered key at the statement's epoch) and proven by K2. The
     * statement is the request's authentication; no other device takes part.
     * Throws [DeviceAuthenticationRotationException] and changes nothing if
     * any check fails.
     *
     * From the moment this returns [DeviceAuthenticationRotationOutcome.ROTATED],
     * only K2 authenticates the device and the epoch is one higher. The
     * messaging identity, prekeys and mailbox are not touched. A retry of the
     * same rotation returns [DeviceAuthenticationRotationOutcome.ALREADY_APPLIED].
     */
    suspend fun rotateDeviceAuthenticationKey(
        address: DeviceAddress,
        authorization: DeviceAuthenticationRotationAuthorization,
    ): DeviceAuthenticationRotationOutcome = rotation.rotate(address, authorization)

    /**
     * The authenticated [device]'s registration metadata: its current
     * authentication epoch, which a routine rotation statement has to name,
     * and the server time its registered key was installed at. Metadata only:
     * whether a rotation is due is the application's policy
     * (docs/device-authentication-rotation.md), never the server's.
     */
    suspend fun registrationStatus(device: AuthenticatedDevice): DeviceAuthenticationRegistrationStatus {
        require(device.endpoint == ProtectedEndpoint.READ_REGISTRATION) { "Not authenticated for the registration" }
        // The device authenticated with its registered key, so the registration exists.
        val state = checkNotNull(storage.devices.registrationState(device.address)) { "Registration disappeared" }
        return DeviceAuthenticationRegistrationStatus(state.authEpoch, state.authKeyInstalledAt)
    }

    /** See [DeviceAuthenticator.authenticate]. */
    suspend fun authenticate(
        address: DeviceAddress,
        endpoint: ProtectedEndpoint,
        body: ByteArray,
        authentication: RequestAuthentication?,
    ): AuthenticatedDevice = authenticator.authenticate(address, endpoint, body, authentication)

    /**
     * Publishes prekeys for the authenticated [device]. See
     * [PreKeyService.publish]. Throws [PreKeyPublicationException] on
     * rejection.
     */
    suspend fun publishPreKeys(device: AuthenticatedDevice, publication: PreKeyPublication) {
        require(device.endpoint == ProtectedEndpoint.PUBLISH_PRE_KEYS) { "Not authenticated for prekey publication" }
        require(device.address == publication.address) { "Publication is for another device" }
        preKeys.publish(publication)
    }

    /** See [PreKeyService.fetchPreKeyBundle]. Public. */
    suspend fun fetchPreKeyBundle(address: DeviceAddress): PreKeyBundle? = preKeys.fetchPreKeyBundle(address)

    /**
     * Queues [envelope] for its recipient. When this returns, the envelope is
     * ordered after every envelope of the same sender for the same recipient
     * that was relayed before ([MailboxRepository], docs/transport-ordering.md).
     * Public: the envelope's sender is not authenticated here.
     */
    suspend fun relay(envelope: EncryptedEnvelope) = storage.mailboxes.enqueue(envelope)

    /** Removes and returns the authenticated [device]'s envelopes, each sender's in relay order. */
    suspend fun receive(device: AuthenticatedDevice): List<EncryptedEnvelope> {
        require(device.endpoint == ProtectedEndpoint.DRAIN_MAILBOX) { "Not authenticated for the mailbox" }
        return storage.mailboxes.drain(device.address)
    }
}
