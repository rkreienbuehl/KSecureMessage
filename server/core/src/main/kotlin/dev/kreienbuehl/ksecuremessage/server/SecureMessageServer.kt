package dev.kreienbuehl.ksecuremessage.server

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceRegistration
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication
import dev.kreienbuehl.ksecuremessage.protocol.RequestAuthentication
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequestAuthentication
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationException
import dev.kreienbuehl.ksecuremessage.storage.MailboxRepository
import dev.kreienbuehl.ksecuremessage.storage.PreKeyPublicationException
import dev.kreienbuehl.ksecuremessage.storage.ServerStorage
import kotlin.time.Clock

/**
 * Blind relay: stores public prekeys and queues opaque envelopes. Never
 * decrypts payloads and never holds client secrets.
 *
 * Device-scoped operations need the device's authentication
 * (docs/server-authentication.md): a device registers its authentication key
 * once ([registerDevice]); publishing prekeys and draining the mailbox then
 * take an [AuthenticatedDevice] from [authenticate]. Fetching a prekey bundle
 * and relaying an envelope stay open to anyone. [clock] is the server time
 * that request timestamps are checked against.
 */
class SecureMessageServer(
    private val storage: ServerStorage,
    clock: Clock = Clock.System,
) {
    private val preKeys = PreKeyService(storage.preKeys)
    private val authenticator = DeviceAuthenticator(storage.devices, storage.authenticationNonces, clock)

    /**
     * Registers the device authentication key of [registration]'s address.
     * [body] is the exact HTTP body the request carried and [authentication]
     * must be signed with the key being registered. Returns `true` for a
     * first registration, `false` if exactly this key was registered before.
     *
     * Throws [DeviceRegistrationException.InvalidRegistration] for a key of
     * the wrong size, [DeviceAuthenticationException] if the request is not
     * authenticated with that key (nothing is registered), and
     * [DeviceRegistrationException.Conflict] if another key is registered;
     * a registered key is never replaced.
     *
     * First registration is trust on first registration: whoever registers
     * an unregistered address first owns it. There is no reset.
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
        return storage.devices.register(registration)
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
