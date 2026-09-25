package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceRegistration
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecoveryAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.RequestAuthentication
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequest

/**
 * Network boundary of [SecureMessageClient]. Implementations report server
 * rejections as [SecureMessageTransportException].
 *
 * Device-scoped requests (registration, prekey publication, mailbox drain)
 * are authenticated with the device authentication key
 * (docs/server-authentication.md). The client passes a [ServerRequestSigner];
 * the transport describes the exact request it sends as a [ServerRequest]
 * (method, canonical path, exact body bytes), has it signed once per attempt
 * and attaches the result.
 */
interface SecureMessageTransport {
    /**
     * Registers the device authentication public key of
     * [registration]'s address, signed with that key. Registering the same key
     * again is harmless. Throws
     * [SecureMessageTransportException.DeviceRegistrationConflict] if the
     * server holds another key for the address.
     */
    suspend fun registerDevice(registration: DeviceRegistration, signer: ServerRequestSigner)

    /**
     * Submits a device recovery (docs/device-recovery.md):
     * `PUT /v1/devices/{user}/{device}/registration/recovery` for the
     * authorization's target. Not signed with a [ServerRequestSigner]: the
     * authorization carries its own two signatures. Returns once the server
     * replaced the key, or recognized a retry of the recovery that did.
     * Throws [SecureMessageTransportException.DeviceRecoveryRejected].
     */
    suspend fun recoverDevice(authorization: DeviceRecoveryAuthorization)

    /**
     * Uploads public prekey material. The server applies it atomically and
     * treats a repeated identical publication as a no-op, so a retry after a
     * lost response is safe. Authenticated.
     */
    suspend fun publishPreKeys(publication: PreKeyPublication, signer: ServerRequestSigner)

    /**
     * Fetches a bundle for a first contact. The server consumes the one-time
     * prekey it returns. Throws [SecureMessageTransportException.DeviceNotFound]
     * for an unknown device. Public.
     */
    suspend fun fetchPreKeyBundle(address: DeviceAddress): PreKeyBundle

    /**
     * Hands [envelope] to the server. When this returns, the envelope is
     * queued behind every envelope this device sent to the same recipient
     * before (docs/transport-ordering.md). Public.
     */
    suspend fun send(envelope: EncryptedEnvelope)

    /**
     * Removes and returns the envelopes queued for [address]. Envelopes of
     * one sender come in the order that sender sent them; process them in
     * that order. Authenticated: only the registered device drains its mailbox.
     */
    suspend fun receive(address: DeviceAddress, signer: ServerRequestSigner): List<EncryptedEnvelope>
}

/**
 * Signs a device-scoped server request with the local device authentication
 * key. Every call uses the current time and a fresh nonce, so a request sent
 * again must be signed again. Never sees or returns private key bytes.
 */
fun interface ServerRequestSigner {
    suspend fun sign(request: ServerRequest): RequestAuthentication
}
