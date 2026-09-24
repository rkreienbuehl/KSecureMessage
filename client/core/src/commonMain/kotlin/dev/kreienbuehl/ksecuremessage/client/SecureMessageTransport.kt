package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication

/**
 * Network boundary of [SecureMessageClient]. Implementations report server
 * rejections as [SecureMessageTransportException].
 */
interface SecureMessageTransport {
    /**
     * Uploads public prekey material. The server applies it atomically and
     * treats a repeated identical publication as a no-op, so a retry after a
     * lost response is safe.
     */
    suspend fun publishPreKeys(publication: PreKeyPublication)

    /**
     * Fetches a bundle for a first contact. The server consumes the one-time
     * prekey it returns. Throws [SecureMessageTransportException.DeviceNotFound]
     * for an unknown device.
     */
    suspend fun fetchPreKeyBundle(address: DeviceAddress): PreKeyBundle

    /**
     * Hands [envelope] to the server. When this returns, the envelope is
     * queued behind every envelope this device sent to the same recipient
     * before (docs/transport-ordering.md).
     */
    suspend fun send(envelope: EncryptedEnvelope)

    /**
     * Removes and returns the envelopes queued for [address]. Envelopes of
     * one sender come in the order that sender sent them; process them in
     * that order.
     */
    suspend fun receive(address: DeviceAddress): List<EncryptedEnvelope>
}
