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

    suspend fun send(envelope: EncryptedEnvelope)
    suspend fun receive(address: DeviceAddress): List<EncryptedEnvelope>
}
