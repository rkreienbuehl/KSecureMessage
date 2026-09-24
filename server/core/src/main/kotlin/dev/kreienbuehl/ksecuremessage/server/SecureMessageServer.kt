package dev.kreienbuehl.ksecuremessage.server

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication
import dev.kreienbuehl.ksecuremessage.storage.MailboxRepository
import dev.kreienbuehl.ksecuremessage.storage.PreKeyPublicationException
import dev.kreienbuehl.ksecuremessage.storage.ServerStorage

/**
 * Blind relay: stores public prekeys and queues opaque envelopes. Never
 * decrypts payloads and never holds client secrets.
 */
class SecureMessageServer(
    private val storage: ServerStorage,
) {
    private val preKeys = PreKeyService(storage.preKeys)

    /** See [PreKeyService.publish]. Throws [PreKeyPublicationException] on rejection. */
    suspend fun publishPreKeys(publication: PreKeyPublication) = preKeys.publish(publication)

    /** See [PreKeyService.fetchPreKeyBundle]. */
    suspend fun fetchPreKeyBundle(address: DeviceAddress): PreKeyBundle? = preKeys.fetchPreKeyBundle(address)

    /**
     * Queues [envelope] for its recipient. When this returns, the envelope is
     * ordered after every envelope of the same sender for the same recipient
     * that was relayed before ([MailboxRepository], docs/transport-ordering.md).
     */
    suspend fun relay(envelope: EncryptedEnvelope) = storage.mailboxes.enqueue(envelope)

    /** Removes and returns [address]'s envelopes, each sender's in relay order. */
    suspend fun receive(address: DeviceAddress): List<EncryptedEnvelope> = storage.mailboxes.drain(address)
}
