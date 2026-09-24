package dev.kreienbuehl.ksecuremessage.server

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication
import dev.kreienbuehl.ksecuremessage.protocol.PreKeyFormat
import dev.kreienbuehl.ksecuremessage.storage.PreKeyPublicationException
import dev.kreienbuehl.ksecuremessage.storage.PreKeyRepository

/**
 * Publication and handout of public prekeys. Treats every publication as
 * untrusted input: its format is checked before the [repository] sees it.
 * Conflict checks and atomicity belong to the [repository].
 *
 * The server does not verify the signed prekey signature. Initiators do
 * that before X3DH, so a tampering server cannot make them accept a bundle.
 */
class PreKeyService(
    private val repository: PreKeyRepository,
) {
    /**
     * Stores [publication] or throws a [PreKeyPublicationException] and
     * changes nothing. Safe to retry.
     */
    suspend fun publish(publication: PreKeyPublication) {
        try {
            PreKeyFormat.validate(publication)
        } catch (e: IllegalArgumentException) {
            throw PreKeyPublicationException.InvalidPublication(e.message ?: "Invalid publication")
        }
        repository.publish(publication)
    }

    /**
     * The bundle for a first contact with [address], or `null` for an unknown
     * device. Hands out and consumes at most one one-time prekey.
     */
    suspend fun fetchPreKeyBundle(address: DeviceAddress): PreKeyBundle? = repository.consumePreKeyBundle(address)
}
