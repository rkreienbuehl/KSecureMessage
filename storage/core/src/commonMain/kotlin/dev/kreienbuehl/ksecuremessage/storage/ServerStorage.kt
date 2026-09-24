package dev.kreienbuehl.ksecuremessage.storage

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication

/**
 * Public prekey material of each device, as published by the devices. Holds
 * public keys only; the server never sees private keys. State is kept per
 * [DeviceAddress]: one identity key, one current signed prekey, an inventory
 * of available one-time prekeys and the IDs of consumed one-time prekeys.
 *
 * Both functions that change state are atomic: they either apply completely
 * or, if they throw, change nothing. Concurrent calls behave as if they ran
 * one after the other. Byte arrays are copied at the boundary.
 *
 * See docs/prekey-publication.md.
 */
interface PreKeyRepository {
    /**
     * Applies [publication]:
     * - The first publication for an address stores its identity key. A later
     *   one with a different identity key throws
     *   [PreKeyPublicationException.IdentityKeyConflict].
     * - A signed prekey with a higher ID than the current one replaces it.
     *   The same ID with the same key and signature changes nothing. The same
     *   ID with other bytes, or a lower ID, throws
     *   [PreKeyPublicationException.SignedPreKeyConflict].
     * - A one-time prekey whose ID was consumed before is skipped. One that is
     *   available with the same bytes changes nothing; with other bytes it
     *   throws [PreKeyPublicationException.OneTimePreKeyConflict]. New ones
     *   are added.
     * - A repeated one-time prekey ID within [publication] throws
     *   [PreKeyPublicationException.InvalidPublication].
     *
     * Publishing the same publication again is harmless.
     */
    suspend fun publish(publication: PreKeyPublication)

    /**
     * Returns the bundle for [address], or `null` for an unknown device. The
     * bundle holds the identity key, the current signed prekey and the
     * available one-time prekey with the lowest ID, or none if the inventory
     * is empty. That one-time prekey is removed and its ID recorded as
     * consumed, in the same atomic step: no two callers get the same one.
     */
    suspend fun consumePreKeyBundle(address: DeviceAddress): PreKeyBundle?

    /** Number of available (published, not yet handed out) one-time prekeys of [address]. */
    suspend fun oneTimePreKeyCount(address: DeviceAddress): Int
}

/** A rejected publication. The repository state is unchanged. Messages never contain key bytes. */
sealed class PreKeyPublicationException(message: String) : Exception(message) {
    /** The publication is malformed: wrong key sizes, repeated IDs, too many keys. */
    class InvalidPublication(message: String) : PreKeyPublicationException(message)

    /** The device already published a different identity key. There is no device reset yet. */
    class IdentityKeyConflict : PreKeyPublicationException("Device already has a different identity key")

    /** The signed prekey ID is known with other bytes, or older than the current one. */
    class SignedPreKeyConflict(message: String) : PreKeyPublicationException(message)

    /** A one-time prekey ID is already available with a different public key. */
    class OneTimePreKeyConflict(val id: OneTimePreKeyId) :
        PreKeyPublicationException("One-time prekey ${id.value} already exists with a different key")
}

interface MailboxRepository {
    suspend fun enqueue(envelope: EncryptedEnvelope)
    suspend fun drain(recipient: DeviceAddress): List<EncryptedEnvelope>
}

interface ServerStorage {
    val preKeys: PreKeyRepository
    val mailboxes: MailboxRepository
}
