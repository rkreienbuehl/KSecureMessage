package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage

// Trust on first use for remote identity keys, see docs/identity-trust.md.
// Both functions run on the receiver of a ClientStorage.transaction, so the
// check, the crypto work and the pin are one atomic, serialized step.

/**
 * Compares [identityKey] with the key pinned for [address]. Returns `true`
 * if the same key is pinned and `false` if none is pinned yet. Throws
 * [SecureMessageClientException.IdentityChanged] for a different key.
 * Writes nothing: pin only after the key passed the protocol's checks, see
 * [pinRemoteIdentity].
 */
internal suspend fun ClientStorage.checkRemoteIdentity(address: DeviceAddress, identityKey: ByteArray): Boolean {
    val pinned = remoteIdentities.identityKey(address) ?: return false
    if (!pinned.contentEquals(identityKey)) throw SecureMessageClientException.IdentityChanged(address)
    return true
}

/** Pins [identityKey] for [address]. Call only after a successful session setup or decrypt with it. */
internal suspend fun ClientStorage.pinRemoteIdentity(address: DeviceAddress, identityKey: ByteArray) {
    remoteIdentities.store(address, identityKey)
}
