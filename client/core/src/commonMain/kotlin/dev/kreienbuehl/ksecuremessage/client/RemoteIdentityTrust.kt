package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.protocol.PublicIdentityKey
import dev.kreienbuehl.ksecuremessage.protocol.VerificationState
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage

/**
 * The trust state of one remote device (docs/identity-verification.md): the
 * identity key pinned on first use or by an accepted change, and whether the
 * user verified exactly that key. Pinning and verification are separate: a
 * pin is always present here, verification only after the user compared the
 * safety number.
 */
class RemoteIdentityTrust(
    val address: DeviceAddress,
    val identityKey: PublicIdentityKey,
    val verification: VerificationState,
) {
    override fun equals(other: Any?): Boolean =
        other is RemoteIdentityTrust && address == other.address && identityKey == other.identityKey && verification == other.verification

    override fun hashCode(): Int = (address.hashCode() * 31 + identityKey.hashCode()) * 31 + verification.hashCode()

    override fun toString(): String = "RemoteIdentityTrust($address, $verification)"
}

/**
 * A change of [remote]'s identity from [previousIdentityKey] (pinned) to
 * [presentedIdentityKey], as reported by
 * [SecureMessageClientException.IdentityChanged]. Accepting it
 * ([SecureMessageClient.acceptRemoteIdentityChange]) installs exactly
 * [presentedIdentityKey], and only while [previousIdentityKey] is still
 * pinned.
 */
class RemoteIdentityChange(
    val remote: DeviceAddress,
    val previousIdentityKey: PublicIdentityKey,
    val presentedIdentityKey: PublicIdentityKey,
) {
    init {
        require(previousIdentityKey != presentedIdentityKey) { "An identity change needs two different keys" }
    }

    override fun equals(other: Any?): Boolean =
        other is RemoteIdentityChange && remote == other.remote &&
            previousIdentityKey == other.previousIdentityKey && presentedIdentityKey == other.presentedIdentityKey

    override fun hashCode(): Int = (remote.hashCode() * 31 + previousIdentityKey.hashCode()) * 31 + presentedIdentityKey.hashCode()

    override fun toString(): String = "RemoteIdentityChange($remote)"
}

// Trust on first use for remote identity keys, see docs/identity-trust.md.
// Both functions run on the receiver of a ClientStorage.transaction, so the
// check, the crypto work and the pin are one atomic, serialized step.

/**
 * Compares [identityKey] with the key pinned for [address]. Returns `true`
 * if the same key is pinned and `false` if none is pinned yet. Throws
 * [SecureMessageClientException.IdentityChanged] for a different key; it
 * never accepts the change. Writes nothing: pin only after the key passed the
 * protocol's checks, see [pinRemoteIdentity]. [identityKey] must have
 * [PublicIdentityKey.SIZE] bytes.
 */
internal suspend fun ClientStorage.checkRemoteIdentity(address: DeviceAddress, identityKey: ByteArray): Boolean {
    val pinned = remoteIdentities.identityKey(address) ?: return false
    if (!pinned.contentEquals(identityKey)) {
        throw SecureMessageClientException.IdentityChanged(
            RemoteIdentityChange(address, PublicIdentityKey(pinned), PublicIdentityKey(identityKey)),
        )
    }
    return true
}

/** Pins [identityKey] for [address]. Call only after a successful session setup or decrypt with it. */
internal suspend fun ClientStorage.pinRemoteIdentity(address: DeviceAddress, identityKey: ByteArray) {
    remoteIdentities.store(address, identityKey)
}
