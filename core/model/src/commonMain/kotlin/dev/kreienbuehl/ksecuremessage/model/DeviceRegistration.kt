package dev.kreienbuehl.ksecuremessage.model

import kotlin.time.Instant

/**
 * Binds [address] to the public half of that device's authentication key
 * (docs/server-authentication.md). The server verifies the device's
 * authenticated requests with [publicKey]. Public data only.
 *
 * The device authentication key is not the messaging identity key: it only
 * authenticates the device to the KSecureMessage server and plays no part in
 * X3DH, the Double Ratchet or identity pinning.
 */
class DeviceRegistration(
    val address: DeviceAddress,
    publicKey: ByteArray,
) {
    private val key: ByteArray = publicKey.copyOf()

    /** A copy of the public key bytes. */
    val publicKey: ByteArray get() = key.copyOf()

    override fun equals(other: Any?): Boolean =
        other is DeviceRegistration && address == other.address && key.contentEquals(other.key)

    override fun hashCode(): Int = 31 * address.hashCode() + key.contentHashCode()

    override fun toString(): String = "DeviceRegistration(address=$address)"
}

/**
 * The server's registration metadata of a device's authoritative device
 * authentication key (docs/device-authentication-rotation.md), as returned by
 * the signed `GET /v1/devices/{user}/{device}/registration`.
 *
 * [authEpoch] is 1 after first registration and grows by one with every
 * device recovery or routine rotation. [authKeyInstalledAt] is the server
 * time at which the currently registered key was installed: first
 * registration, the recovery or the rotation that installed it. Retries of
 * those change neither. It is not the key's local creation time.
 */
data class DeviceAuthenticationRegistrationStatus(
    val authEpoch: Long,
    val authKeyInstalledAt: Instant,
) {
    init {
        require(authEpoch >= 1) { "Authentication epoch must be positive" }
    }
}
