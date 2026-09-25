package dev.kreienbuehl.ksecuremessage.model

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
