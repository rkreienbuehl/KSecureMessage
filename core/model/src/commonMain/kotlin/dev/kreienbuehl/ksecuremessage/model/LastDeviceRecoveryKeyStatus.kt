package dev.kreienbuehl.ksecuremessage.model

import kotlin.time.Instant

/**
 * The server's state of a user's offline last-device recovery key
 * (docs/recovery-key-lifecycle.md), as returned to a registered device of the
 * user by the signed `GET /v1/devices/{user}/{device}/last-device-recovery/key`.
 *
 * The recovery key epoch is 1 after the first registration and grows by one
 * with every rotation, revocation and registration after a revocation. It
 * never decreases and is independent of any device authentication epoch.
 */
sealed interface LastDeviceRecoveryKeyStatus {
    /** The user never registered a recovery key. */
    data object Unconfigured : LastDeviceRecoveryKeyStatus

    /**
     * A recovery key is registered: [publicKey] (32 bytes, public data), at
     * [epoch], installed at the server time [installedAt] (registration or
     * the rotation that installed it; retries change neither).
     */
    class Active(val epoch: Long, val installedAt: Instant, publicKey: ByteArray) : LastDeviceRecoveryKeyStatus {
        private val key: ByteArray = publicKey.copyOf()

        init {
            require(epoch >= 1) { "Recovery key epoch must be positive" }
        }

        /** A copy of the active recovery public key. */
        val publicKey: ByteArray get() = key.copyOf()

        /** `true` if [publicKey] is the active recovery key. */
        fun isKey(publicKey: ByteArray): Boolean = key.contentEquals(publicKey)

        override fun equals(other: Any?): Boolean =
            other is Active && epoch == other.epoch && installedAt == other.installedAt && key.contentEquals(other.key)

        override fun hashCode(): Int = (31 * epoch.hashCode() + installedAt.hashCode()) * 31 + key.contentHashCode()

        override fun toString(): String = "Active(epoch=$epoch, installedAt=$installedAt)"
    }

    /**
     * The recovery key was revoked at the server time [revokedAt]; no key is
     * registered and no last-device recovery is possible until a new key is
     * registered (at a higher epoch).
     */
    data class Revoked(val epoch: Long, val revokedAt: Instant) : LastDeviceRecoveryKeyStatus {
        init {
            require(epoch >= 1) { "Recovery key epoch must be positive" }
        }
    }
}
