package dev.kreienbuehl.ksecuremessage.model

import kotlin.io.encoding.Base64
import kotlin.time.Instant

/**
 * Server-chosen identifier of one pending recovery key reset
 * (docs/recovery-key-reset.md): 16 cryptographically random bytes. Not
 * secret, but never printed by [toString]. The canonical text form [encode]
 * is Base64url without padding (22 characters).
 */
class RecoveryKeyResetId(bytes: ByteArray) {
    private val value: ByteArray = bytes.copyOf()

    init {
        require(value.size == SIZE) { "Recovery key reset ID must have $SIZE bytes" }
    }

    /** A copy of the 16 ID bytes. */
    val bytes: ByteArray get() = value.copyOf()

    /** The canonical text form: Base64url without padding, [TEXT_LENGTH] characters. */
    fun encode(): String = TEXT.encode(value)

    override fun equals(other: Any?): Boolean = other is RecoveryKeyResetId && value.contentEquals(other.value)

    override fun hashCode(): Int = value.contentHashCode()

    override fun toString(): String = "RecoveryKeyResetId(<redacted>)"

    companion object {
        const val SIZE: Int = 16

        /** Length of [encode]'s result. */
        const val TEXT_LENGTH: Int = 22

        private val TEXT = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT)

        /**
         * Decodes the canonical text form. Strict: exactly [TEXT_LENGTH]
         * Base64url characters, no padding, canonical. Throws
         * [IllegalArgumentException] otherwise.
         */
        fun decode(value: String): RecoveryKeyResetId {
            require(value.length == TEXT_LENGTH) { "Recovery key reset ID has an invalid length" }
            require(value.all { it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_' }) {
                "Recovery key reset ID contains an invalid character"
            }
            val bytes = try {
                TEXT.decode(value)
            } catch (e: IllegalArgumentException) {
                throw IllegalArgumentException("Recovery key reset ID is malformed")
            }
            require(bytes.size == SIZE && TEXT.encode(bytes) == value) { "Recovery key reset ID is not canonical" }
            return RecoveryKeyResetId(bytes)
        }
    }
}

/**
 * The pending delayed reset of a user's offline recovery key
 * (docs/recovery-key-reset.md), as returned to a registered device of the
 * user by the signed `GET …/last-device-recovery/key/reset`, or to the holder
 * of the current recovery key by the recovery-key-signed status query.
 *
 * Applications must check this themselves (poll it, surface it to the user):
 * the library sends no notification and never completes a reset on its own.
 */
sealed interface RecoveryKeyResetStatus {
    /** No reset is pending. */
    data object None : RecoveryKeyResetStatus

    /**
     * A reset [resetId] requested by [requestedBy] at the server time
     * [requestedAt] is pending. It can be completed from [eligibleAt] on
     * (server time; nothing happens automatically then) and cancelled until
     * it is completed. It replaces the recovery key [recoveryPublicKey]
     * (32 bytes, public data) at [recoveryKeyEpoch]; that key stays
     * authoritative, including for last-device recovery, until completion.
     */
    class Pending(
        val resetId: RecoveryKeyResetId,
        val requestedBy: DeviceAddress,
        val requestedAt: Instant,
        val eligibleAt: Instant,
        val recoveryKeyEpoch: Long,
        recoveryPublicKey: ByteArray,
    ) : RecoveryKeyResetStatus {
        private val key: ByteArray = recoveryPublicKey.copyOf()

        init {
            require(recoveryKeyEpoch >= 1) { "Recovery key epoch must be positive" }
            require(key.size == 32) { "Recovery public key has an invalid size" }
            require(eligibleAt > requestedAt) { "A reset becomes eligible after it was requested" }
        }

        /** A copy of the recovery public key the reset replaces. */
        val recoveryPublicKey: ByteArray get() = key.copyOf()

        /** The user this reset belongs to. */
        val userId: UserId get() = requestedBy.userId

        /** `true` if the server would accept a completion at [now] (by the server's clock). */
        fun isEligibleAt(now: Instant): Boolean = now >= eligibleAt

        override fun equals(other: Any?): Boolean =
            other is Pending && resetId == other.resetId && requestedBy == other.requestedBy &&
                requestedAt == other.requestedAt && eligibleAt == other.eligibleAt &&
                recoveryKeyEpoch == other.recoveryKeyEpoch && key.contentEquals(other.key)

        override fun hashCode(): Int = (31 * resetId.hashCode() + eligibleAt.hashCode()) * 31 + recoveryKeyEpoch.hashCode()

        override fun toString(): String =
            "Pending(requestedBy=$requestedBy, requestedAt=$requestedAt, eligibleAt=$eligibleAt, recoveryKeyEpoch=$recoveryKeyEpoch)"
    }
}
