package dev.kreienbuehl.ksecuremessage.model

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline
import kotlin.uuid.Uuid

@Serializable
@JvmInline
value class UserId(val value: String)

@Serializable
@JvmInline
value class DeviceId(val value: String)

@Serializable
data class DeviceAddress(
    val userId: UserId,
    val deviceId: DeviceId,
)

/**
 * ID of one [EncryptedEnvelope]: one transport attempt. A logical message
 * that is sent again gets a new envelope with a new [MessageId] but keeps
 * its [LogicalMessageId].
 */
@Serializable
@JvmInline
value class MessageId(val value: String)

/**
 * KSecureMessage-owned identifier of one logical application message
 * (docs/message-reliability.md). 128 random bits chosen by the sending
 * device. It travels inside the encrypted payload, never in the envelope, and
 * stays the same when the message is encrypted again for a resend. Only
 * meaningful together with the sender's [DeviceAddress]: two devices may
 * pick the same value for unrelated messages.
 */
@JvmInline
value class LogicalMessageId(val uuid: Uuid) {
    fun toByteArray(): ByteArray = uuid.toByteArray()

    override fun toString(): String = uuid.toString()

    companion object {
        const val SIZE: Int = Uuid.SIZE_BYTES

        fun random(): LogicalMessageId = LogicalMessageId(Uuid.random())

        /** Any [SIZE] bytes; throws [IllegalArgumentException] for another length. */
        fun fromByteArray(bytes: ByteArray): LogicalMessageId {
            require(bytes.size == SIZE) { "Logical message ID must be $SIZE bytes" }
            return LogicalMessageId(Uuid.fromByteArray(bytes))
        }
    }
}

/**
 * KSecureMessage-owned identifier of a signed prekey. Chosen by the owning
 * device; used to select the matching private key when a [PreKeyMessage]
 * arrives and, later, for rotation. Range `0..Int.MAX_VALUE`: the wire format
 * encodes it as 32 bits with the high bit clear.
 */
@Serializable
@JvmInline
value class SignedPreKeyId(val value: Int) {
    init {
        require(value >= 0) { "Signed prekey ID must not be negative" }
    }
}

/**
 * KSecureMessage-owned identifier of a one-time prekey. Separate ID space from
 * [SignedPreKeyId]. Used to find and then delete the consumed private key.
 * Range `0..Int.MAX_VALUE`, like [SignedPreKeyId].
 */
@Serializable
@JvmInline
value class OneTimePreKeyId(val value: Int) {
    init {
        require(value >= 0) { "One-time prekey ID must not be negative" }
    }
}
