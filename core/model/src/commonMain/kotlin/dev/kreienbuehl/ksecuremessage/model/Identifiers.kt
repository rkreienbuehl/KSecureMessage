package dev.kreienbuehl.ksecuremessage.model

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

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

@Serializable
@JvmInline
value class MessageId(val value: String)

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
