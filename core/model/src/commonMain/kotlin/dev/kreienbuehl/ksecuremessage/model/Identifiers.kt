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
