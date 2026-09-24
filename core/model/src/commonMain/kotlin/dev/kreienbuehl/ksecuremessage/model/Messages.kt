package dev.kreienbuehl.ksecuremessage.model

import kotlinx.serialization.Serializable

/**
 * Transport envelope. The payload stays opaque to the server.
 *
 * `protocolVersion` gives the wire format room to evolve independently of
 * Kodium's internal serialization format.
 */
@Serializable
data class EncryptedEnvelope(
    val id: MessageId,
    val sender: DeviceAddress,
    val recipient: DeviceAddress,
    val protocolVersion: Int = 1,
    val payload: ByteArray,
)

/**
 * Public data published by a device for asynchronous session establishment.
 * Byte arrays intentionally avoid exposing Kodium-specific key types in the
 * public KSecureMessage model.
 */
@Serializable
data class PreKeyBundle(
    val address: DeviceAddress,
    val identityKey: ByteArray,
    val signedPreKey: ByteArray,
    val signedPreKeySignature: ByteArray,
    val oneTimePreKey: ByteArray? = null,
)
