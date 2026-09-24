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
 * Public half of a signed prekey. [signature] is the identity key's detached
 * signature over [publicKey]; initiators must reject bundles where it does not
 * verify.
 */
@Serializable
data class PublicSignedPreKey(
    val id: SignedPreKeyId,
    val publicKey: ByteArray,
    val signature: ByteArray,
)

/** Public half of a one-time prekey. Each one should be handed out at most once. */
@Serializable
data class PublicOneTimePreKey(
    val id: OneTimePreKeyId,
    val publicKey: ByteArray,
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
    val signedPreKey: PublicSignedPreKey,
    val oneTimePreKey: PublicOneTimePreKey? = null,
)

/** Output of `ProtocolEngine.encrypt`, input of `ProtocolEngine.decrypt`. */
@Serializable
sealed interface CiphertextMessage

/**
 * A Double Ratchet message on an established session. [bytes] is opaque:
 * ratchet header plus authenticated ciphertext.
 */
@Serializable
data class RatchetMessage(val bytes: ByteArray) : CiphertextMessage

/**
 * A ratchet message plus the X3DH data the recipient needs to create its side
 * of the session.
 *
 * The initiator sends every message as a [PreKeyMessage] until it has
 * decrypted the first reply. So the recipient can still set up the session if
 * earlier messages were lost or arrive out of order. [signedPreKeyId] and
 * [oneTimePreKeyId] tell the recipient which of its private prekeys to use.
 */
@Serializable
data class PreKeyMessage(
    val identityKey: ByteArray,
    val ephemeralKey: ByteArray,
    val signedPreKeyId: SignedPreKeyId,
    val oneTimePreKeyId: OneTimePreKeyId?,
    val message: RatchetMessage,
) : CiphertextMessage
