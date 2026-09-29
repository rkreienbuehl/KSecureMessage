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
 *
 * [initiationVersion] is the session initiation format (docs/session-lifecycle.md).
 * New initiations are always [SessionInitiationVersion.V2], which
 * authenticates every header field and both device addresses. A
 * [SessionInitiationVersion.V1] message only continues a session that exists
 * already; it never creates, replaces or wins anything (S1).
 */
@Serializable
data class PreKeyMessage(
    val identityKey: ByteArray,
    val ephemeralKey: ByteArray,
    val signedPreKeyId: SignedPreKeyId,
    val oneTimePreKeyId: OneTimePreKeyId?,
    val message: RatchetMessage,
    val initiationVersion: SessionInitiationVersion = SessionInitiationVersion.V2,
) : CiphertextMessage

/**
 * Session initiation format (docs/session-lifecycle.md, S1 in
 * docs/security-review-remediation.md).
 */
@Serializable
enum class SessionInitiationVersion {
    /**
     * Milestones 1–25: the associated data is only both identity keys; the
     * ephemeral key's signing half and the prekey IDs are not authenticated
     * and the sender address is not bound. Accepted only to continue an
     * existing session.
     */
    V1,

    /**
     * S1: the associated data is the canonical initiation transcript
     * (domain, sender and recipient address, both identity keys, the whole
     * ephemeral key, both prekey IDs), so every header field and both
     * addresses are authenticated, and the initiation ID is derived from
     * exactly those bytes.
     */
    V2,
}
