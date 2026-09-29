package dev.kreienbuehl.ksecuremessage.protocol

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyMessage
import dev.kreienbuehl.ksecuremessage.model.SessionInitiationVersion
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import org.kotlincrypto.hash.sha2.SHA256

/**
 * Identifies one X3DH session initiation: 32 bytes (see docs/session-lifecycle.md).
 *
 * **Version 2** (S1, every new initiation): SHA-256 over the canonical
 * initiation transcript, which is also the session's ratchet associated
 * data, so the ID is derived only from bytes the first message's AEAD
 * authenticates:
 *
 * ```
 * u32 length | "KSecureMessage-SessionInitiation-v2" (UTF-8)
 * | u32 length | sender userId (UTF-8) | u32 length | sender deviceId (UTF-8)
 * | u32 length | recipient userId (UTF-8) | u32 length | recipient deviceId (UTF-8)
 * | initiatorIdentityKey[64] | responderIdentityKey[64] | ephemeralKey[64]
 * | signedPreKeyId:u32 | flag:u8 (0x00 absent, 0x01 present) | [oneTimePreKeyId:u32]
 * ```
 *
 * The sender is the initiator. A relay that changes any of these bytes
 * (including the signing half of the ephemeral key, a prekey ID or either
 * address) makes the first message fail to decrypt, so it can never obtain
 * a second valid ID for the same initiation.
 *
 * **Version 1** (milestones 6–25, kept for stored sessions and retired IDs
 * only): SHA-256 over
 *
 * ```
 * u32 length of domain | domain (UTF-8, ProtocolConstants.SESSION_INITIATION_DOMAIN)
 * | initiatorIdentityKey[64] | responderIdentityKey[64] | ephemeralKey[64]
 * | signedPreKeyId:u32 | flag:u8 (0x00 absent, 0x01 present) | [oneTimePreKeyId:u32]
 * ```
 *
 * whose ephemeral key signing half and prekey IDs are not authenticated by
 * X3DH (finding F3). The two versions use different domains, so their IDs
 * never coincide.
 *
 * Integers are big-endian. Both sides of a session derive the same ID: the
 * initiator from its own initiation, the responder from the
 * [PreKeyMessage] and the envelope's addresses. Before acceptance an ID
 * computed from a message is only a lookup key; it is trusted as a
 * session's origin only after decryption with the matching transcript.
 *
 * IDs are ordered unsigned-lexicographically. The order is used to pick the
 * winner of a simultaneous initiation and says nothing about age.
 */
class SessionInitiationId(bytes: ByteArray) : Comparable<SessionInitiationId> {
    private val value: ByteArray = bytes.copyOf()

    init {
        require(value.size == SIZE) { "Session initiation ID must have $SIZE bytes" }
    }

    /** A copy of the 32 ID bytes. */
    val bytes: ByteArray get() = value.copyOf()

    override fun compareTo(other: SessionInitiationId): Int {
        for (i in 0 until SIZE) {
            val result = (value[i].toInt() and 0xFF).compareTo(other.value[i].toInt() and 0xFF)
            if (result != 0) return result
        }
        return 0
    }

    // For use as a map or set key only. Protocol decisions use equals and compareTo.
    override fun equals(other: Any?): Boolean = other is SessionInitiationId && value.contentEquals(other.value)

    override fun hashCode(): Int = value.contentHashCode()

    override fun toString(): String = "SessionInitiationId(<redacted>)"

    companion object {
        const val SIZE: Int = 32

        /**
         * The version 1 ID of the initiation [message] belongs to, for the
         * responder whose public identity key is [responderIdentityKey]. Only
         * for sessions created before S1; never trust it for anything new.
         */
        fun of(message: PreKeyMessage, responderIdentityKey: ByteArray): SessionInitiationId = derive(
            initiatorIdentityKey = message.identityKey,
            responderIdentityKey = responderIdentityKey,
            ephemeralKey = message.ephemeralKey,
            signedPreKeyId = message.signedPreKeyId,
            oneTimePreKeyId = message.oneTimePreKeyId,
        )

        /**
         * The version 2 ID of the initiation [message] belongs to, for a
         * message from [sender] to [recipient], whose public identity key is
         * [responderIdentityKey]. Requires a [SessionInitiationVersion.V2]
         * message.
         */
        fun v2Of(
            message: PreKeyMessage,
            sender: DeviceAddress,
            recipient: DeviceAddress,
            responderIdentityKey: ByteArray,
        ): SessionInitiationId {
            if (message.initiationVersion != SessionInitiationVersion.V2) {
                throw ProtocolException.InvalidMessage("Not a version 2 session initiation")
            }
            return ofTranscript(
                v2Transcript(
                    sender = sender,
                    recipient = recipient,
                    initiatorIdentityKey = message.identityKey,
                    responderIdentityKey = responderIdentityKey,
                    ephemeralKey = message.ephemeralKey,
                    signedPreKeyId = message.signedPreKeyId,
                    oneTimePreKeyId = message.oneTimePreKeyId,
                ),
            )
        }

        /** The version 2 ID for [transcript] ([v2Transcript]). */
        internal fun ofTranscript(transcript: ByteArray): SessionInitiationId = SessionInitiationId(SHA256().digest(transcript))

        /** The canonical version 2 initiation transcript; see the class documentation. */
        internal fun v2Transcript(
            sender: DeviceAddress,
            recipient: DeviceAddress,
            initiatorIdentityKey: ByteArray,
            responderIdentityKey: ByteArray,
            ephemeralKey: ByteArray,
            signedPreKeyId: SignedPreKeyId,
            oneTimePreKeyId: OneTimePreKeyId?,
        ): ByteArray {
            val out = BinaryWriter()
            out.bytes(DOMAIN_V2)
            out.bytes(sender.userId.value.encodeToByteArray())
            out.bytes(sender.deviceId.value.encodeToByteArray())
            out.bytes(recipient.userId.value.encodeToByteArray())
            out.bytes(recipient.deviceId.value.encodeToByteArray())
            out.key(initiatorIdentityKey)
            out.key(responderIdentityKey)
            out.key(ephemeralKey)
            out.id(signedPreKeyId.value)
            if (oneTimePreKeyId == null) {
                out.byte(0)
            } else {
                out.byte(1)
                out.id(oneTimePreKeyId.value)
            }
            return out.toByteArray()
        }

        internal fun derive(
            initiatorIdentityKey: ByteArray,
            responderIdentityKey: ByteArray,
            ephemeralKey: ByteArray,
            signedPreKeyId: SignedPreKeyId,
            oneTimePreKeyId: OneTimePreKeyId?,
        ): SessionInitiationId {
            val out = BinaryWriter()
            out.bytes(DOMAIN)
            out.key(initiatorIdentityKey)
            out.key(responderIdentityKey)
            out.key(ephemeralKey)
            out.id(signedPreKeyId.value)
            if (oneTimePreKeyId == null) {
                out.byte(0)
            } else {
                out.byte(1)
                out.id(oneTimePreKeyId.value)
            }
            return SessionInitiationId(SHA256().digest(out.toByteArray()))
        }

        private val DOMAIN = ProtocolConstants.SESSION_INITIATION_DOMAIN.encodeToByteArray()
        private val DOMAIN_V2 = ProtocolConstants.SESSION_INITIATION_V2_DOMAIN.encodeToByteArray()

        private fun BinaryWriter.key(value: ByteArray) {
            if (value.size != ProtocolConstants.PUBLIC_KEY_SIZE) throw ProtocolException.InvalidMessage("Public key has an invalid size")
            fixed(value)
        }

        private fun BinaryWriter.id(value: Int) {
            if (value < 0) throw ProtocolException.InvalidMessage("Prekey ID out of range")
            int(value)
        }
    }
}
