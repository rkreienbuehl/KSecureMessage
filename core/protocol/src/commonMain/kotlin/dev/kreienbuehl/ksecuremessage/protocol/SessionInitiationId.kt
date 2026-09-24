package dev.kreienbuehl.ksecuremessage.protocol

import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyMessage
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import org.kotlincrypto.hash.sha2.SHA256

/**
 * Identifies one X3DH session initiation: 32 bytes, SHA-256 over the
 * initiation's public inputs (see docs/session-lifecycle.md):
 *
 * ```
 * u32 length of domain | domain (UTF-8, ProtocolConstants.SESSION_INITIATION_DOMAIN)
 * | initiatorIdentityKey[64] | responderIdentityKey[64] | ephemeralKey[64]
 * | signedPreKeyId:u32 | flag:u8 (0x00 absent, 0x01 present) | [oneTimePreKeyId:u32]
 * ```
 *
 * Integers are big-endian. Both sides of a session derive the same ID: the
 * initiator from its pending prekey data, the responder from the
 * [PreKeyMessage]. The header fields of a [PreKeyMessage] are only
 * authenticated once the responder accepted the session with them.
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
         * The ID of the initiation [message] belongs to, for the responder
         * whose public identity key is [responderIdentityKey].
         */
        fun of(message: PreKeyMessage, responderIdentityKey: ByteArray): SessionInitiationId = derive(
            initiatorIdentityKey = message.identityKey,
            responderIdentityKey = responderIdentityKey,
            ephemeralKey = message.ephemeralKey,
            signedPreKeyId = message.signedPreKeyId,
            oneTimePreKeyId = message.oneTimePreKeyId,
        )

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
