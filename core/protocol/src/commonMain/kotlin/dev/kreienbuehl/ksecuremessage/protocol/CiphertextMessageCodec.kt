package dev.kreienbuehl.ksecuremessage.protocol

import dev.kreienbuehl.ksecuremessage.model.CiphertextMessage
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyMessage
import dev.kreienbuehl.ksecuremessage.model.RatchetMessage
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId

/**
 * KSecureMessage ciphertext wire format, version 1. The output goes into
 * `EncryptedEnvelope.payload`. Framing only: no cryptography happens here and
 * the ratchet bytes are carried unchanged. Full specification:
 * `docs/wire-format.md`.
 *
 * ```
 * RatchetMessage: version=0x01 | type=0x01 | length:u32 | ratchet bytes
 * PreKeyMessage:  version=0x01 | type=0x02 | signedPreKeyId:u32
 *                 | flag:u8 (0x00 absent, 0x01 present) | [oneTimePreKeyId:u32]
 *                 | identityKey[64] | ephemeralKey[64] | length:u32 | ratchet bytes
 * ```
 *
 * Integers are unsigned 32-bit big-endian. Prekey IDs must have the high bit
 * clear. Decoding treats input as untrusted: anything that is not exactly one
 * well-formed message is rejected with a [ProtocolException], never partially
 * accepted. Encoding is deterministic.
 */
object CiphertextMessageCodec {
    const val WIRE_VERSION: Int = 0x01
    const val TYPE_RATCHET_MESSAGE: Int = 0x01
    const val TYPE_PREKEY_MESSAGE: Int = 0x02

    /** Upper bound for the opaque ratchet bytes (Kodium header plus ciphertext). */
    const val MAX_RATCHET_PAYLOAD_SIZE: Int = 256 * 1024

    /** Size of the largest header (a [PreKeyMessage] with one-time prekey). */
    private const val MAX_HEADER_SIZE = 2 + 4 + 1 + 4 + 2 * ProtocolConstants.PUBLIC_KEY_SIZE + 4

    /** Upper bound for a complete encoded message. */
    const val MAX_ENCODED_SIZE: Int = MAX_RATCHET_PAYLOAD_SIZE + MAX_HEADER_SIZE

    private const val FLAG_ABSENT: Byte = 0x00
    private const val FLAG_PRESENT: Byte = 0x01

    fun encode(message: CiphertextMessage): ByteArray {
        val out = BinaryWriter()
        out.byte(WIRE_VERSION.toByte())
        when (message) {
            is RatchetMessage -> {
                out.byte(TYPE_RATCHET_MESSAGE.toByte())
                out.ratchet(message)
            }
            is PreKeyMessage -> {
                out.byte(TYPE_PREKEY_MESSAGE.toByte())
                out.id(message.signedPreKeyId.value)
                val oneTimePreKeyId = message.oneTimePreKeyId
                if (oneTimePreKeyId == null) {
                    out.byte(FLAG_ABSENT)
                } else {
                    out.byte(FLAG_PRESENT)
                    out.id(oneTimePreKeyId.value)
                }
                out.key(message.identityKey)
                out.key(message.ephemeralKey)
                out.ratchet(message.message)
            }
        }
        return out.toByteArray()
    }

    fun decode(bytes: ByteArray): CiphertextMessage {
        if (bytes.size > MAX_ENCODED_SIZE) throw ProtocolException.MessageTooLarge("Encoded message exceeds $MAX_ENCODED_SIZE bytes")
        if (bytes.size < 2) throw ProtocolException.MalformedMessage("Encoded message is truncated")
        val version = bytes[0].toInt() and 0xFF
        if (version != WIRE_VERSION) throw ProtocolException.UnsupportedWireVersion(version)
        val type = bytes[1].toInt() and 0xFF
        if (type != TYPE_RATCHET_MESSAGE && type != TYPE_PREKEY_MESSAGE) throw ProtocolException.UnknownMessageType(type)

        return try {
            val input = BinaryReader(bytes)
            input.fixed(2)
            val message = if (type == TYPE_RATCHET_MESSAGE) input.ratchet() else input.preKeyMessage()
            input.requireEnd()
            message
        } catch (e: IllegalArgumentException) {
            throw ProtocolException.MalformedMessage("Encoded message is malformed", e)
        }
    }

    private fun BinaryReader.preKeyMessage(): PreKeyMessage {
        val signedPreKeyId = SignedPreKeyId(id())
        val oneTimePreKeyId = when (byte()) {
            FLAG_ABSENT -> null
            FLAG_PRESENT -> OneTimePreKeyId(id())
            else -> throw IllegalArgumentException("Invalid one-time prekey flag")
        }
        return PreKeyMessage(
            identityKey = fixed(ProtocolConstants.PUBLIC_KEY_SIZE),
            ephemeralKey = fixed(ProtocolConstants.PUBLIC_KEY_SIZE),
            signedPreKeyId = signedPreKeyId,
            oneTimePreKeyId = oneTimePreKeyId,
            message = ratchet(),
        )
    }

    private fun BinaryReader.id(): Int {
        val value = int()
        require(value >= 0) { "Prekey ID out of range" }
        return value
    }

    private fun BinaryReader.ratchet(): RatchetMessage {
        // Read the length first so the size limit is checked before any copy.
        val size = int()
        if (size < 0 || size > MAX_RATCHET_PAYLOAD_SIZE) {
            throw ProtocolException.MessageTooLarge("Ratchet payload exceeds $MAX_RATCHET_PAYLOAD_SIZE bytes")
        }
        require(size > 0) { "Empty ratchet payload" }
        return RatchetMessage(fixed(size))
    }

    private fun BinaryWriter.id(value: Int) {
        if (value < 0) throw ProtocolException.MalformedMessage("Prekey ID out of range")
        int(value)
    }

    private fun BinaryWriter.key(value: ByteArray) {
        if (value.size != ProtocolConstants.PUBLIC_KEY_SIZE) throw ProtocolException.MalformedMessage("Public key has an invalid size")
        fixed(value)
    }

    private fun BinaryWriter.ratchet(message: RatchetMessage) {
        if (message.bytes.size > MAX_RATCHET_PAYLOAD_SIZE) {
            throw ProtocolException.MessageTooLarge("Ratchet payload exceeds $MAX_RATCHET_PAYLOAD_SIZE bytes")
        }
        if (message.bytes.isEmpty()) throw ProtocolException.MalformedMessage("Empty ratchet payload")
        bytes(message.bytes)
    }
}
