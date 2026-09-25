package dev.kreienbuehl.ksecuremessage.protocol

import dev.kreienbuehl.ksecuremessage.model.LogicalMessageId

/**
 * Content of one decrypted KSecureMessage message: the reliability frame
 * that is the ratchet plaintext (docs/message-reliability.md). It is
 * encrypted, so the server never sees it.
 */
sealed interface SecurePayload {
    val id: LogicalMessageId

    /** An application message. [body] is the application's plaintext. */
    class ApplicationMessage(override val id: LogicalMessageId, val body: ByteArray) : SecurePayload

    /** Confirms that the sender of this frame accepted the application message [id]. */
    class Acknowledgement(override val id: LogicalMessageId) : SecurePayload
}

/**
 * Reliability frame format, version 1. Its output is the plaintext handed to
 * [ProtocolEngine.encrypt]; the ciphertext wire format
 * ([CiphertextMessageCodec]) is not affected. Full specification:
 * `docs/message-reliability.md`.
 *
 * ```
 * ApplicationMessage: version=0x01 | type=0x01 | messageId[16] | length:u32 | body
 * Acknowledgement:    version=0x01 | type=0x02 | messageId[16]
 * ```
 *
 * Integers are unsigned 32-bit big-endian. Every plaintext of a milestone 8
 * peer is such a frame; there is no fallback for raw plaintext. Decoding
 * treats input as untrusted: anything that is not exactly one well-formed
 * frame is rejected with a [ProtocolException]. Encoding is deterministic.
 */
object SecurePayloadCodec {
    const val VERSION: Int = 0x01
    const val TYPE_APPLICATION_MESSAGE: Int = 0x01
    const val TYPE_ACKNOWLEDGEMENT: Int = 0x02

    /**
     * Largest application body. The frame adds [APPLICATION_HEADER_SIZE]
     * bytes; the result, plus the ratchet overhead, stays below
     * [CiphertextMessageCodec.MAX_RATCHET_PAYLOAD_SIZE].
     */
    const val MAX_BODY_SIZE: Int = 192 * 1024

    const val APPLICATION_HEADER_SIZE: Int = 2 + LogicalMessageId.SIZE + 4

    /** Upper bound for a complete encoded frame. */
    const val MAX_ENCODED_SIZE: Int = APPLICATION_HEADER_SIZE + MAX_BODY_SIZE

    fun encode(payload: SecurePayload): ByteArray {
        val out = BinaryWriter()
        out.byte(VERSION.toByte())
        when (payload) {
            is SecurePayload.ApplicationMessage -> {
                if (payload.body.size > MAX_BODY_SIZE) {
                    throw ProtocolException.MessageTooLarge("Message body exceeds $MAX_BODY_SIZE bytes")
                }
                out.byte(TYPE_APPLICATION_MESSAGE.toByte())
                out.fixed(payload.id.toByteArray())
                out.bytes(payload.body)
            }
            is SecurePayload.Acknowledgement -> {
                out.byte(TYPE_ACKNOWLEDGEMENT.toByte())
                out.fixed(payload.id.toByteArray())
            }
        }
        return out.toByteArray()
    }

    fun decode(bytes: ByteArray): SecurePayload {
        if (bytes.size > MAX_ENCODED_SIZE) throw ProtocolException.MessageTooLarge("Payload exceeds $MAX_ENCODED_SIZE bytes")
        if (bytes.size < 2) throw ProtocolException.MalformedSecurePayload("Payload is truncated")
        val version = bytes[0].toInt() and 0xFF
        if (version != VERSION) throw ProtocolException.UnsupportedSecurePayloadVersion(version)
        val type = bytes[1].toInt() and 0xFF

        return try {
            val input = BinaryReader(bytes)
            input.fixed(2)
            val id = LogicalMessageId.fromByteArray(input.fixed(LogicalMessageId.SIZE))
            val payload = when (type) {
                TYPE_APPLICATION_MESSAGE -> {
                    // Read the length first so the limit is checked before any copy.
                    val size = input.int()
                    require(size in 0..MAX_BODY_SIZE) { "Invalid body length" }
                    SecurePayload.ApplicationMessage(id, input.fixed(size))
                }
                TYPE_ACKNOWLEDGEMENT -> SecurePayload.Acknowledgement(id)
                else -> throw ProtocolException.MalformedSecurePayload("Unknown payload type $type")
            }
            input.requireEnd()
            payload
        } catch (e: IllegalArgumentException) {
            throw ProtocolException.MalformedSecurePayload("Payload is malformed", e)
        }
    }
}
