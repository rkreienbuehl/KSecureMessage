package dev.kreienbuehl.ksecuremessage.protocol

/**
 * Failures raised by a [ProtocolEngine]. Messages never contain key material.
 * The underlying cause is kept for debugging.
 */
sealed class ProtocolException(
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause) {
    class InvalidPreKeyBundle(message: String, cause: Throwable? = null) : ProtocolException(message, cause)

    class InvalidSignature(message: String) : ProtocolException(message)

    class InvalidMessage(message: String, cause: Throwable? = null) : ProtocolException(message, cause)

    class DecryptionFailed(message: String, cause: Throwable? = null) : ProtocolException(message, cause)

    class InvalidSessionState(message: String, cause: Throwable? = null) : ProtocolException(message, cause)

    // Wire format errors raised by CiphertextMessageCodec.

    /** The encoded message uses a wire version this implementation does not support. */
    class UnsupportedWireVersion(val version: Int) : ProtocolException("Unsupported wire version $version")

    /** The encoded message has an unknown message type byte. */
    class UnknownMessageType(val type: Int) : ProtocolException("Unknown message type $type")

    /** The encoded message is truncated, has trailing bytes or an invalid field. */
    class MalformedMessage(message: String, cause: Throwable? = null) : ProtocolException(message, cause)

    /** The message or one of its fields exceeds a wire format size limit. */
    class MessageTooLarge(message: String) : ProtocolException(message)

    // Reliability frame errors raised by SecurePayloadCodec.

    /** The decrypted payload uses a reliability-frame version this implementation does not support. */
    class UnsupportedSecurePayloadVersion(val version: Int) :
        ProtocolException("Unsupported secure payload version $version")

    /**
     * The decrypted payload is not a well-formed reliability frame: truncated,
     * trailing bytes, unknown type or an invalid field. Also raised for
     * plaintext from a peer that does not use the frame (before milestone 8).
     */
    class MalformedSecurePayload(message: String, cause: Throwable? = null) : ProtocolException(message, cause)
}
