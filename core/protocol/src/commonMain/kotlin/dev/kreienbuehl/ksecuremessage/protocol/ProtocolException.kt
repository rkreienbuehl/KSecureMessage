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
}
