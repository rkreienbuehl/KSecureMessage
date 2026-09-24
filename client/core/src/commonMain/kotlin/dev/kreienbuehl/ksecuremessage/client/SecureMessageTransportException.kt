package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress

/** Server rejections reported by a [SecureMessageTransport]. Messages never contain key material. */
sealed class SecureMessageTransportException(message: String) : Exception(message) {
    /** The server has no published prekeys for [address]. */
    class DeviceNotFound(val address: DeviceAddress) :
        SecureMessageTransportException("No prekeys published for the device")

    /** The server rejected a prekey publication and stored nothing from it. */
    class PublicationRejected(val reason: Reason) :
        SecureMessageTransportException("Prekey publication rejected: $reason")

    /** Any other unexpected server response. */
    class UnexpectedResponse(val status: Int) :
        SecureMessageTransportException("Unexpected server response $status")

    enum class Reason {
        /** The request was malformed: key sizes, repeated IDs, too many keys. */
        INVALID_PUBLICATION,

        /** The server holds a different identity key for this device. */
        IDENTITY_KEY_CONFLICT,

        /** The signed prekey ID is known with other bytes, or older than the server's current one. */
        SIGNED_PRE_KEY_CONFLICT,

        /** A one-time prekey ID is known with a different public key. */
        ONE_TIME_PRE_KEY_CONFLICT,
    }
}
