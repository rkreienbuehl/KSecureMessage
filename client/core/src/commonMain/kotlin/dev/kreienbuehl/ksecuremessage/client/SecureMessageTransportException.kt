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

    /** The server rejected a device registration as malformed. Nothing was registered. */
    class RegistrationRejected : SecureMessageTransportException("Device registration rejected")

    /**
     * The server holds a different device authentication key for this
     * address. It never replaces a registered key; there is no reset yet.
     */
    class DeviceRegistrationConflict : SecureMessageTransportException("Device is registered with a different authentication key")

    /** The server did not accept the request's device authentication; the request changed nothing. */
    class AuthenticationFailed(val failure: AuthenticationFailure) :
        SecureMessageTransportException("Device authentication failed: $failure")

    /** Any other unexpected server response. */
    class UnexpectedResponse(val status: Int) :
        SecureMessageTransportException("Unexpected server response $status")

    enum class AuthenticationFailure {
        /** The request carried no authentication. */
        MISSING,

        /** Malformed authentication, or the signature does not verify with the registered key. */
        INVALID,

        /** The timestamp is outside the server's validity window: check the device clock. */
        EXPIRED,

        /** The nonce was used before. */
        REPLAY,

        /** The device has not registered its authentication key. Call `SecureMessageClient.registerDevice`. */
        NOT_REGISTERED,
    }

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
