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
     * address. Registration never replaces a registered key; only a device
     * recovery does (docs/device-recovery.md).
     */
    class DeviceRegistrationConflict : SecureMessageTransportException("Device is registered with a different authentication key")

    /** The server did not accept the request's device authentication; the request changed nothing. */
    class AuthenticationFailed(val failure: AuthenticationFailure) :
        SecureMessageTransportException("Device authentication failed: $failure")

    /** The server rejected a device recovery (docs/device-recovery.md); nothing was changed. */
    class DeviceRecoveryRejected(val reason: RecoveryFailure) :
        SecureMessageTransportException("Device recovery rejected: $reason")

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

    enum class RecoveryFailure {
        /** The request was malformed. */
        INVALID_REQUEST,

        /** The device named itself as authorizer. */
        SELF_AUTHORIZATION,

        /** The authorizing device belongs to another user. */
        CROSS_USER,

        /** The authorizing device is not registered. */
        AUTHORIZER_NOT_REGISTERED,

        /** The device to recover is not registered: use first registration. */
        TARGET_NOT_REGISTERED,

        /** The request time is outside the server's validity window. */
        EXPIRED,

        /** The authorizer's signature or the proof of possession does not verify. */
        INVALID_PROOF,

        /** The request's nonce was used before. */
        REPLAY,

        /** The registration changed since the request was made (another recovery won), or the key is already registered. */
        CONFLICT,
    }
}
