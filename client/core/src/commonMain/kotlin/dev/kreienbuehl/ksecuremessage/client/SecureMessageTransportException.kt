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
     * recovery (docs/device-recovery.md) or a routine rotation
     * (docs/device-authentication-rotation.md) does.
     */
    class DeviceRegistrationConflict : SecureMessageTransportException("Device is registered with a different authentication key")

    /** The server did not accept the request's device authentication; the request changed nothing. */
    class AuthenticationFailed(val failure: AuthenticationFailure) :
        SecureMessageTransportException("Device authentication failed: $failure")

    /** The server rejected a device recovery (docs/device-recovery.md); nothing was changed. */
    class DeviceRecoveryRejected(val reason: RecoveryFailure) :
        SecureMessageTransportException("Device recovery rejected: $reason")

    /**
     * The server rejected a routine device authentication key rotation
     * (docs/device-authentication-rotation.md); nothing was changed.
     */
    class DeviceAuthenticationRotationRejected(val reason: RotationFailure) :
        SecureMessageTransportException("Device authentication rotation rejected: $reason")

    /** The server refused the last-device recovery key registration (docs/last-device-recovery.md). */
    class LastDeviceRecoveryKeyRejected(val reason: RecoveryKeyFailure) :
        SecureMessageTransportException("Last-device recovery key rejected: $reason")

    /** The server refused a last-device recovery challenge or recovery (docs/last-device-recovery.md). */
    class LastDeviceRecoveryRejected(val reason: LastDeviceRecoveryFailure) :
        SecureMessageTransportException("Last-device recovery rejected: $reason")

    /** The server refused a recovery key rotation (docs/recovery-key-lifecycle.md); nothing was changed. */
    class RecoveryKeyRotationRejected(val reason: RecoveryKeyTransitionFailure) :
        SecureMessageTransportException("Recovery key rotation rejected: $reason")

    /** The server refused a recovery key revocation (docs/recovery-key-lifecycle.md); nothing was changed. */
    class RecoveryKeyRevocationRejected(val reason: RecoveryKeyTransitionFailure) :
        SecureMessageTransportException("Recovery key revocation rejected: $reason")

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

        /** The target's authentication epoch cannot grow any more. */
        EPOCH_EXHAUSTED,
    }

    enum class RotationFailure {
        /** The request was malformed, or did not change the key. */
        INVALID_REQUEST,

        /** The device is not registered: use first registration. */
        NOT_REGISTERED,

        /** The statement time is outside the server's validity window. */
        EXPIRED,

        /** The current key's authorization or the replacement key's proof of possession does not verify. */
        INVALID_PROOF,

        /** The statement's nonce was used before. */
        REPLAY,

        /**
         * The registered key or epoch is not the one the statement names: an
         * earlier attempt, another rotation or a recovery changed it.
         */
        CONFLICT,

        /** The authentication epoch cannot grow any more. */
        EPOCH_EXHAUSTED,
    }

    enum class RecoveryKeyFailure {
        /** The registration was malformed, or its proof of possession does not verify. */
        INVALID,

        /** The user has a different active recovery key. Only a rotation replaces it (docs/recovery-key-lifecycle.md). */
        CONFLICT,

        /** The recovery key epoch cannot grow any more (after a revocation at the maximum epoch). */
        EPOCH_EXHAUSTED,
    }

    /** Why the server refused a recovery key rotation or revocation (docs/recovery-key-lifecycle.md). */
    enum class RecoveryKeyTransitionFailure {
        /** The request was malformed, named another authorizing device, or rotated to the same key. */
        INVALID_REQUEST,

        /** The user has no active recovery key (never registered, or revoked). */
        NOT_CONFIGURED,

        /** The statement time is outside the server's validity window. */
        EXPIRED,

        /** The current recovery key's signature or the new key's proof of possession does not verify. */
        INVALID_PROOF,

        /** The statement's nonce was used before. */
        REPLAY,

        /**
         * The active recovery key or epoch is not the one the statement names
         * (another transition won, or a stale statement), or this device's
         * registration changed meanwhile.
         */
        CONFLICT,

        /** The recovery key epoch cannot grow any more. */
        EPOCH_EXHAUSTED,
    }

    enum class LastDeviceRecoveryFailure {
        /** The request was malformed or named another device. */
        INVALID_REQUEST,

        /** The user has no registered last-device recovery key. */
        NOT_CONFIGURED,

        /** The device to recover is not registered: use first registration. */
        TARGET_NOT_REGISTERED,

        /** The challenge is unknown, consumed or replaced: request a new one. */
        CHALLENGE_INVALID,

        /** The challenge expired: request a new one. */
        EXPIRED,

        /** The recovery key's signature or the proof of possession does not verify, or it is not the user's recovery key. */
        INVALID_PROOF,

        /** The registration changed since the challenge was issued, or the key is already registered. */
        CONFLICT,

        /** The authentication epoch cannot grow any more. */
        EPOCH_EXHAUSTED,
    }
}
