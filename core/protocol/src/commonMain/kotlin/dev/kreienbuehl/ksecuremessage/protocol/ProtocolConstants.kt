package dev.kreienbuehl.ksecuremessage.protocol

/**
 * KSecureMessage protocol compatibility constants.
 *
 * The info strings are the HKDF domain separation labels passed to Kodium's
 * X3DH and Double Ratchet. Every existing session and every message on the
 * wire depends on them: changing a value makes all existing sessions
 * undecryptable. Introduce a new protocol version instead.
 */
internal object ProtocolConstants {
    /** HKDF info for X3DH key agreement. */
    const val X3DH_INFO = "KSecureMessage-X3DH-v1"

    /** HKDF info for the Double Ratchet root and chain KDFs. */
    const val RATCHET_INFO = "KSecureMessage-Ratchet-v1"

    /**
     * Domain separator of [SessionInitiationId]. Persisted IDs and the
     * simultaneous-initiation decision depend on it.
     */
    const val SESSION_INITIATION_DOMAIN = "KSecureMessage-SessionInitiation-v1"

    /**
     * Domain separator of the session initiation v2 transcript (S1): the
     * associated data of every v2 session and the input of its
     * [SessionInitiationId]. Never shared with v1.
     */
    const val SESSION_INITIATION_V2_DOMAIN = "KSecureMessage-SessionInitiation-v2"

    /**
     * Domain separator of the server request signature input
     * ([ServerRequestAuthentication]). Registered devices and every signed
     * request depend on it.
     */
    const val SERVER_AUTH_DOMAIN = "KSecureMessage-ServerAuth-v1"

    /**
     * Domain separator of the device recovery authorization signed by
     * another device of the same user ([DeviceRecovery]).
     */
    const val DEVICE_RECOVERY_DOMAIN = "KSecureMessage-DeviceRecovery-v1"

    /**
     * Domain separator of the proof of possession signed with the
     * replacement key of a device recovery ([DeviceRecovery]).
     */
    const val DEVICE_RECOVERY_POP_DOMAIN = "KSecureMessage-DeviceRecovery-PoP-v1"

    /** Domain separator of [DeviceRecoveryId]. Recorded by the server for idempotent retries. */
    const val DEVICE_RECOVERY_ID_DOMAIN = "KSecureMessage-DeviceRecoveryId-v1"

    /**
     * Domain separator of a routine device authentication key rotation,
     * signed by the device's current key ([DeviceAuthenticationRotation]).
     */
    const val DEVICE_AUTH_ROTATION_DOMAIN = "KSecureMessage-DeviceAuthRotation-v1"

    /**
     * Domain separator of the proof of possession signed with the
     * replacement key of a routine rotation ([DeviceAuthenticationRotation]).
     */
    const val DEVICE_AUTH_ROTATION_POP_DOMAIN = "KSecureMessage-DeviceAuthRotation-PoP-v1"

    /** Domain separator of [DeviceAuthenticationRotationId]. Recorded by the server for idempotent retries. */
    const val DEVICE_AUTH_ROTATION_ID_DOMAIN = "KSecureMessage-DeviceAuthRotationId-v1"

    /**
     * Domain separator of a last-device recovery authorization, signed by the
     * user's offline recovery key ([LastDeviceRecovery]).
     */
    const val LAST_DEVICE_RECOVERY_DOMAIN = "KSecureMessage-LastDeviceRecovery-v1"

    /**
     * Domain separator of the proof of possession signed with the
     * replacement key of a last-device recovery ([LastDeviceRecovery]).
     */
    const val LAST_DEVICE_RECOVERY_POP_DOMAIN = "KSecureMessage-LastDeviceRecovery-PoP-v1"

    /** Domain separator of [LastDeviceRecoveryId]. Recorded by the server for idempotent retries. */
    const val LAST_DEVICE_RECOVERY_ID_DOMAIN = "KSecureMessage-LastDeviceRecoveryId-v1"

    /**
     * Domain separator of the proof of possession a recovery key gives when
     * it is registered ([LastDeviceRecovery.registerKey]).
     */
    const val LAST_DEVICE_RECOVERY_KEY_POP_DOMAIN = "KSecureMessage-LastDeviceRecoveryKey-PoP-v1"

    /**
     * Domain separator of a recovery key rotation authorization, signed by
     * the current offline recovery key ([RecoveryKeyRotation]).
     */
    const val RECOVERY_KEY_ROTATION_DOMAIN = "KSecureMessage-RecoveryKeyRotation-v1"

    /**
     * Domain separator of the proof of possession signed with the new
     * offline recovery key of a rotation ([RecoveryKeyRotation]).
     */
    const val RECOVERY_KEY_ROTATION_NEW_KEY_POP_DOMAIN = "KSecureMessage-RecoveryKeyRotation-NewKeyPoP-v1"

    /** Domain separator of [RecoveryKeyRotationId]. Recorded by the server for idempotent retries. */
    const val RECOVERY_KEY_ROTATION_ID_DOMAIN = "KSecureMessage-RecoveryKeyRotationId-v1"

    /**
     * Domain separator of a recovery key revocation, signed by the current
     * offline recovery key ([RecoveryKeyRevocation]).
     */
    const val RECOVERY_KEY_REVOCATION_DOMAIN = "KSecureMessage-RecoveryKeyRevocation-v1"

    /** Domain separator of [RecoveryKeyRevocationId]. Recorded by the server for idempotent retries. */
    const val RECOVERY_KEY_REVOCATION_ID_DOMAIN = "KSecureMessage-RecoveryKeyRevocationId-v1"

    /**
     * Domain separator of the proof of possession signed with the new
     * offline recovery key that completes a delayed recovery key reset
     * ([RecoveryKeyReset]).
     */
    const val RECOVERY_KEY_RESET_NEW_KEY_POP_DOMAIN = "KSecureMessage-RecoveryKeyReset-NewKeyPoP-v1"

    /** Domain separator of [RecoveryKeyResetCompletionId]. Recorded by the server for idempotent retries. */
    const val RECOVERY_KEY_RESET_ID_DOMAIN = "KSecureMessage-RecoveryKeyResetId-v1"

    /**
     * Domain separator of the cancellation of a pending recovery key reset,
     * signed by the current offline recovery key ([RecoveryKeyReset]).
     */
    const val RECOVERY_KEY_RESET_CANCEL_DOMAIN = "KSecureMessage-RecoveryKeyReset-Cancel-v1"

    /**
     * Domain separator of a recovery key reset status query, signed by the
     * current offline recovery key ([RecoveryKeyReset]).
     */
    const val RECOVERY_KEY_RESET_STATUS_QUERY_DOMAIN = "KSecureMessage-RecoveryKeyResetStatusQuery-v1"

    /**
     * Domain separator of the safety number fingerprint ([SafetyNumber]).
     * Every safety number users compared and every verification payload
     * depend on it.
     */
    const val SAFETY_NUMBER_DOMAIN = "KSecureMessage-SafetyNumber-v1"

    /**
     * Domain separator of [ApplicationMessageDigest], the content commitment
     * kept with a committed inbound message. Local storage only, never sent;
     * stored digests depend on it.
     */
    const val PROCESSED_MESSAGE_DOMAIN = "KSecureMessage-ProcessedMessage-v1"

    /** Size of an encoded public key: X25519 key followed by Ed25519 key. */
    const val PUBLIC_KEY_SIZE = 64
}
