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
     * Domain separator of the safety number fingerprint ([SafetyNumber]).
     * Every safety number users compared and every verification payload
     * depend on it.
     */
    const val SAFETY_NUMBER_DOMAIN = "KSecureMessage-SafetyNumber-v1"

    /** Size of an encoded public key: X25519 key followed by Ed25519 key. */
    const val PUBLIC_KEY_SIZE = 64
}
