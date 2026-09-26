package dev.kreienbuehl.ksecuremessage.client

/** A successful [SecureMessageClient.rotateLastDeviceRecoveryKey] (docs/recovery-key-lifecycle.md). */
enum class LastDeviceRecoveryKeyRotationResult {
    /** The server replaced the current recovery key with the new one (by this call, or by an identical earlier submission it recognized). */
    ROTATED,

    /**
     * The new key was already the active recovery key: an earlier call
     * rotated to it and its response was lost, or the application is
     * resuming after a restart. Nothing was sent.
     */
    ALREADY_ACTIVE,
}

/** A successful [SecureMessageClient.revokeLastDeviceRecoveryKey] (docs/recovery-key-lifecycle.md). */
enum class LastDeviceRecoveryKeyRevocationResult {
    /** The server revoked the recovery key. */
    REVOKED,

    /**
     * The user's recovery key was already revoked (for example by an earlier
     * call whose response was lost, or by another device). Nothing was sent.
     */
    ALREADY_REVOKED,
}
