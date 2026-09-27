package dev.kreienbuehl.ksecuremessage.client

/**
 * The state of this device's server authentication credentials, as
 * classified by [SecureMessageClient.deviceAuthenticationHealth]
 * (docs/device-authentication-health.md). A read-only composition of the
 * local device authentication key slots and, only when they do not decide,
 * the signed registration status: factual states only, no severity and no
 * recommendation. The application decides what to show and what to do.
 *
 * Not an atomic snapshot: the state can change right after it was read.
 * Carries no key material.
 */
sealed interface DeviceAuthenticationHealth {
    /**
     * The active key is present, the server has a registration for this
     * device and no transition is pending locally. With a [policy], the key
     * is younger than [DeviceAuthenticationRotationPolicy.maxKeyAge]; without
     * one (`null`), the age was not evaluated against anything.
     *
     * The registration status does not name the registered key, so this does
     * not prove that the server's key is the local active key; the signed read
     * succeeding with it is the only evidence. [DeviceAuthenticationRotationStatus.pendingRotation]
     * and [DeviceAuthenticationRotationStatus.pendingRecovery] are always `false` here.
     */
    data class Healthy(
        val status: DeviceAuthenticationRotationStatus,
        val policy: DeviceAuthenticationRotationPolicy?,
    ) : DeviceAuthenticationHealth

    /**
     * As [Healthy], but the registered key reached [policy]'s maximum age
     * ([DeviceAuthenticationRotationStatus.age] >= [DeviceAuthenticationRotationPolicy.maxKeyAge])
     * by the client clock. Nothing was rotated.
     */
    data class RotationDue(
        val status: DeviceAuthenticationRotationStatus,
        val policy: DeviceAuthenticationRotationPolicy,
    ) : DeviceAuthenticationHealth

    /**
     * A routine rotation key is pending locally and the active key is
     * present. The server was not asked; nothing was completed or resolved.
     */
    data object RotationPending : DeviceAuthenticationHealth

    /**
     * A replacement key of a device recovery or a last-device recovery
     * ([kind]) is pending locally, whether the active key is present or not.
     * The server was not asked; nothing was completed or resolved.
     */
    data class RecoveryPending(val kind: DeviceAuthenticationRecoveryKind) : DeviceAuthenticationHealth

    /**
     * The local identity exists, but the active device authentication key
     * is missing and no transition is pending. It is never recreated: the
     * device needs a recovery (docs/device-recovery.md,
     * docs/last-device-recovery.md). The server was not asked.
     */
    data object ActiveKeyMissing : DeviceAuthenticationHealth

    /** The active key is present, but the server has no registration for this device. Nothing was registered. */
    data object Unregistered : DeviceAuthenticationHealth

    /** The local key slots contradict each other; impossible while the storage keeps its invariants. */
    data class Inconsistent(val reason: DeviceAuthenticationHealthInconsistency) : DeviceAuthenticationHealth
}

/** Which recovery [DeviceAuthenticationHealth.RecoveryPending] reports. */
enum class DeviceAuthenticationRecoveryKind {
    /** A device recovery authorized by another device of the user (docs/device-recovery.md). */
    DEVICE_RECOVERY,

    /** A last-device recovery with the offline recovery key (docs/last-device-recovery.md). */
    LAST_DEVICE_RECOVERY,
}

/** Why [DeviceAuthenticationHealth.Inconsistent] was returned. Carries no key material. */
enum class DeviceAuthenticationHealthInconsistency {
    /** More than one of the pending recovery, rotation and last-device recovery keys is stored. */
    MULTIPLE_PENDING_TRANSITIONS,

    /** A routine rotation key is pending, but the active key it replaces is missing. */
    ROTATION_PENDING_WITHOUT_ACTIVE_KEY,
}
