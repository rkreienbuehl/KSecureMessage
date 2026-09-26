package dev.kreienbuehl.ksecuremessage.client

import kotlin.time.Duration
import kotlin.time.Instant

/**
 * An application's policy for routine device authentication key rotation
 * (docs/device-authentication-rotation.md): rotate once the registered key is
 * at least [maxKeyAge] old. The library has no default policy and never
 * applies one on its own; the application passes it to
 * [SecureMessageClient.evaluateDeviceAuthenticationRotation] or
 * [SecureMessageClient.rotateDeviceAuthenticationKeyIfNeeded] when it chooses.
 *
 * [maxKeyAge] must be positive. [Duration.INFINITE] disables age-based
 * rotation: no key is ever due.
 */
class DeviceAuthenticationRotationPolicy(val maxKeyAge: Duration) {
    init {
        require(maxKeyAge > Duration.ZERO) { "Maximum key age must be positive" }
    }

    /** Whether a key of [age] is due: `age >= maxKeyAge`. */
    fun isDue(age: Duration): Boolean = age >= maxKeyAge

    override fun equals(other: Any?): Boolean = other is DeviceAuthenticationRotationPolicy && maxKeyAge == other.maxKeyAge

    override fun hashCode(): Int = maxKeyAge.hashCode()

    override fun toString(): String = "DeviceAuthenticationRotationPolicy(maxKeyAge=$maxKeyAge)"
}

/**
 * This device's server authentication state, for display, logging and
 * policy decisions. Contains no key material.
 *
 * [authEpoch] and [authKeyInstalledAt] come from the server's registration
 * (the signed `GET …/registration`): the server time the registered key was
 * installed at by first registration, recovery or rotation. [age] is
 * [evaluatedAt] (the client's clock) minus [authKeyInstalledAt], never
 * negative: a client clock behind the server time gives age zero.
 * [pendingRotation] and [pendingRecovery] tell whether a routine rotation or
 * a device recovery key is waiting locally.
 */
data class DeviceAuthenticationRotationStatus(
    val authEpoch: Long,
    val authKeyInstalledAt: Instant,
    val evaluatedAt: Instant,
    val pendingRotation: Boolean,
    val pendingRecovery: Boolean,
) {
    val age: Duration get() = keyAge(authKeyInstalledAt, evaluatedAt)
}

/** `now - installedAt`, clamped to zero when the clock is behind the installation time. */
internal fun keyAge(installedAt: Instant, now: Instant): Duration = (now - installedAt).coerceAtLeast(Duration.ZERO)

/** Result of [SecureMessageClient.evaluateDeviceAuthenticationRotation]. Evaluation never rotates. */
sealed interface DeviceAuthenticationRotationDecision {
    /** The registered key is younger than the policy's maximum age. */
    data class NotNeeded(val status: DeviceAuthenticationRotationStatus) : DeviceAuthenticationRotationDecision

    /** The registered key reached the policy's maximum age. */
    data class Due(val status: DeviceAuthenticationRotationStatus) : DeviceAuthenticationRotationDecision

    /**
     * A routine rotation was started and not completed: complete or resolve
     * it ([SecureMessageClient.rotateDeviceAuthenticationKeyIfNeeded] does)
     * before a new one can start. The server was not asked.
     */
    data object RotationPending : DeviceAuthenticationRotationDecision

    /** A device recovery is pending; no routine rotation starts until it is completed or cancelled. The server was not asked. */
    data object RecoveryPending : DeviceAuthenticationRotationDecision
}

/** Result of [SecureMessageClient.rotateDeviceAuthenticationKeyIfNeeded]. */
sealed interface DeviceAuthenticationRotationResult {
    /** The registered key is younger than the policy's maximum age; nothing changed. */
    data class NotNeeded(val status: DeviceAuthenticationRotationStatus) : DeviceAuthenticationRotationResult

    /** The key was due and has been rotated. [previous] is the status of the replaced key. */
    data class Rotated(val previous: DeviceAuthenticationRotationStatus) : DeviceAuthenticationRotationResult

    /**
     * A pending routine rotation existed; it was completed (or found already
     * applied by the server) with its existing key instead of starting a new
     * one. The policy was not evaluated.
     */
    data object ResumedPendingRotation : DeviceAuthenticationRotationResult

    /** A device recovery is pending; nothing was started or sent. */
    data object RecoveryInProgress : DeviceAuthenticationRotationResult
}
