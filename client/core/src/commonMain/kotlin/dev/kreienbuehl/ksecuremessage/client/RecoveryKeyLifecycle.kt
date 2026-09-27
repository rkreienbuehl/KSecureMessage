package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.LastDeviceRecoveryKeyStatus
import dev.kreienbuehl.ksecuremessage.model.RecoveryKeyResetStatus

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

/** A successful [SecureMessageClient.completeLastDeviceRecoveryKeyReset] (docs/recovery-key-reset.md). */
enum class LastDeviceRecoveryKeyResetResult {
    /** The server replaced the lost recovery key with the new one (by this call, or by an identical earlier submission). */
    COMPLETED,

    /**
     * The new key was already the active recovery key: an earlier call
     * completed the reset and its response was lost, or the application is
     * resuming after a restart. Nothing was sent.
     */
    ALREADY_ACTIVE,
}

/** The outcome of a recovery key reset cancellation (docs/recovery-key-reset.md). */
sealed interface LastDeviceRecoveryKeyResetCancellationResult {
    /** The reset was cancelled by this call. The recovery key and its epoch are unchanged. */
    data object Cancelled : LastDeviceRecoveryKeyResetCancellationResult

    /**
     * The reset was no longer pending: cancelled before (a lost response,
     * another device, the recovery key), completed, or removed by a rotation
     * or revocation. [recoveryKeyStatus] (the device path only; `null` for
     * the recovery key path) and [currentReset] (the reset pending now;
     * `null` if the recovery key path could no longer query it because the
     * key is not active any more) tell which. Nothing was recreated.
     */
    class NotPending(
        val recoveryKeyStatus: LastDeviceRecoveryKeyStatus?,
        val currentReset: RecoveryKeyResetStatus?,
    ) : LastDeviceRecoveryKeyResetCancellationResult {
        override fun toString(): String = "NotPending(recoveryKeyStatus=$recoveryKeyStatus, currentReset=$currentReset)"
    }
}
