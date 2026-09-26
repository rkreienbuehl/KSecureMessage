package dev.kreienbuehl.ksecuremessage.server

import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecovery
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecoveryAuthorization
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationRepository
import dev.kreienbuehl.ksecuremessage.storage.RecoveryReplacement
import dev.kreienbuehl.ksecuremessage.storage.RecoveryReplacementResult
import kotlin.time.Clock
import kotlin.time.Instant

/** A rejected device recovery. Nothing was changed. Messages never contain key material. */
sealed class DeviceRecoveryException(message: String) : Exception(message) {
    /** The request is malformed. */
    class InvalidRecovery(message: String) : DeviceRecoveryException(message)

    /** The target device named itself as authorizer. */
    class SelfAuthorization : DeviceRecoveryException("A device cannot authorize its own recovery")

    /** The authorizer belongs to another user than the target. */
    class CrossUser : DeviceRecoveryException("The authorizing device belongs to another user")

    /** The authorizing device has no registered key. */
    class AuthorizerNotRegistered : DeviceRecoveryException("The authorizing device is not registered")

    /** The target device has no registered key: use first registration. */
    class TargetNotRegistered : DeviceRecoveryException("The device to recover is not registered")

    /** The timestamp is outside the validity window. */
    class Expired : DeviceRecoveryException("Recovery timestamp is outside the validity window")

    /** The authorizer's signature or the proof of possession does not verify. */
    class InvalidProof : DeviceRecoveryException("Recovery proof is invalid")

    /** The nonce was used before. */
    class Replay : DeviceRecoveryException("Recovery nonce was already used")

    /**
     * The target's or the authorizer's registration changed since the proofs
     * were checked (another recovery won), or the replacement key is already
     * the target's key from another recovery.
     */
    class Conflict : DeviceRecoveryException("Device registration changed, recovery not applied")

    /** The target's authentication epoch cannot grow any more. */
    class EpochExhausted : DeviceRecoveryException("Authentication epoch is exhausted")
}

/** A successful device recovery. */
enum class DeviceRecoveryOutcome {
    /** The target's key was replaced. */
    REPLACED,

    /** The same recovery had replaced the key before (a retry); nothing changed. */
    ALREADY_APPLIED,
}

/**
 * Verifies and applies device recoveries (docs/device-recovery.md): another
 * registered device of the same user authorizes a replacement device
 * authentication key for a registered target device.
 *
 * Checks, in this order, before anything is changed: key and signature
 * sizes; the authorizer is not the target and has the same [dev.kreienbuehl.ksecuremessage.model.UserId];
 * the authorizer and the target are registered; the timestamp is within
 * [DeviceRecovery.VALIDITY_WINDOW] of [clock]'s time, bounds included; the
 * authorizer's signature verifies with its **registered** key; the proof of
 * possession verifies with the replacement key. Then
 * [DeviceRegistrationRepository.replaceForRecovery] claims the nonce and
 * replaces the key in one atomic step, only if both registrations are still
 * the verified ones.
 */
internal class DeviceRecoveryService(
    private val devices: DeviceRegistrationRepository,
    private val clock: Clock,
) {
    suspend fun recover(authorization: DeviceRecoveryAuthorization): DeviceRecoveryOutcome {
        val request = authorization.request
        // The request types enforce the sizes; checked again because they are the trust boundary.
        if (request.replacementPublicKey.size != DeviceRecovery.PUBLIC_KEY_SIZE ||
            request.proofOfPossession.size != DeviceRecovery.SIGNATURE_SIZE ||
            authorization.authorizerSignature.size != DeviceRecovery.SIGNATURE_SIZE
        ) {
            throw DeviceRecoveryException.InvalidRecovery("Recovery key or signature has an invalid size")
        }
        if (request.authorizer == request.target) throw DeviceRecoveryException.SelfAuthorization()
        if (request.authorizer.userId != request.target.userId) throw DeviceRecoveryException.CrossUser()

        val authorizer = devices.registrationState(request.authorizer) ?: throw DeviceRecoveryException.AuthorizerNotRegistered()
        val target = devices.registrationState(request.target) ?: throw DeviceRecoveryException.TargetNotRegistered()

        val now = Instant.fromEpochMilliseconds(clock.now().toEpochMilliseconds())
        val window = DeviceRecovery.VALIDITY_WINDOW
        if (request.timestamp < now - window || request.timestamp > now + window) throw DeviceRecoveryException.Expired()

        // Always the authorizer's registered key; never one the request supplies.
        if (!DeviceRecovery.verifyAuthorization(authorizer.registration.publicKey, authorization)) {
            throw DeviceRecoveryException.InvalidProof()
        }
        if (!DeviceRecovery.verifyProofOfPossession(request)) throw DeviceRecoveryException.InvalidProof()

        val result = devices.replaceForRecovery(
            RecoveryReplacement(
                expectedTarget = target,
                expectedAuthorizer = authorizer,
                replacementPublicKey = request.replacementPublicKey,
                recoveryId = DeviceRecovery.recoveryId(request),
                nonce = request.nonce,
                timestamp = request.timestamp,
                pruneBefore = now - window,
                // The server's time, never the request's: the recovered key's age starts here.
                installedAt = now,
            ),
        )
        return when (result) {
            RecoveryReplacementResult.REPLACED -> DeviceRecoveryOutcome.REPLACED
            RecoveryReplacementResult.ALREADY_APPLIED -> DeviceRecoveryOutcome.ALREADY_APPLIED
            RecoveryReplacementResult.CONFLICT -> throw DeviceRecoveryException.Conflict()
            RecoveryReplacementResult.REPLAY -> throw DeviceRecoveryException.Replay()
            RecoveryReplacementResult.TARGET_NOT_REGISTERED -> throw DeviceRecoveryException.TargetNotRegistered()
            RecoveryReplacementResult.EPOCH_EXHAUSTED -> throw DeviceRecoveryException.EpochExhausted()
        }
    }
}
