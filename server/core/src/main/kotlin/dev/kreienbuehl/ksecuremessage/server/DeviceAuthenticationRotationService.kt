package dev.kreienbuehl.ksecuremessage.server

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationRotation
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationRotationAuthorization
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationRepository
import dev.kreienbuehl.ksecuremessage.storage.RotationReplacement
import dev.kreienbuehl.ksecuremessage.storage.RotationReplacementResult
import kotlin.time.Clock
import kotlin.time.Instant

/** A rejected routine rotation. Nothing was changed. Messages never contain key material. */
sealed class DeviceAuthenticationRotationException(message: String) : Exception(message) {
    /** The request is malformed, names another device than the route, or does not change the key. */
    class InvalidRotation(message: String) : DeviceAuthenticationRotationException(message)

    /** The device has no registered key: use first registration. */
    class NotRegistered : DeviceAuthenticationRotationException("The device is not registered")

    /** The timestamp is outside the validity window. */
    class Expired : DeviceAuthenticationRotationException("Rotation timestamp is outside the validity window")

    /** The current key's authorization or the replacement key's proof of possession does not verify. */
    class InvalidProof : DeviceAuthenticationRotationException("Rotation proof is invalid")

    /** The nonce was used before. */
    class Replay : DeviceAuthenticationRotationException("Rotation nonce was already used")

    /**
     * The registered key or epoch is not the one the statement names (another
     * rotation or a recovery won, or the statement is stale), or the
     * replacement key is already registered from another transition.
     */
    class Conflict : DeviceAuthenticationRotationException("Device registration changed, rotation not applied")

    /** The authentication epoch cannot grow any more. */
    class EpochExhausted : DeviceAuthenticationRotationException("Authentication epoch is exhausted")
}

/** A successful routine rotation. */
enum class DeviceAuthenticationRotationOutcome {
    /** The device's key was replaced. */
    ROTATED,

    /** The same rotation had replaced the key before (a retry); nothing changed. */
    ALREADY_APPLIED,
}

/**
 * Verifies and applies routine device authentication key rotations
 * (docs/device-authentication-rotation.md): a registered device replaces its
 * key K1 with K2, authorized by K1 and proven by K2. No other device takes
 * part; that is device recovery ([DeviceRecoveryService]), which this never
 * accepts. The rotation statement is the request's authentication: the
 * endpoint carries no ServerAuth headers.
 *
 * Checks, in this order, before anything is changed:
 *
 * 1. the statement names the route's device (sizes and a key change are
 *    enforced by the statement type);
 * 2. the device is registered;
 * 3. the timestamp is within [DeviceAuthenticationRotation.VALIDITY_WINDOW]
 *    of [clock]'s time, bounds included;
 * 4. exact retry: if the rotation with this statement's ID installed the
 *    registered key, and both proofs verify (the authorization with the
 *    statement's current key, which that ID binds; the proof of possession
 *    with the registered replacement key), the result is ALREADY_APPLIED
 *    without any write;
 * 5. the registered key is the statement's current key and the epoch its
 *    expected epoch;
 * 6. the authorization verifies with the **registered** key;
 * 7. the proof of possession verifies with the replacement key.
 *
 * Then [DeviceRegistrationRepository.replaceForRotation] claims the nonce and
 * replaces the key in one atomic compare-and-set on key and epoch.
 */
internal class DeviceAuthenticationRotationService(
    private val devices: DeviceRegistrationRepository,
    private val clock: Clock,
) {
    suspend fun rotate(address: DeviceAddress, authorization: DeviceAuthenticationRotationAuthorization): DeviceAuthenticationRotationOutcome {
        val statement = authorization.statement
        if (statement.address != address) throw DeviceAuthenticationRotationException.InvalidRotation("Rotation is for another device")

        val state = devices.registrationState(address) ?: throw DeviceAuthenticationRotationException.NotRegistered()

        val now = Instant.fromEpochMilliseconds(clock.now().toEpochMilliseconds())
        val window = DeviceAuthenticationRotation.VALIDITY_WINDOW
        if (statement.timestamp < now - window || statement.timestamp > now + window) {
            throw DeviceAuthenticationRotationException.Expired()
        }

        val rotationId = DeviceAuthenticationRotation.rotationId(statement)
        val registeredKey = state.registration.publicKey
        if (state.rotationId == rotationId && registeredKey.contentEquals(statement.replacementPublicKey)) {
            // A retry after a lost response. K1 is no longer registered, but the
            // stored ID binds exactly this statement, which names K1.
            if (!DeviceAuthenticationRotation.verifyAuthorization(statement.currentPublicKey, authorization) ||
                !DeviceAuthenticationRotation.verifyProofOfPossession(authorization)
            ) {
                throw DeviceAuthenticationRotationException.InvalidProof()
            }
            return DeviceAuthenticationRotationOutcome.ALREADY_APPLIED
        }

        if (!registeredKey.contentEquals(statement.currentPublicKey) || state.authEpoch != statement.expectedAuthEpoch) {
            throw DeviceAuthenticationRotationException.Conflict()
        }
        // Always the registered key; never one the request supplies.
        if (!DeviceAuthenticationRotation.verifyAuthorization(registeredKey, authorization)) {
            throw DeviceAuthenticationRotationException.InvalidProof()
        }
        if (!DeviceAuthenticationRotation.verifyProofOfPossession(authorization)) {
            throw DeviceAuthenticationRotationException.InvalidProof()
        }

        val result = devices.replaceForRotation(
            RotationReplacement(
                expected = state,
                replacementPublicKey = statement.replacementPublicKey,
                rotationId = rotationId,
                nonce = statement.nonce,
                timestamp = statement.timestamp,
                pruneBefore = now - window,
                // The server's time, never the statement's: the new key's age starts here.
                installedAt = now,
            ),
        )
        return when (result) {
            RotationReplacementResult.REPLACED -> DeviceAuthenticationRotationOutcome.ROTATED
            RotationReplacementResult.ALREADY_APPLIED -> DeviceAuthenticationRotationOutcome.ALREADY_APPLIED
            RotationReplacementResult.CONFLICT -> throw DeviceAuthenticationRotationException.Conflict()
            RotationReplacementResult.REPLAY -> throw DeviceAuthenticationRotationException.Replay()
            RotationReplacementResult.NOT_REGISTERED -> throw DeviceAuthenticationRotationException.NotRegistered()
            RotationReplacementResult.EPOCH_EXHAUSTED -> throw DeviceAuthenticationRotationException.EpochExhausted()
        }
    }
}
