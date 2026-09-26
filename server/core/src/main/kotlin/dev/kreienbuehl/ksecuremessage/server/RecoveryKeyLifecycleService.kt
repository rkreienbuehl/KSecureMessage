package dev.kreienbuehl.ksecuremessage.server

import dev.kreienbuehl.ksecuremessage.model.LastDeviceRecoveryKeyStatus
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRevocation
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRevocationAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRotation
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRotationAuthorization
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryRepository
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyRevocationResult
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyRevocationTransition
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyRotationResult
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyRotationTransition
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyState
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyStatus
import kotlin.time.Clock
import kotlin.time.Instant

/** A rejected recovery key rotation or revocation. Nothing was changed. Messages never contain key material. */
sealed class RecoveryKeyLifecycleException(message: String) : Exception(message) {
    /** The statement is malformed or names another authorizing device than the authenticated one. */
    class InvalidRequest(message: String) : RecoveryKeyLifecycleException(message)

    /** The user has no active recovery key (never registered, or revoked). */
    class NotConfigured : RecoveryKeyLifecycleException("No active last-device recovery key")

    /** The statement's timestamp is outside the validity window. */
    class Expired : RecoveryKeyLifecycleException("Recovery key statement timestamp is outside the validity window")

    /** The current recovery key's signature or the new key's proof of possession does not verify. */
    class InvalidProof : RecoveryKeyLifecycleException("Recovery key proof is invalid")

    /** The statement's nonce was used before. */
    class Replay : RecoveryKeyLifecycleException("Recovery key statement nonce was already used")

    /**
     * The recovery key state is not the one the statement names (another
     * transition won, a stale statement, or the same key again), or the
     * authorizing device's registration changed.
     */
    class Conflict : RecoveryKeyLifecycleException("Recovery key changed, transition not applied")

    /** The recovery key epoch cannot grow any more. */
    class EpochExhausted : RecoveryKeyLifecycleException("Recovery key epoch is exhausted")
}

/** A successful recovery key rotation. */
enum class RecoveryKeyRotationOutcome {
    /** The recovery key was replaced. */
    ROTATED,

    /** The same rotation had replaced it before (a retry); nothing changed. */
    ALREADY_APPLIED,
}

/** A successful recovery key revocation. */
enum class RecoveryKeyRevocationOutcome {
    /** The recovery key was revoked. */
    REVOKED,

    /** The same revocation had revoked it before (a retry); nothing changed. */
    ALREADY_APPLIED,
}

/**
 * Offline recovery key rotation and revocation (docs/recovery-key-lifecycle.md).
 * Both need two authorities: the ServerAuth v1 request of a registered
 * device of the user (an [AuthenticatedDevice], checked before the body is
 * parsed), and the current offline recovery key's signature over a statement
 * that names that device. A rotation's new key also proves possession.
 *
 * Rotation checks, in this order, before anything is changed:
 *
 * 1. the statement's authorizing device is the authenticated device (so the
 *    user is its user);
 * 2. the user registered a recovery key at all;
 * 3. exact retry: if the rotation with this statement's ID installed the
 *    active key and it is the statement's new key, and both proofs verify
 *    (the current key's signature with the statement's current key, which
 *    is no longer registered), the result is ALREADY_APPLIED without a write.
 *    This precedes the window, so a lost response can be resubmitted after
 *    a slow retrieval of the offline key;
 * 4. the key is active;
 * 5. the timestamp is within [RecoveryKeyRotation.VALIDITY_WINDOW] of
 *    [clock]'s time (bounds included);
 * 6. the active key and epoch are the statement's;
 * 7. the current key's signature verifies with the **registered** key;
 * 8. the new key's proof of possession verifies.
 *
 * Then [LastDeviceRecoveryRepository.rotateRecoveryKey] compares the state
 * and the authorizing registration, claims the nonce, installs the key and
 * removes the user's challenges in one atomic step. Revocation follows the
 * same order with a single proof.
 */
internal class RecoveryKeyLifecycleService(
    private val repository: LastDeviceRecoveryRepository,
    private val clock: Clock,
) {
    suspend fun status(device: AuthenticatedDevice): LastDeviceRecoveryKeyStatus {
        require(device.endpoint == ProtectedEndpoint.READ_LAST_DEVICE_RECOVERY_KEY) { "Not authenticated for the recovery key" }
        val state = repository.recoveryKeyState(device.address.userId) ?: return LastDeviceRecoveryKeyStatus.Unconfigured
        return when (state.status) {
            RecoveryKeyStatus.ACTIVE -> LastDeviceRecoveryKeyStatus.Active(state.epoch, checkNotNull(state.installedAt), checkNotNull(state.publicKey))
            RecoveryKeyStatus.REVOKED -> LastDeviceRecoveryKeyStatus.Revoked(state.epoch, state.transitionedAt)
        }
    }

    suspend fun rotate(device: AuthenticatedDevice, authorization: RecoveryKeyRotationAuthorization): RecoveryKeyRotationOutcome {
        require(device.endpoint == ProtectedEndpoint.ROTATE_LAST_DEVICE_RECOVERY_KEY) { "Not authenticated for a recovery key rotation" }
        val statement = authorization.statement
        if (statement.authorizer != device.address) {
            throw RecoveryKeyLifecycleException.InvalidRequest("The statement names another authorizing device")
        }
        val rotationId = RecoveryKeyRotation.rotationId(statement)
        val state = repository.recoveryKeyState(statement.userId) ?: throw RecoveryKeyLifecycleException.NotConfigured()
        if (state.isRotatedBy(rotationId, statement.newPublicKey)) return alreadyRotated(authorization)
        if (state.status != RecoveryKeyStatus.ACTIVE) throw RecoveryKeyLifecycleException.NotConfigured()

        val now = now()
        checkWindow(statement.timestamp, now)
        val registeredKey = checkNotNull(state.publicKey)
        if (state.epoch != statement.expectedEpoch || !registeredKey.contentEquals(statement.currentPublicKey)) {
            throw RecoveryKeyLifecycleException.Conflict()
        }
        // Always the registered recovery key; never one the request supplies.
        if (!RecoveryKeyRotation.verifyCurrentKeySignature(registeredKey, authorization)) throw RecoveryKeyLifecycleException.InvalidProof()
        if (!RecoveryKeyRotation.verifyNewKeyProofOfPossession(authorization)) throw RecoveryKeyLifecycleException.InvalidProof()

        val result = repository.rotateRecoveryKey(
            RecoveryKeyRotationTransition(
                userId = statement.userId,
                expectedPublicKey = registeredKey,
                expectedEpoch = state.epoch,
                newPublicKey = statement.newPublicKey,
                expectedAuthorizer = device.registrationState,
                rotationId = rotationId,
                nonce = statement.nonce,
                timestamp = statement.timestamp,
                pruneBefore = now - RecoveryKeyRotation.VALIDITY_WINDOW,
                // The server's time, never the statement's.
                now = now,
            ),
        )
        return when (result) {
            RecoveryKeyRotationResult.ROTATED -> RecoveryKeyRotationOutcome.ROTATED
            RecoveryKeyRotationResult.ALREADY_APPLIED -> RecoveryKeyRotationOutcome.ALREADY_APPLIED
            RecoveryKeyRotationResult.NOT_CONFIGURED -> throw RecoveryKeyLifecycleException.NotConfigured()
            RecoveryKeyRotationResult.REPLAY -> throw RecoveryKeyLifecycleException.Replay()
            RecoveryKeyRotationResult.EPOCH_EXHAUSTED -> throw RecoveryKeyLifecycleException.EpochExhausted()
            RecoveryKeyRotationResult.CONFLICT -> {
                // An identical submission may have committed since the state was read above.
                val fresh = repository.recoveryKeyState(statement.userId)
                if (fresh != null && fresh.isRotatedBy(rotationId, statement.newPublicKey)) return alreadyRotated(authorization)
                throw RecoveryKeyLifecycleException.Conflict()
            }
        }
    }

    suspend fun revoke(device: AuthenticatedDevice, authorization: RecoveryKeyRevocationAuthorization): RecoveryKeyRevocationOutcome {
        require(device.endpoint == ProtectedEndpoint.REVOKE_LAST_DEVICE_RECOVERY_KEY) { "Not authenticated for a recovery key revocation" }
        val statement = authorization.statement
        if (statement.authorizer != device.address) {
            throw RecoveryKeyLifecycleException.InvalidRequest("The statement names another authorizing device")
        }
        val revocationId = RecoveryKeyRevocation.revocationId(statement)
        val state = repository.recoveryKeyState(statement.userId) ?: throw RecoveryKeyLifecycleException.NotConfigured()
        if (state.isRevokedBy(revocationId)) return alreadyRevoked(authorization)
        if (state.status != RecoveryKeyStatus.ACTIVE) throw RecoveryKeyLifecycleException.NotConfigured()

        val now = now()
        checkWindow(statement.timestamp, now)
        val registeredKey = checkNotNull(state.publicKey)
        if (state.epoch != statement.expectedEpoch || !registeredKey.contentEquals(statement.currentPublicKey)) {
            throw RecoveryKeyLifecycleException.Conflict()
        }
        if (!RecoveryKeyRevocation.verifySignature(registeredKey, authorization)) throw RecoveryKeyLifecycleException.InvalidProof()

        val result = repository.revokeRecoveryKey(
            RecoveryKeyRevocationTransition(
                userId = statement.userId,
                expectedPublicKey = registeredKey,
                expectedEpoch = state.epoch,
                expectedAuthorizer = device.registrationState,
                revocationId = revocationId,
                nonce = statement.nonce,
                timestamp = statement.timestamp,
                pruneBefore = now - RecoveryKeyRotation.VALIDITY_WINDOW,
                now = now,
            ),
        )
        return when (result) {
            RecoveryKeyRevocationResult.REVOKED -> RecoveryKeyRevocationOutcome.REVOKED
            RecoveryKeyRevocationResult.ALREADY_APPLIED -> RecoveryKeyRevocationOutcome.ALREADY_APPLIED
            RecoveryKeyRevocationResult.NOT_CONFIGURED -> throw RecoveryKeyLifecycleException.NotConfigured()
            RecoveryKeyRevocationResult.REPLAY -> throw RecoveryKeyLifecycleException.Replay()
            RecoveryKeyRevocationResult.EPOCH_EXHAUSTED -> throw RecoveryKeyLifecycleException.EpochExhausted()
            RecoveryKeyRevocationResult.CONFLICT -> {
                val fresh = repository.recoveryKeyState(statement.userId)
                if (fresh != null && fresh.isRevokedBy(revocationId)) return alreadyRevoked(authorization)
                throw RecoveryKeyLifecycleException.Conflict()
            }
        }
    }

    /** Exact retry of a rotation: both proofs over the statement, the current key being the statement's (no longer registered). */
    private fun alreadyRotated(authorization: RecoveryKeyRotationAuthorization): RecoveryKeyRotationOutcome {
        if (!RecoveryKeyRotation.verifyCurrentKeySignature(authorization.statement.currentPublicKey, authorization) ||
            !RecoveryKeyRotation.verifyNewKeyProofOfPossession(authorization)
        ) {
            throw RecoveryKeyLifecycleException.InvalidProof()
        }
        return RecoveryKeyRotationOutcome.ALREADY_APPLIED
    }

    private fun alreadyRevoked(authorization: RecoveryKeyRevocationAuthorization): RecoveryKeyRevocationOutcome {
        if (!RecoveryKeyRevocation.verifySignature(authorization.statement.currentPublicKey, authorization)) {
            throw RecoveryKeyLifecycleException.InvalidProof()
        }
        return RecoveryKeyRevocationOutcome.ALREADY_APPLIED
    }

    private fun RecoveryKeyState.isRotatedBy(id: dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRotationId, newKey: ByteArray) =
        status == RecoveryKeyStatus.ACTIVE && rotationId == id && publicKey.contentEquals(newKey)

    private fun RecoveryKeyState.isRevokedBy(id: dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRevocationId) =
        status == RecoveryKeyStatus.REVOKED && revocationId == id

    private fun checkWindow(timestamp: Instant, now: Instant) {
        val window = RecoveryKeyRotation.VALIDITY_WINDOW
        if (timestamp < now - window || timestamp > now + window) throw RecoveryKeyLifecycleException.Expired()
    }

    private fun now(): Instant = Instant.fromEpochMilliseconds(clock.now().toEpochMilliseconds())
}
