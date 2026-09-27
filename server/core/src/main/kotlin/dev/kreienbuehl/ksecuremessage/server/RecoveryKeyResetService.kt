package dev.kreienbuehl.ksecuremessage.server

import dev.kreienbuehl.ksecuremessage.model.RecoveryKeyResetId
import dev.kreienbuehl.ksecuremessage.model.RecoveryKeyResetStatus
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyReset
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyResetCancellationAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyResetCompletionAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyResetCompletionId
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyResetStatusQuery
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryRepository
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyResetCancellation
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyResetCancellationAuthority
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyResetCancellationResult
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyResetCompletionResult
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyResetCompletionTransition
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyResetRequest
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyResetRequestResult
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyState
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyStatus
import java.security.SecureRandom
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Instant

/**
 * The host's policy for delayed recovery key resets (docs/recovery-key-reset.md):
 * a reset requested at server time `t` can be completed from `t + delay` on
 * (rounded up to whole milliseconds). The delay is the time every device of
 * the user, and the holder of the current recovery key, has to notice and
 * cancel a reset; choose it for how often the application checks. There is no
 * default: a server without a policy refuses reset requests.
 */
data class RecoveryKeyResetPolicy(val delay: Duration) {
    init {
        require(delay.isPositive() && delay.isFinite()) { "Recovery key reset delay must be positive and finite" }
    }

    /** The eligibility time of a reset requested at [requestedAt] (whole milliseconds). Fails closed on overflow. */
    internal fun eligibleAt(requestedAt: Instant): Instant {
        val whole = delay.inWholeMilliseconds
        val millis = if (delay > whole.milliseconds) whole + 1 else whole
        val eligible = try {
            Math.addExact(requestedAt.toEpochMilliseconds(), millis)
        } catch (e: ArithmeticException) {
            throw IllegalStateException("Recovery key reset delay exceeds the representable time")
        }
        val instant = Instant.fromEpochMilliseconds(eligible)
        check(instant.toEpochMilliseconds() == eligible) { "Recovery key reset delay exceeds the representable time" }
        return instant
    }
}

/** A rejected recovery key reset operation. Nothing was changed. Messages never contain key material. */
sealed class RecoveryKeyResetException(message: String) : Exception(message) {
    /** The server has no reset policy: delayed resets are disabled. */
    class NotAvailable : RecoveryKeyResetException("Delayed recovery key reset is not available")

    /** The user has no active recovery key (never registered, or revoked). */
    class NotConfigured : RecoveryKeyResetException("No active last-device recovery key")

    /** No reset with this ID is pending (none, cancelled, completed or replaced by another transition). */
    class NotPending : RecoveryKeyResetException("No such recovery key reset is pending")

    /** The pending reset cannot be completed yet. */
    class NotYetEligible : RecoveryKeyResetException("Recovery key reset is not eligible yet")

    /** The statement does not match the pending reset or the current recovery key, or the acting device's registration changed. */
    class Conflict : RecoveryKeyResetException("Recovery key reset changed, operation not applied")

    /** The request is malformed or names another device than the authenticated one. */
    class InvalidRequest(message: String) : RecoveryKeyResetException(message)

    /** The new key's proof of possession or the current recovery key's signature does not verify. */
    class InvalidProof : RecoveryKeyResetException("Recovery key reset proof is invalid")

    /** The status query's timestamp is outside the validity window. */
    class Expired : RecoveryKeyResetException("Recovery key reset status query timestamp is outside the validity window")

    /** The recovery key epoch cannot grow any more. */
    class EpochExhausted : RecoveryKeyResetException("Recovery key epoch is exhausted")
}

/** A reset request: the pending [reset], [created] by this request or an existing one returned unchanged. */
class RecoveryKeyResetRequestOutcome(val reset: RecoveryKeyResetStatus.Pending, val created: Boolean)

/** A successful reset completion. */
enum class RecoveryKeyResetCompletionOutcome {
    /** The recovery key was replaced. */
    COMPLETED,

    /** The same completion had replaced it before (a retry); nothing changed. */
    ALREADY_APPLIED,
}

/**
 * Delayed recovery key reset (docs/recovery-key-reset.md): the exceptional
 * replacement of a lost offline recovery key. Weaker than a rotation
 * ([RecoveryKeyLifecycleService]), which needs the current recovery key and
 * stays the normal path.
 *
 * - A registered device of the user requests it (ServerAuth). The server
 *   stores it with its own time as request time and `policy.eligibleAt` as
 *   eligibility time; nothing in a request chooses either. A repeated
 *   request returns the pending reset unchanged.
 * - Every registered device of the user reads it (ServerAuth), and so does
 *   the holder of the current recovery key (a signed status query).
 * - Any registered device of the user cancels it (ServerAuth), and so does
 *   the current recovery key alone (a signed cancellation).
 * - From the eligibility time on, a registered device of the user completes
 *   it (ServerAuth) with the new key's proof of possession over a statement
 *   bound to the exact reset and the state it replaces. Nothing happens
 *   automatically at the eligibility time.
 *
 * Completion checks, in this order, before anything is changed: the
 * completing device is the authenticated one; the user registered a recovery
 * key; exact retry (the completion with this ID installed the active key,
 * proof verified: ALREADY_APPLIED without a write); the key is active; the
 * reset is pending with this ID; the statement names the pending reset's
 * key, epoch and times; the state is still that key and epoch; [clock]'s
 * time is not before the eligibility time; the proof of possession verifies.
 * Then [LastDeviceRecoveryRepository.completeRecoveryKeyReset] compares
 * everything again and applies the transition in one atomic step.
 */
internal class RecoveryKeyResetService(
    private val repository: LastDeviceRecoveryRepository,
    private val clock: Clock,
    private val policy: RecoveryKeyResetPolicy?,
    private val random: SecureRandom = SecureRandom(),
) {
    suspend fun request(device: AuthenticatedDevice): RecoveryKeyResetRequestOutcome {
        require(device.endpoint == ProtectedEndpoint.REQUEST_LAST_DEVICE_RECOVERY_KEY_RESET) { "Not authenticated for a recovery key reset request" }
        val policy = policy ?: throw RecoveryKeyResetException.NotAvailable()
        val candidate = RecoveryKeyResetId(ByteArray(RecoveryKeyResetId.SIZE).also(random::nextBytes))
        // The server's time and policy only; never a time from the request.
        val now = now()
        val result = repository.requestRecoveryKeyReset(
            RecoveryKeyResetRequest(device.registrationState, candidate, now, policy.eligibleAt(now)),
        )
        return when (result) {
            is RecoveryKeyResetRequestResult.Created -> RecoveryKeyResetRequestOutcome(result.reset, created = true)
            is RecoveryKeyResetRequestResult.Existing -> RecoveryKeyResetRequestOutcome(result.reset, created = false)
            RecoveryKeyResetRequestResult.NotConfigured -> throw RecoveryKeyResetException.NotConfigured()
            RecoveryKeyResetRequestResult.Conflict -> throw RecoveryKeyResetException.Conflict()
            RecoveryKeyResetRequestResult.EpochExhausted -> throw RecoveryKeyResetException.EpochExhausted()
        }
    }

    suspend fun status(device: AuthenticatedDevice): RecoveryKeyResetStatus {
        require(device.endpoint == ProtectedEndpoint.READ_LAST_DEVICE_RECOVERY_KEY_RESET) { "Not authenticated for the recovery key reset" }
        return repository.pendingRecoveryKeyReset(device.address.userId) ?: RecoveryKeyResetStatus.None
    }

    suspend fun statusByRecoveryKey(query: RecoveryKeyResetStatusQuery): RecoveryKeyResetStatus {
        val statement = query.statement
        val registered = repository.recoveryKey(statement.userId) ?: throw RecoveryKeyResetException.NotConfigured()
        if (!registered.contentEquals(statement.currentPublicKey)) throw RecoveryKeyResetException.InvalidProof()
        val now = now()
        val window = RecoveryKeyReset.VALIDITY_WINDOW
        if (statement.timestamp < now - window || statement.timestamp > now + window) throw RecoveryKeyResetException.Expired()
        // Always the registered recovery key; never one the request supplies.
        if (!RecoveryKeyReset.verifyStatusQuery(registered, query)) throw RecoveryKeyResetException.InvalidProof()
        return repository.pendingRecoveryKeyReset(statement.userId) ?: RecoveryKeyResetStatus.None
    }

    suspend fun complete(device: AuthenticatedDevice, authorization: RecoveryKeyResetCompletionAuthorization): RecoveryKeyResetCompletionOutcome {
        require(device.endpoint == ProtectedEndpoint.COMPLETE_LAST_DEVICE_RECOVERY_KEY_RESET) { "Not authenticated for a recovery key reset completion" }
        val statement = authorization.statement
        if (statement.completer != device.address) {
            throw RecoveryKeyResetException.InvalidRequest("The statement names another completing device")
        }
        val completionId = RecoveryKeyReset.completionId(statement)
        val state = repository.recoveryKeyState(statement.userId) ?: throw RecoveryKeyResetException.NotConfigured()
        if (state.isCompletedBy(completionId, statement.newPublicKey)) return alreadyCompleted(authorization)
        if (state.status != RecoveryKeyStatus.ACTIVE) throw RecoveryKeyResetException.NotConfigured()

        val reset = repository.pendingRecoveryKeyReset(statement.userId)
        if (reset == null || reset.resetId != statement.resetId) throw RecoveryKeyResetException.NotPending()
        if (reset.recoveryKeyEpoch != statement.expectedEpoch || !reset.recoveryPublicKey.contentEquals(statement.currentPublicKey) ||
            reset.requestedAt != statement.requestedAt || reset.eligibleAt != statement.eligibleAt ||
            !state.isActive(statement.currentPublicKey, statement.expectedEpoch)
        ) {
            throw RecoveryKeyResetException.Conflict()
        }
        val now = now()
        if (now < reset.eligibleAt) throw RecoveryKeyResetException.NotYetEligible()
        if (!RecoveryKeyReset.verifyNewKeyProofOfPossession(authorization)) throw RecoveryKeyResetException.InvalidProof()

        val result = repository.completeRecoveryKeyReset(
            RecoveryKeyResetCompletionTransition(
                userId = statement.userId,
                resetId = reset.resetId,
                expectedPublicKey = reset.recoveryPublicKey,
                expectedEpoch = reset.recoveryKeyEpoch,
                requestedAt = reset.requestedAt,
                eligibleAt = reset.eligibleAt,
                newPublicKey = statement.newPublicKey,
                expectedCompleter = device.registrationState,
                completionId = completionId,
                // The server's time, never the request's or the eligibility time.
                now = now,
            ),
        )
        return when (result) {
            RecoveryKeyResetCompletionResult.COMPLETED -> RecoveryKeyResetCompletionOutcome.COMPLETED
            RecoveryKeyResetCompletionResult.ALREADY_APPLIED -> RecoveryKeyResetCompletionOutcome.ALREADY_APPLIED
            RecoveryKeyResetCompletionResult.NOT_CONFIGURED -> throw RecoveryKeyResetException.NotConfigured()
            RecoveryKeyResetCompletionResult.NOT_YET_ELIGIBLE -> throw RecoveryKeyResetException.NotYetEligible()
            RecoveryKeyResetCompletionResult.EPOCH_EXHAUSTED -> throw RecoveryKeyResetException.EpochExhausted()
            RecoveryKeyResetCompletionResult.NOT_PENDING, RecoveryKeyResetCompletionResult.CONFLICT -> {
                // An identical submission may have committed since the state was read above.
                val fresh = repository.recoveryKeyState(statement.userId)
                if (fresh != null && fresh.isCompletedBy(completionId, statement.newPublicKey)) return alreadyCompleted(authorization)
                if (result == RecoveryKeyResetCompletionResult.NOT_PENDING) throw RecoveryKeyResetException.NotPending()
                throw RecoveryKeyResetException.Conflict()
            }
        }
    }

    suspend fun cancel(device: AuthenticatedDevice, resetId: RecoveryKeyResetId) {
        require(device.endpoint == ProtectedEndpoint.CANCEL_LAST_DEVICE_RECOVERY_KEY_RESET) { "Not authenticated for a recovery key reset cancellation" }
        cancel(RecoveryKeyResetCancellation(device.address.userId, resetId, RecoveryKeyResetCancellationAuthority.Device(device.registrationState)))
    }

    suspend fun cancelByRecoveryKey(authorization: RecoveryKeyResetCancellationAuthorization) {
        val statement = authorization.statement
        val reset = repository.pendingRecoveryKeyReset(statement.userId)
        if (reset == null || reset.resetId != statement.resetId) throw RecoveryKeyResetException.NotPending()
        if (reset.recoveryKeyEpoch != statement.expectedEpoch || !reset.recoveryPublicKey.contentEquals(statement.currentPublicKey) ||
            reset.requestedAt != statement.requestedAt || reset.eligibleAt != statement.eligibleAt
        ) {
            throw RecoveryKeyResetException.Conflict()
        }
        // The pending reset is bound to the registered key (the repository checks it on read): verify with that key.
        if (!RecoveryKeyReset.verifyCancellation(reset.recoveryPublicKey, authorization)) throw RecoveryKeyResetException.InvalidProof()
        cancel(
            RecoveryKeyResetCancellation(
                statement.userId, reset.resetId, RecoveryKeyResetCancellationAuthority.RecoveryKey(reset.recoveryPublicKey, reset.recoveryKeyEpoch),
            ),
        )
    }

    private suspend fun cancel(cancellation: RecoveryKeyResetCancellation) {
        when (repository.cancelRecoveryKeyReset(cancellation)) {
            RecoveryKeyResetCancellationResult.CANCELLED -> Unit
            RecoveryKeyResetCancellationResult.NOT_PENDING -> throw RecoveryKeyResetException.NotPending()
            RecoveryKeyResetCancellationResult.CONFLICT -> throw RecoveryKeyResetException.Conflict()
        }
    }

    /** Exact retry of a completion: the proof of possession over the statement. */
    private fun alreadyCompleted(authorization: RecoveryKeyResetCompletionAuthorization): RecoveryKeyResetCompletionOutcome {
        if (!RecoveryKeyReset.verifyNewKeyProofOfPossession(authorization)) throw RecoveryKeyResetException.InvalidProof()
        return RecoveryKeyResetCompletionOutcome.ALREADY_APPLIED
    }

    private fun RecoveryKeyState.isCompletedBy(id: RecoveryKeyResetCompletionId, newKey: ByteArray) =
        status == RecoveryKeyStatus.ACTIVE && resetCompletionId == id && publicKey.contentEquals(newKey)

    private fun now(): Instant = Instant.fromEpochMilliseconds(clock.now().toEpochMilliseconds())
}
