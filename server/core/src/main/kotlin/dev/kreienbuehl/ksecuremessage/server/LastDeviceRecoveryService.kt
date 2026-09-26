package dev.kreienbuehl.ksecuremessage.server

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecovery
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryAuthorization
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryChallenge
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryChallengeId
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryKeyRegistration
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationRepository
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryChallengeIssue
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryChallengeRequest
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryReplacement
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryReplacementResult
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryRepository
import java.security.SecureRandom
import kotlin.time.Clock
import kotlin.time.Instant

/** A rejected last-device recovery or recovery key registration. Nothing was changed. Messages never contain key material. */
sealed class LastDeviceRecoveryException(message: String) : Exception(message) {
    /** The request is malformed or names another device than the route. */
    class InvalidRequest(message: String) : LastDeviceRecoveryException(message)

    /** The recovery key registration's proof of possession does not verify, or it is for another user. */
    class InvalidKeyRegistration(message: String) : LastDeviceRecoveryException(message)

    /** The target's user has no registered recovery key. */
    class NotConfigured : LastDeviceRecoveryException("No last-device recovery key is registered")

    /** The target has no registered device authentication key: use first registration. */
    class TargetNotRegistered : LastDeviceRecoveryException("The device is not registered")

    /** The challenge is unknown, consumed, replaced, for another device, or its fields were changed. */
    class ChallengeInvalid : LastDeviceRecoveryException("Last-device recovery challenge is invalid")

    /** The challenge expired. Request a new one. */
    class Expired : LastDeviceRecoveryException("Last-device recovery challenge expired")

    /** The recovery signature or the replacement key's proof of possession does not verify. */
    class InvalidProof : LastDeviceRecoveryException("Last-device recovery proof is invalid")

    /**
     * The registration changed since the challenge was issued (another
     * transition won), or the replacement key is the registered key.
     */
    class Conflict : LastDeviceRecoveryException("Device registration changed, last-device recovery not applied")

    /** The authentication epoch cannot grow any more. */
    class EpochExhausted : LastDeviceRecoveryException("Authentication epoch is exhausted")
}

/** A successful last-device recovery. */
enum class LastDeviceRecoveryOutcome {
    /** The target's key was replaced. */
    REPLACED,

    /** The same recovery had replaced the key before (a retry); nothing changed. */
    ALREADY_APPLIED,
}

/**
 * Last-device recovery (docs/last-device-recovery.md): registers users'
 * offline recovery public keys, issues single-use challenges and verifies
 * and applies recoveries. The recovery key authorizes, the replacement key
 * proves possession; no device authentication key takes part, so the
 * recovery endpoints carry no ServerAuth headers. Registering the recovery
 * key does (an [AuthenticatedDevice] of the same user).
 *
 * Recovery checks, in this order, before anything is changed:
 *
 * 1. the statement names the route's device (sizes and key distinctness are
 *    enforced by the statement type);
 * 2. the target's user has a registered recovery key, and it is the
 *    statement's recovery key;
 * 3. the target is registered;
 * 4. exact retry: if the last-device recovery with this statement's ID
 *    installed the registered key, and both proofs verify, the result is
 *    ALREADY_APPLIED without any write (the challenge is already consumed);
 * 5. the target's stored challenge has the statement's ID, nonce, epoch and
 *    expiry, and has not expired at [clock]'s time (bounds included);
 * 6. the registered key and epoch are still the ones the challenge was
 *    issued for (if 5 or 6 fails, the exact retry check of 4 is repeated on
 *    the current registration: an identical submission may have committed
 *    and consumed the challenge in between);
 * 7. the recovery signature verifies with the **registered** recovery key;
 * 8. the proof of possession verifies with the replacement key.
 *
 * Then [DeviceRegistrationRepository.replaceForLastDeviceRecovery] consumes
 * the challenge and replaces the key in one atomic compare-and-set on key and
 * epoch, shared with device recovery and routine rotation.
 */
internal class LastDeviceRecoveryService(
    private val devices: DeviceRegistrationRepository,
    private val repository: LastDeviceRecoveryRepository,
    private val clock: Clock,
    private val random: SecureRandom = SecureRandom(),
) {
    suspend fun registerKey(device: AuthenticatedDevice, registration: LastDeviceRecoveryKeyRegistration): Boolean {
        require(device.endpoint == ProtectedEndpoint.REGISTER_LAST_DEVICE_RECOVERY_KEY) { "Not authenticated for the recovery key" }
        if (registration.userId != device.address.userId) {
            throw LastDeviceRecoveryException.InvalidKeyRegistration("Recovery key is for another user")
        }
        if (!LastDeviceRecovery.verifyKeyRegistration(registration)) {
            throw LastDeviceRecoveryException.InvalidKeyRegistration("Recovery key proof of possession is invalid")
        }
        // Throws LastDeviceRecoveryKeyException.Conflict (storage:core) for another key: never replaced.
        return repository.registerRecoveryKey(registration.userId, registration.publicKey, now())
    }

    suspend fun issueChallenge(target: DeviceAddress): LastDeviceRecoveryChallenge {
        val now = now()
        val id = ByteArray(LastDeviceRecoveryChallengeId.SIZE).also(random::nextBytes)
        val nonce = ByteArray(LastDeviceRecoveryChallenge.NONCE_SIZE).also(random::nextBytes)
        val request = LastDeviceRecoveryChallengeRequest(
            target, LastDeviceRecoveryChallengeId(id), nonce, now, now + LastDeviceRecovery.CHALLENGE_LIFETIME,
        )
        return when (val issue = repository.issueChallenge(request)) {
            is LastDeviceRecoveryChallengeIssue.Issued -> issue.challenge.challenge
            LastDeviceRecoveryChallengeIssue.NotConfigured -> throw LastDeviceRecoveryException.NotConfigured()
            LastDeviceRecoveryChallengeIssue.NotRegistered -> throw LastDeviceRecoveryException.TargetNotRegistered()
        }
    }

    suspend fun recover(address: DeviceAddress, authorization: LastDeviceRecoveryAuthorization): LastDeviceRecoveryOutcome {
        val statement = authorization.statement
        val challenge = statement.challenge
        if (statement.target != address) throw LastDeviceRecoveryException.InvalidRequest("Recovery is for another device")

        val recoveryKey = repository.recoveryKey(address.userId) ?: throw LastDeviceRecoveryException.NotConfigured()
        if (!recoveryKey.contentEquals(statement.recoveryPublicKey)) throw LastDeviceRecoveryException.InvalidProof()

        val state = devices.registrationState(address) ?: throw LastDeviceRecoveryException.TargetNotRegistered()

        val recoveryId = LastDeviceRecovery.recoveryId(statement)
        val registeredKey = state.registration.publicKey
        if (state.lastDeviceRecoveryId == recoveryId && registeredKey.contentEquals(statement.replacementPublicKey)) {
            // A retry after a lost response: the challenge is consumed, but the
            // stored ID binds exactly this statement.
            verifyProofs(recoveryKey, authorization)
            return LastDeviceRecoveryOutcome.ALREADY_APPLIED
        }

        val now = now()
        val stored = repository.challenge(address)
        val failure = when {
            stored == null || stored.challenge.id != challenge.id || !stored.challenge.nonce.contentEquals(challenge.nonce) ||
                stored.challenge.authEpoch != challenge.authEpoch || stored.challenge.expiresAt != challenge.expiresAt ->
                LastDeviceRecoveryException.ChallengeInvalid()
            now > stored.challenge.expiresAt -> LastDeviceRecoveryException.Expired()
            !registeredKey.contentEquals(stored.authPublicKey) || state.authEpoch != stored.challenge.authEpoch ->
                LastDeviceRecoveryException.Conflict()
            else -> null
        }
        if (failure != null) {
            // An identical submission may have committed since the state was read above,
            // consuming the challenge: that is still an exact retry, not a failure.
            val fresh = devices.registrationState(address)
            if (fresh != null && fresh.lastDeviceRecoveryId == recoveryId &&
                fresh.registration.publicKey.contentEquals(statement.replacementPublicKey)
            ) {
                verifyProofs(recoveryKey, authorization)
                return LastDeviceRecoveryOutcome.ALREADY_APPLIED
            }
            throw failure
        }
        // Always the registered recovery key; never one the request supplies.
        verifyProofs(recoveryKey, authorization)

        val result = devices.replaceForLastDeviceRecovery(
            LastDeviceRecoveryReplacement(
                expected = state,
                expectedRecoveryPublicKey = recoveryKey,
                challengeId = challenge.id,
                challengeNonce = challenge.nonce,
                replacementPublicKey = statement.replacementPublicKey,
                recoveryId = recoveryId,
                // The server's time: the challenge's expiry and the new key's installation time.
                now = now,
            ),
        )
        return when (result) {
            LastDeviceRecoveryReplacementResult.REPLACED -> LastDeviceRecoveryOutcome.REPLACED
            LastDeviceRecoveryReplacementResult.ALREADY_APPLIED -> LastDeviceRecoveryOutcome.ALREADY_APPLIED
            LastDeviceRecoveryReplacementResult.NOT_REGISTERED -> throw LastDeviceRecoveryException.TargetNotRegistered()
            LastDeviceRecoveryReplacementResult.NOT_CONFIGURED -> throw LastDeviceRecoveryException.NotConfigured()
            LastDeviceRecoveryReplacementResult.CHALLENGE_INVALID -> throw LastDeviceRecoveryException.ChallengeInvalid()
            LastDeviceRecoveryReplacementResult.EXPIRED -> throw LastDeviceRecoveryException.Expired()
            LastDeviceRecoveryReplacementResult.CONFLICT -> throw LastDeviceRecoveryException.Conflict()
            LastDeviceRecoveryReplacementResult.EPOCH_EXHAUSTED -> throw LastDeviceRecoveryException.EpochExhausted()
        }
    }

    private fun verifyProofs(recoveryKey: ByteArray, authorization: LastDeviceRecoveryAuthorization) {
        if (!LastDeviceRecovery.verifyRecoverySignature(recoveryKey, authorization)) throw LastDeviceRecoveryException.InvalidProof()
        if (!LastDeviceRecovery.verifyProofOfPossession(authorization)) throw LastDeviceRecoveryException.InvalidProof()
    }

    private fun now(): Instant = Instant.fromEpochMilliseconds(clock.now().toEpochMilliseconds())
}
