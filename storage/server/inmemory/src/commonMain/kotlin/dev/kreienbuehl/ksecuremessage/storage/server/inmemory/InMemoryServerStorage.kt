package dev.kreienbuehl.ksecuremessage.storage.server.inmemory

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceRegistration
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication
import dev.kreienbuehl.ksecuremessage.model.PublicOneTimePreKey
import dev.kreienbuehl.ksecuremessage.model.PublicSignedPreKey
import dev.kreienbuehl.ksecuremessage.model.RecoveryKeyResetStatus
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationRotationId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecoveryId
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecovery
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryChallenge
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryId
import dev.kreienbuehl.ksecuremessage.storage.AuthenticationNonceRepository
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationException
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationRepository
import dev.kreienbuehl.ksecuremessage.storage.DeviceRegistrationState
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryChallengeIssue
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryChallengeRequest
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryKeyException
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryReplacement
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryReplacementResult
import dev.kreienbuehl.ksecuremessage.storage.LastDeviceRecoveryRepository
import dev.kreienbuehl.ksecuremessage.storage.MailboxRepository
import dev.kreienbuehl.ksecuremessage.storage.PreKeyPublicationException
import dev.kreienbuehl.ksecuremessage.storage.PreKeyRepository
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyResetCancellation
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyResetCancellationAuthority
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyResetCancellationResult
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyResetCompletionResult
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyResetCompletionTransition
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyResetRequest
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyResetRequestResult
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyRevocationResult
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyRevocationTransition
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyRotationResult
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyRotationTransition
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyState
import dev.kreienbuehl.ksecuremessage.storage.RecoveryKeyStatus
import dev.kreienbuehl.ksecuremessage.storage.RecoveryReplacement
import dev.kreienbuehl.ksecuremessage.storage.RecoveryReplacementResult
import dev.kreienbuehl.ksecuremessage.storage.RotationReplacement
import dev.kreienbuehl.ksecuremessage.storage.RotationReplacementResult
import dev.kreienbuehl.ksecuremessage.storage.ServerStorage
import dev.kreienbuehl.ksecuremessage.storage.StoredLastDeviceRecoveryChallenge
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.time.Instant

/**
 * Non-persistent [ServerStorage] for tests and examples.
 *
 * The prekey repository keeps immutable state behind a [Mutex]: publication
 * and bundle consumption each run under the lock and replace the state only
 * after all checks passed, so they are atomic and serialized. The mailboxes
 * are one queue per recipient behind another [Mutex], so enqueue and drain
 * are serialized too and each recipient's queue is in enqueue order. That is
 * stronger than the per (sender, recipient) order [MailboxRepository]
 * promises. Device registrations and authentication nonces share one more
 * [Mutex], so registration, nonce claims, device recovery and routine
 * rotation (key replacement together with its nonce claim) are atomic. The
 * last-device recovery keys and challenges live under that mutex too, so a
 * last-device recovery consumes its challenge in the same step as it replaces
 * the key, and a recovery key rotation or revocation claims its nonce, checks
 * the authorizing registration and removes the user's challenges in the same
 * step as it changes the recovery key. The pending recovery key resets live
 * there as well: every recovery key transition removes the user's reset in
 * the same step, and a reset completion replaces the key, removes the reset
 * and the challenges at once.
 */
class InMemoryServerStorage : ServerStorage {
    override val preKeys: PreKeyRepository = InMemoryPreKeyRepository()

    override val mailboxes: MailboxRepository = InMemoryMailboxRepository()

    private val authentication = AuthenticationState()

    override val devices: DeviceRegistrationRepository = InMemoryDeviceRegistrationRepository(authentication)

    override val authenticationNonces: AuthenticationNonceRepository = InMemoryAuthenticationNonceRepository(authentication)

    override val lastDeviceRecovery: LastDeviceRecoveryRepository = InMemoryLastDeviceRecoveryRepository(authentication)

    /** Test support: sets a registered device's epoch, for the epoch exhaustion boundary. */
    internal suspend fun setAuthEpochForTesting(address: DeviceAddress, authEpoch: Long) = authentication.mutex.withLock {
        val registration = checkNotNull(authentication.registrations[address]) { "Device is not registered" }
        authentication.registrations = authentication.registrations +
            (address to registration.copy(authEpoch = authEpoch))
    }

    /** Test support: sets a user's recovery key epoch, for the epoch exhaustion boundary. */
    internal suspend fun setRecoveryKeyEpochForTesting(userId: UserId, epoch: Long) = authentication.mutex.withLock {
        val state = checkNotNull(authentication.recoveryKeys[userId]) { "No recovery key state" }
        authentication.recoveryKeys = authentication.recoveryKeys + (
            userId to RecoveryKeyState(
                epoch, state.status, state.publicKey, state.installedAt, state.transitionedAt, state.rotationId, state.revocationId,
                state.resetCompletionId,
            )
        )
    }
}

/**
 * One stored registration with the server time its key was installed at and
 * the transition that installed it (at most one of [recoveryId],
 * [rotationId] and [lastDeviceRecoveryId]). The key is copied on the way in
 * and out.
 */
private class Registration(
    val publicKey: ByteArray,
    val authEpoch: Long,
    val installedAt: Instant,
    val recoveryId: DeviceRecoveryId?,
    val rotationId: DeviceAuthenticationRotationId?,
    val lastDeviceRecoveryId: LastDeviceRecoveryId? = null,
) {
    fun copy(authEpoch: Long) = Registration(publicKey, authEpoch, installedAt, recoveryId, rotationId, lastDeviceRecoveryId)
}

/** A stored last-device recovery challenge with the key, epoch and recovery key epoch it was issued for. */
private class Challenge(val challenge: LastDeviceRecoveryChallenge, val authPublicKey: ByteArray, val recoveryKeyEpoch: Long)

/**
 * Registrations and accepted nonces behind one [Mutex], so a recovery or a
 * rotation replaces a key and claims its nonce in one atomic step
 * ([DeviceRegistrationRepository.replaceForRecovery],
 * [DeviceRegistrationRepository.replaceForRotation]). Nonces are kept with
 * their request timestamps; pruning runs inside every claim, under the same
 * lock, so the state never outgrows the nonces of the validity window.
 */
private class AuthenticationState {
    val mutex = Mutex()
    var registrations = mapOf<DeviceAddress, Registration>()
    var nonces = mapOf<Pair<DeviceAddress, NonceKey>, Instant>()

    /** Recovery key state per user (immutable values; the key is copied at the boundary). */
    var recoveryKeys = mapOf<UserId, RecoveryKeyState>()

    /** The pending recovery key reset per user, bound to the ACTIVE key and epoch it was requested for. */
    var resets = mapOf<UserId, RecoveryKeyResetStatus.Pending>()

    /** Caller holds [mutex]. The user's active recovery key state, or `null`. */
    fun activeRecoveryKey(userId: UserId): RecoveryKeyState? =
        recoveryKeys[userId]?.takeIf { it.status == RecoveryKeyStatus.ACTIVE }

    /**
     * The compare-and-set shared by recovery key rotation, revocation and
     * reset completion, after their own idempotency and expected-state checks
     * passed. Caller holds [mutex]. Checks epoch exhaustion, runs [claim] (the
     * nonce claim; `false` = replay), then stores [next] and removes every
     * last-device recovery challenge and the pending reset of [userId].
     */
    fun transitionRecoveryKey(
        userId: UserId,
        current: RecoveryKeyState,
        next: (epoch: Long) -> RecoveryKeyState,
        claim: () -> Boolean,
    ): RecoveryKeyTransition {
        if (current.epoch == Long.MAX_VALUE) return RecoveryKeyTransition.EPOCH_EXHAUSTED
        if (!claim()) return RecoveryKeyTransition.REPLAY
        recoveryKeys = recoveryKeys + (userId to next(current.epoch + 1))
        challenges = challenges.filterKeys { it.userId != userId }
        resets = resets - userId
        return RecoveryKeyTransition.APPLIED
    }

    enum class RecoveryKeyTransition { APPLIED, REPLAY, EPOCH_EXHAUSTED }

    /** Caller holds [mutex]. `true` if [expected]'s address is still registered with its key and epoch. */
    fun registrationMatches(expected: DeviceRegistrationState): Boolean {
        val current = registrations[expected.address] ?: return false
        return current.authEpoch == expected.authEpoch && current.publicKey.contentEquals(expected.registration.publicKey)
    }

    /** At most one last-device recovery challenge per device. */
    var challenges = mapOf<DeviceAddress, Challenge>()

    /** Caller holds [mutex]. Removes every challenge that expired before [now]. */
    fun pruneChallenges(now: Instant) {
        challenges = challenges.filterValues { it.challenge.expiresAt >= now }
    }

    /**
     * The compare-and-set shared by recovery, rotation and last-device
     * recovery, after their own idempotency and expected-state checks passed.
     * Caller holds [mutex]. Checks epoch exhaustion, runs [claim] (the nonce
     * claim, or the challenge consumption; `false` = replay), then installs
     * [newKey] with epoch + 1, [installedAt] and exactly one of [recoveryId],
     * [rotationId] and [lastDeviceRecoveryId].
     */
    fun replaceKey(
        address: DeviceAddress,
        current: Registration,
        newKey: ByteArray,
        installedAt: Instant,
        recoveryId: DeviceRecoveryId?,
        rotationId: DeviceAuthenticationRotationId?,
        lastDeviceRecoveryId: LastDeviceRecoveryId?,
        claim: () -> Boolean,
    ): KeyReplacement {
        if (current.authEpoch == Long.MAX_VALUE) return KeyReplacement.EPOCH_EXHAUSTED
        if (!claim()) return KeyReplacement.REPLAY
        registrations = registrations +
            (address to Registration(newKey, current.authEpoch + 1, installedAt, recoveryId, rotationId, lastDeviceRecoveryId))
        return KeyReplacement.REPLACED
    }

    enum class KeyReplacement { REPLACED, REPLAY, EPOCH_EXHAUSTED }

    /** Largest prune bound ever applied; never decreases (docs/server-authentication.md, "Nonce lifetime"). */
    var nonceWatermark: Instant = Instant.DISTANT_PAST

    /** Caller holds [mutex]. */
    fun claim(address: DeviceAddress, nonce: ByteArray, timestamp: Instant, pruneBefore: Instant): Boolean {
        if (pruneBefore > nonceWatermark) nonceWatermark = pruneBefore
        // The nonce of such a request may already have been pruned: refuse it as a possible replay.
        if (timestamp < nonceWatermark) return false
        val watermark = nonceWatermark
        val kept = nonces.filterValues { it >= watermark }
        val key = address to NonceKey(nonce.copyOf())
        if (key in kept) {
            nonces = kept
            return false
        }
        nonces = kept + (key to timestamp)
        return true
    }

    class NonceKey(val bytes: ByteArray) {
        override fun equals(other: Any?) = other is NonceKey && bytes.contentEquals(other.bytes)
        override fun hashCode() = bytes.contentHashCode()
    }
}

private class InMemoryDeviceRegistrationRepository(private val state: AuthenticationState) : DeviceRegistrationRepository {
    override suspend fun registration(address: DeviceAddress): DeviceRegistration? =
        state.mutex.withLock { state.registrations[address]?.let { DeviceRegistration(address, it.publicKey) } }

    override suspend fun registrationState(address: DeviceAddress): DeviceRegistrationState? = state.mutex.withLock {
        state.registrations[address]?.let {
            DeviceRegistrationState(
                DeviceRegistration(address, it.publicKey), it.authEpoch, it.installedAt, it.recoveryId, it.rotationId, it.lastDeviceRecoveryId,
            )
        }
    }

    // A retry of the registered key changes nothing, also not the installation time.
    override suspend fun register(registration: DeviceRegistration, installedAt: Instant): Boolean = state.mutex.withLock {
        val existing = state.registrations[registration.address]
        when {
            existing == null -> {
                state.registrations = state.registrations + (registration.address to Registration(registration.publicKey, 1, installedAt, null, null))
                true
            }
            existing.publicKey.contentEquals(registration.publicKey) -> false
            else -> throw DeviceRegistrationException.Conflict()
        }
    }

    override suspend fun replaceForRecovery(replacement: RecoveryReplacement): RecoveryReplacementResult = state.mutex.withLock {
        val target = state.registrations[replacement.target] ?: return@withLock RecoveryReplacementResult.TARGET_NOT_REGISTERED
        if (target.recoveryId == replacement.recoveryId) return@withLock RecoveryReplacementResult.ALREADY_APPLIED
        val newKey = replacement.replacementPublicKey
        val authorizer = state.registrations[replacement.expectedAuthorizer.address]
        if (!target.matches(replacement.expectedTarget) ||
            authorizer == null || !authorizer.matches(replacement.expectedAuthorizer) ||
            target.publicKey.contentEquals(newKey)
        ) {
            return@withLock RecoveryReplacementResult.CONFLICT
        }
        val result = state.replaceKey(
            replacement.target, target, newKey, replacement.installedAt,
            recoveryId = replacement.recoveryId, rotationId = null, lastDeviceRecoveryId = null,
        ) { state.claim(replacement.target, replacement.nonce.bytes, replacement.timestamp, replacement.pruneBefore) }
        when (result) {
            AuthenticationState.KeyReplacement.REPLACED -> RecoveryReplacementResult.REPLACED
            AuthenticationState.KeyReplacement.REPLAY -> RecoveryReplacementResult.REPLAY
            AuthenticationState.KeyReplacement.EPOCH_EXHAUSTED -> RecoveryReplacementResult.EPOCH_EXHAUSTED
        }
    }

    override suspend fun replaceForRotation(replacement: RotationReplacement): RotationReplacementResult = state.mutex.withLock {
        val current = state.registrations[replacement.address] ?: return@withLock RotationReplacementResult.NOT_REGISTERED
        if (current.rotationId == replacement.rotationId) return@withLock RotationReplacementResult.ALREADY_APPLIED
        val newKey = replacement.replacementPublicKey
        if (!current.matches(replacement.expected) || current.publicKey.contentEquals(newKey)) {
            return@withLock RotationReplacementResult.CONFLICT
        }
        val result = state.replaceKey(
            replacement.address, current, newKey, replacement.installedAt,
            recoveryId = null, rotationId = replacement.rotationId, lastDeviceRecoveryId = null,
        ) { state.claim(replacement.address, replacement.nonce.bytes, replacement.timestamp, replacement.pruneBefore) }
        when (result) {
            AuthenticationState.KeyReplacement.REPLACED -> RotationReplacementResult.REPLACED
            AuthenticationState.KeyReplacement.REPLAY -> RotationReplacementResult.REPLAY
            AuthenticationState.KeyReplacement.EPOCH_EXHAUSTED -> RotationReplacementResult.EPOCH_EXHAUSTED
        }
    }

    override suspend fun replaceForLastDeviceRecovery(
        replacement: LastDeviceRecoveryReplacement,
    ): LastDeviceRecoveryReplacementResult = state.mutex.withLock {
        val target = replacement.target
        val current = state.registrations[target] ?: return@withLock LastDeviceRecoveryReplacementResult.NOT_REGISTERED
        if (current.lastDeviceRecoveryId == replacement.recoveryId) return@withLock LastDeviceRecoveryReplacementResult.ALREADY_APPLIED
        val recoveryKey = state.activeRecoveryKey(target.userId)
        if (recoveryKey == null || !recoveryKey.publicKey.contentEquals(replacement.expectedRecoveryPublicKey)) {
            return@withLock LastDeviceRecoveryReplacementResult.NOT_CONFIGURED
        }
        val stored = state.challenges[target]
        if (stored == null || stored.challenge.id != replacement.challengeId ||
            !stored.challenge.nonce.contentEquals(replacement.challengeNonce) || stored.recoveryKeyEpoch != recoveryKey.epoch
        ) {
            state.pruneChallenges(replacement.now)
            return@withLock LastDeviceRecoveryReplacementResult.CHALLENGE_INVALID
        }
        if (stored.challenge.expiresAt < replacement.now) {
            state.pruneChallenges(replacement.now)
            return@withLock LastDeviceRecoveryReplacementResult.EXPIRED
        }
        state.pruneChallenges(replacement.now)
        val newKey = replacement.replacementPublicKey
        if (!current.matches(replacement.expected) ||
            stored.challenge.authEpoch != current.authEpoch || !stored.authPublicKey.contentEquals(current.publicKey) ||
            current.publicKey.contentEquals(newKey)
        ) {
            return@withLock LastDeviceRecoveryReplacementResult.CONFLICT
        }
        val result = state.replaceKey(
            target, current, newKey, replacement.now,
            recoveryId = null, rotationId = null, lastDeviceRecoveryId = replacement.recoveryId,
        ) {
            state.challenges = state.challenges - target
            true
        }
        when (result) {
            AuthenticationState.KeyReplacement.REPLACED -> LastDeviceRecoveryReplacementResult.REPLACED
            AuthenticationState.KeyReplacement.REPLAY -> error("A challenge consumption never replays")
            AuthenticationState.KeyReplacement.EPOCH_EXHAUSTED -> LastDeviceRecoveryReplacementResult.EPOCH_EXHAUSTED
        }
    }

    private fun Registration.matches(expected: DeviceRegistrationState) =
        authEpoch == expected.authEpoch && publicKey.contentEquals(expected.registration.publicKey)
}

private class InMemoryLastDeviceRecoveryRepository(private val state: AuthenticationState) : LastDeviceRecoveryRepository {
    override suspend fun recoveryKey(userId: UserId): ByteArray? = state.mutex.withLock { state.activeRecoveryKey(userId)?.publicKey }

    override suspend fun recoveryKeyState(userId: UserId): RecoveryKeyState? = state.mutex.withLock { state.recoveryKeys[userId] }

    override suspend fun registerRecoveryKey(userId: UserId, publicKey: ByteArray, registeredAt: Instant): Boolean {
        require(publicKey.size == LastDeviceRecovery.PUBLIC_KEY_SIZE) { "Recovery public key has an invalid size" }
        return state.mutex.withLock {
            val existing = state.recoveryKeys[userId]
            val epoch = when {
                existing == null -> 1L
                existing.status == RecoveryKeyStatus.ACTIVE ->
                    if (existing.publicKey.contentEquals(publicKey)) return@withLock false else throw LastDeviceRecoveryKeyException.Conflict()
                // Revoked: a new key continues the epoch, never restarts it.
                existing.epoch == Long.MAX_VALUE -> throw LastDeviceRecoveryKeyException.EpochExhausted()
                else -> existing.epoch + 1
            }
            state.recoveryKeys = state.recoveryKeys +
                (userId to RecoveryKeyState(epoch, RecoveryKeyStatus.ACTIVE, publicKey, registeredAt, registeredAt))
            state.resets = state.resets - userId
            true
        }
    }

    override suspend fun rotateRecoveryKey(transition: RecoveryKeyRotationTransition): RecoveryKeyRotationResult = state.mutex.withLock {
        val userId = transition.userId
        val current = state.recoveryKeys[userId] ?: return@withLock RecoveryKeyRotationResult.NOT_CONFIGURED
        val newKey = transition.newPublicKey
        if (current.rotationId == transition.rotationId && current.publicKey.contentEquals(newKey)) {
            return@withLock RecoveryKeyRotationResult.ALREADY_APPLIED
        }
        if (current.status != RecoveryKeyStatus.ACTIVE || current.epoch != transition.expectedEpoch ||
            !current.publicKey.contentEquals(transition.expectedPublicKey) || current.publicKey.contentEquals(newKey) ||
            !state.registrationMatches(transition.expectedAuthorizer)
        ) {
            return@withLock RecoveryKeyRotationResult.CONFLICT
        }
        val result = state.transitionRecoveryKey(
            userId, current,
            next = { epoch ->
                RecoveryKeyState(epoch, RecoveryKeyStatus.ACTIVE, newKey, transition.now, transition.now, rotationId = transition.rotationId)
            },
        ) { state.claim(transition.expectedAuthorizer.address, transition.nonce.bytes, transition.timestamp, transition.pruneBefore) }
        when (result) {
            AuthenticationState.RecoveryKeyTransition.APPLIED -> RecoveryKeyRotationResult.ROTATED
            AuthenticationState.RecoveryKeyTransition.REPLAY -> RecoveryKeyRotationResult.REPLAY
            AuthenticationState.RecoveryKeyTransition.EPOCH_EXHAUSTED -> RecoveryKeyRotationResult.EPOCH_EXHAUSTED
        }
    }

    override suspend fun revokeRecoveryKey(transition: RecoveryKeyRevocationTransition): RecoveryKeyRevocationResult = state.mutex.withLock {
        val userId = transition.userId
        val current = state.recoveryKeys[userId] ?: return@withLock RecoveryKeyRevocationResult.NOT_CONFIGURED
        if (current.status == RecoveryKeyStatus.REVOKED && current.revocationId == transition.revocationId) {
            return@withLock RecoveryKeyRevocationResult.ALREADY_APPLIED
        }
        if (current.status != RecoveryKeyStatus.ACTIVE || current.epoch != transition.expectedEpoch ||
            !current.publicKey.contentEquals(transition.expectedPublicKey) ||
            !state.registrationMatches(transition.expectedAuthorizer)
        ) {
            return@withLock RecoveryKeyRevocationResult.CONFLICT
        }
        val result = state.transitionRecoveryKey(
            userId, current,
            next = { epoch ->
                RecoveryKeyState(epoch, RecoveryKeyStatus.REVOKED, null, null, transition.now, revocationId = transition.revocationId)
            },
        ) { state.claim(transition.expectedAuthorizer.address, transition.nonce.bytes, transition.timestamp, transition.pruneBefore) }
        when (result) {
            AuthenticationState.RecoveryKeyTransition.APPLIED -> RecoveryKeyRevocationResult.REVOKED
            AuthenticationState.RecoveryKeyTransition.REPLAY -> RecoveryKeyRevocationResult.REPLAY
            AuthenticationState.RecoveryKeyTransition.EPOCH_EXHAUSTED -> RecoveryKeyRevocationResult.EPOCH_EXHAUSTED
        }
    }

    override suspend fun issueChallenge(request: LastDeviceRecoveryChallengeRequest): LastDeviceRecoveryChallengeIssue =
        state.mutex.withLock {
            state.pruneChallenges(request.now)
            val target = request.target
            val registration = state.registrations[target] ?: return@withLock LastDeviceRecoveryChallengeIssue.NotRegistered
            val recoveryKey = state.activeRecoveryKey(target.userId) ?: return@withLock LastDeviceRecoveryChallengeIssue.NotConfigured
            val existing = state.challenges[target]
            if (existing != null && existing.challenge.authEpoch == registration.authEpoch &&
                existing.authPublicKey.contentEquals(registration.publicKey) && existing.recoveryKeyEpoch == recoveryKey.epoch
            ) {
                return@withLock LastDeviceRecoveryChallengeIssue.Issued(existing.stored())
            }
            val challenge = Challenge(
                LastDeviceRecoveryChallenge(target, request.candidateId, request.candidateNonce, registration.authEpoch, request.expiresAt),
                registration.publicKey.copyOf(),
                recoveryKey.epoch,
            )
            state.challenges = state.challenges + (target to challenge)
            LastDeviceRecoveryChallengeIssue.Issued(challenge.stored())
        }

    override suspend fun challenge(target: DeviceAddress): StoredLastDeviceRecoveryChallenge? =
        state.mutex.withLock { state.challenges[target]?.stored() }

    override suspend fun pendingRecoveryKeyReset(userId: UserId): RecoveryKeyResetStatus.Pending? = state.mutex.withLock {
        val reset = state.resets[userId] ?: return@withLock null
        val current = state.recoveryKeys[userId]
        check(current != null && current.isActive(reset.recoveryPublicKey, reset.recoveryKeyEpoch)) {
            "A pending recovery key reset is not bound to the current recovery key"
        }
        reset
    }

    override suspend fun requestRecoveryKeyReset(request: RecoveryKeyResetRequest): RecoveryKeyResetRequestResult = state.mutex.withLock {
        val userId = request.userId
        val current = state.activeRecoveryKey(userId) ?: return@withLock RecoveryKeyResetRequestResult.NotConfigured
        if (!state.registrationMatches(request.requester)) return@withLock RecoveryKeyResetRequestResult.Conflict
        state.resets[userId]?.let { return@withLock RecoveryKeyResetRequestResult.Existing(it) }
        if (current.epoch == Long.MAX_VALUE) return@withLock RecoveryKeyResetRequestResult.EpochExhausted
        val reset = RecoveryKeyResetStatus.Pending(
            request.candidateId, request.requester.address, request.now, request.eligibleAt, current.epoch, checkNotNull(current.publicKey),
        )
        state.resets = state.resets + (userId to reset)
        RecoveryKeyResetRequestResult.Created(reset)
    }

    override suspend fun completeRecoveryKeyReset(transition: RecoveryKeyResetCompletionTransition): RecoveryKeyResetCompletionResult =
        state.mutex.withLock {
            val userId = transition.userId
            val current = state.recoveryKeys[userId] ?: return@withLock RecoveryKeyResetCompletionResult.NOT_CONFIGURED
            val newKey = transition.newPublicKey
            if (current.resetCompletionId == transition.completionId && current.publicKey.contentEquals(newKey)) {
                return@withLock RecoveryKeyResetCompletionResult.ALREADY_APPLIED
            }
            val reset = state.resets[userId]
            if (reset == null || reset.resetId != transition.resetId) return@withLock RecoveryKeyResetCompletionResult.NOT_PENDING
            if (reset.recoveryKeyEpoch != transition.expectedEpoch || !reset.recoveryPublicKey.contentEquals(transition.expectedPublicKey) ||
                reset.requestedAt != transition.requestedAt || reset.eligibleAt != transition.eligibleAt ||
                !current.isActive(transition.expectedPublicKey, transition.expectedEpoch) || current.publicKey.contentEquals(newKey) ||
                !state.registrationMatches(transition.expectedCompleter)
            ) {
                return@withLock RecoveryKeyResetCompletionResult.CONFLICT
            }
            if (transition.now < reset.eligibleAt) return@withLock RecoveryKeyResetCompletionResult.NOT_YET_ELIGIBLE
            val result = state.transitionRecoveryKey(
                userId, current,
                next = { epoch ->
                    RecoveryKeyState(
                        epoch, RecoveryKeyStatus.ACTIVE, newKey, transition.now, transition.now, resetCompletionId = transition.completionId,
                    )
                },
            ) { true }
            when (result) {
                AuthenticationState.RecoveryKeyTransition.APPLIED -> RecoveryKeyResetCompletionResult.COMPLETED
                AuthenticationState.RecoveryKeyTransition.REPLAY -> error("A reset completion claims no nonce")
                AuthenticationState.RecoveryKeyTransition.EPOCH_EXHAUSTED -> RecoveryKeyResetCompletionResult.EPOCH_EXHAUSTED
            }
        }

    override suspend fun cancelRecoveryKeyReset(cancellation: RecoveryKeyResetCancellation): RecoveryKeyResetCancellationResult =
        state.mutex.withLock {
            val userId = cancellation.userId
            val reset = state.resets[userId]
            if (reset == null || reset.resetId != cancellation.resetId) return@withLock RecoveryKeyResetCancellationResult.NOT_PENDING
            val authorized = when (val authority = cancellation.authority) {
                is RecoveryKeyResetCancellationAuthority.Device -> state.registrationMatches(authority.registration)
                is RecoveryKeyResetCancellationAuthority.RecoveryKey ->
                    reset.recoveryKeyEpoch == authority.epoch && reset.recoveryPublicKey.contentEquals(authority.publicKey) &&
                        state.recoveryKeys[userId]?.isActive(authority.publicKey, authority.epoch) == true
            }
            if (!authorized) return@withLock RecoveryKeyResetCancellationResult.CONFLICT
            state.resets = state.resets - userId
            RecoveryKeyResetCancellationResult.CANCELLED
        }

    private fun Challenge.stored() = StoredLastDeviceRecoveryChallenge(challenge, authPublicKey, recoveryKeyEpoch)
}

private class InMemoryAuthenticationNonceRepository(private val state: AuthenticationState) : AuthenticationNonceRepository {
    override suspend fun claim(address: DeviceAddress, nonce: ByteArray, timestamp: Instant, pruneBefore: Instant): Boolean =
        state.mutex.withLock { state.claim(address, nonce, timestamp, pruneBefore) }
}

private class InMemoryMailboxRepository : MailboxRepository {
    private val mutex = Mutex()
    private val queues = mutableMapOf<DeviceAddress, ArrayDeque<EncryptedEnvelope>>()

    override suspend fun enqueue(envelope: EncryptedEnvelope) = mutex.withLock {
        queues.getOrPut(envelope.recipient) { ArrayDeque() }.addLast(envelope)
    }

    override suspend fun drain(recipient: DeviceAddress): List<EncryptedEnvelope> = mutex.withLock {
        queues.remove(recipient)?.toList().orEmpty()
    }
}

/** Published state of one device. Arrays are never handed out without a copy. */
private data class DeviceKeys(
    val identityKey: ByteArray,
    val signedPreKey: PublicSignedPreKey,
    /** Available one-time prekeys, public key by ID. */
    val available: Map<OneTimePreKeyId, ByteArray>,
    /** IDs already handed out. Never published again. */
    val consumed: Set<OneTimePreKeyId>,
)

private class InMemoryPreKeyRepository : PreKeyRepository {
    private val mutex = Mutex()
    private var devices = mapOf<DeviceAddress, DeviceKeys>()

    override suspend fun publish(publication: PreKeyPublication) = mutex.withLock {
        val ids = publication.oneTimePreKeys.map { it.id }
        if (ids.toSet().size != ids.size) {
            throw PreKeyPublicationException.InvalidPublication("Duplicate one-time prekey ID")
        }
        val existing = devices[publication.address]
        if (existing != null && !existing.identityKey.contentEquals(publication.identityKey)) {
            throw PreKeyPublicationException.IdentityKeyConflict()
        }
        val signedPreKey = publication.signedPreKey
        if (existing != null) checkSignedPreKey(existing.signedPreKey, signedPreKey)

        val available = existing?.available.orEmpty().toMutableMap()
        val consumed = existing?.consumed.orEmpty()
        for (preKey in publication.oneTimePreKeys) {
            if (preKey.id in consumed) continue
            val stored = available[preKey.id]
            when {
                stored == null -> available[preKey.id] = preKey.publicKey.copyOf()
                !stored.contentEquals(preKey.publicKey) -> throw PreKeyPublicationException.OneTimePreKeyConflict(preKey.id)
            }
        }
        // All checks passed: commit.
        devices = devices + (publication.address to DeviceKeys(
            identityKey = publication.identityKey.copyOf(),
            signedPreKey = signedPreKey.deepCopy(),
            available = available,
            consumed = consumed,
        ))
    }

    private fun checkSignedPreKey(current: PublicSignedPreKey, published: PublicSignedPreKey) {
        when {
            published.id.value < current.id.value ->
                throw PreKeyPublicationException.SignedPreKeyConflict("Signed prekey is older than the current one")
            published.id == current.id && (
                !published.publicKey.contentEquals(current.publicKey) ||
                    !published.signature.contentEquals(current.signature)
                ) ->
                throw PreKeyPublicationException.SignedPreKeyConflict("Signed prekey ID already exists with other bytes")
        }
    }

    override suspend fun consumePreKeyBundle(address: DeviceAddress): PreKeyBundle? = mutex.withLock {
        val device = devices[address] ?: return@withLock null
        val id = device.available.keys.minByOrNull { it.value }
        if (id != null) {
            devices = devices + (address to device.copy(available = device.available - id, consumed = device.consumed + id))
        }
        PreKeyBundle(
            address = address,
            identityKey = device.identityKey.copyOf(),
            signedPreKey = device.signedPreKey.deepCopy(),
            oneTimePreKey = id?.let { PublicOneTimePreKey(it, device.available.getValue(it).copyOf()) },
        )
    }

    override suspend fun oneTimePreKeyCount(address: DeviceAddress): Int =
        mutex.withLock { devices[address]?.available?.size ?: 0 }
}

// Not named copy(): the data class member would win and copy shallowly.
private fun PublicSignedPreKey.deepCopy() = PublicSignedPreKey(id, publicKey.copyOf(), signature.copyOf())
