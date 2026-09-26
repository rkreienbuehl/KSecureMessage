package dev.kreienbuehl.ksecuremessage.storage

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceRegistration
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationRotationId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecoveryId
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryChallenge
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryChallengeId
import dev.kreienbuehl.ksecuremessage.protocol.LastDeviceRecoveryId
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRevocationId
import dev.kreienbuehl.ksecuremessage.protocol.RecoveryKeyRotationId
import dev.kreienbuehl.ksecuremessage.protocol.RequestNonce
import kotlin.time.Instant

/**
 * Public prekey material of each device, as published by the devices. Holds
 * public keys only; the server never sees private keys. State is kept per
 * [DeviceAddress]: one identity key, one current signed prekey, an inventory
 * of available one-time prekeys and the IDs of consumed one-time prekeys.
 *
 * Both functions that change state are atomic: they either apply completely
 * or, if they throw, change nothing. Concurrent calls behave as if they ran
 * one after the other. Byte arrays are copied at the boundary.
 *
 * See docs/prekey-publication.md.
 */
interface PreKeyRepository {
    /**
     * Applies [publication]:
     * - The first publication for an address stores its identity key. A later
     *   one with a different identity key throws
     *   [PreKeyPublicationException.IdentityKeyConflict].
     * - A signed prekey with a higher ID than the current one replaces it.
     *   The same ID with the same key and signature changes nothing. The same
     *   ID with other bytes, or a lower ID, throws
     *   [PreKeyPublicationException.SignedPreKeyConflict].
     * - A one-time prekey whose ID was consumed before is skipped. One that is
     *   available with the same bytes changes nothing; with other bytes it
     *   throws [PreKeyPublicationException.OneTimePreKeyConflict]. New ones
     *   are added.
     * - A repeated one-time prekey ID within [publication] throws
     *   [PreKeyPublicationException.InvalidPublication].
     *
     * Publishing the same publication again is harmless.
     */
    suspend fun publish(publication: PreKeyPublication)

    /**
     * Returns the bundle for [address], or `null` for an unknown device. The
     * bundle holds the identity key, the current signed prekey and the
     * available one-time prekey with the lowest ID, or none if the inventory
     * is empty. That one-time prekey is removed and its ID recorded as
     * consumed, in the same atomic step: no two callers get the same one.
     */
    suspend fun consumePreKeyBundle(address: DeviceAddress): PreKeyBundle?

    /** Number of available (published, not yet handed out) one-time prekeys of [address]. */
    suspend fun oneTimePreKeyCount(address: DeviceAddress): Int
}

/** A rejected publication. The repository state is unchanged. Messages never contain key bytes. */
sealed class PreKeyPublicationException(message: String) : Exception(message) {
    /** The publication is malformed: wrong key sizes, repeated IDs, too many keys. */
    class InvalidPublication(message: String) : PreKeyPublicationException(message)

    /** The device already published a different identity key. There is no device reset yet. */
    class IdentityKeyConflict : PreKeyPublicationException("Device already has a different identity key")

    /** The signed prekey ID is known with other bytes, or older than the current one. */
    class SignedPreKeyConflict(message: String) : PreKeyPublicationException(message)

    /** A one-time prekey ID is already available with a different public key. */
    class OneTimePreKeyConflict(val id: OneTimePreKeyId) :
        PreKeyPublicationException("One-time prekey ${id.value} already exists with a different key")
}

/**
 * Queues opaque envelopes per recipient device. See
 * docs/transport-ordering.md for why the order matters.
 *
 * Ordering contract: for each ordered pair (sender [DeviceAddress], recipient
 * [DeviceAddress]), envelopes are drained in the order their [enqueue] calls
 * returned. An envelope whose [enqueue] returned before another one's started
 * comes out first. Nothing is promised about the order between different
 * senders, or between one sender's envelopes for different recipients.
 *
 * Every enqueued envelope is returned by exactly one [drain]: none is lost,
 * duplicated or returned twice, also when calls run concurrently. There are no
 * acknowledgements, expiry or persistence guarantees beyond that.
 */
interface MailboxRepository {
    /** Appends [envelope] to the queue of its recipient. Atomic. */
    suspend fun enqueue(envelope: EncryptedEnvelope)

    /** Removes and returns the queued envelopes of [recipient], each (sender, recipient) stream in order. Atomic. */
    suspend fun drain(recipient: DeviceAddress): List<EncryptedEnvelope>
}

/**
 * Device authentication public keys, one per [DeviceAddress]
 * (docs/server-authentication.md). A registration is added by [register]
 * and replaced only by [replaceForRecovery] (docs/device-recovery.md) or
 * [replaceForRotation] (docs/device-authentication-rotation.md); it is never
 * removed. Atomic; byte arrays are copied at the boundary.
 *
 * Every registration has an authentication epoch: 1 for the first
 * registration, one more for each recovery or rotation. Epochs only grow and
 * never wrap: at [Long.MAX_VALUE] no further replacement is possible.
 *
 * Every registration also has the server time its current key was installed
 * at ([DeviceRegistrationState.authKeyInstalledAt]): set by [register] for a
 * new registration and by a successful replacement, together with the key
 * and the epoch. The caller supplies that time (the server's clock, never a
 * client-supplied timestamp); retries that change nothing keep it
 * (docs/device-authentication-rotation.md).
 */
interface DeviceRegistrationRepository {
    suspend fun registration(address: DeviceAddress): DeviceRegistration?

    /**
     * The registration of [address] with its epoch, its key's installation
     * time and the transition that installed its key, or `null`.
     */
    suspend fun registrationState(address: DeviceAddress): DeviceRegistrationState?

    /**
     * Replaces the target's key in one atomic step, together with the claim
     * of the recovery's nonce ([AuthenticationNonceRepository], same nonces,
     * under the target's address). In this order:
     *
     * 1. the target has no registration: [RecoveryReplacementResult.TARGET_NOT_REGISTERED];
     * 2. the target's current key was installed by the recovery with
     *    [RecoveryReplacement.recoveryId]: [RecoveryReplacementResult.ALREADY_APPLIED],
     *    nothing written;
     * 3. the target's or the authorizer's key or epoch differ from the
     *    expected state, or the replacement key is the target's current key:
     *    [RecoveryReplacementResult.CONFLICT], nothing written;
     * 4. the target's epoch is [Long.MAX_VALUE]:
     *    [RecoveryReplacementResult.EPOCH_EXHAUSTED], nothing written;
     * 5. prunes nonces older than [RecoveryReplacement.pruneBefore] and
     *    claims the nonce; already claimed: [RecoveryReplacementResult.REPLAY]
     *    (the prune may commit);
     * 6. stores the replacement key, epoch + 1, the recovery ID and
     *    [RecoveryReplacement.installedAt] as installation time, and clears
     *    the rotation ID and the last-device recovery ID:
     *    [RecoveryReplacementResult.REPLACED].
     *
     * Nothing else changes: prekeys, mailboxes and other nonces stay.
     * Concurrent calls behave as if they ran one after the other.
     */
    suspend fun replaceForRecovery(replacement: RecoveryReplacement): RecoveryReplacementResult

    /**
     * Replaces the device's key by a routine rotation
     * (docs/device-authentication-rotation.md) in one atomic step, together
     * with the claim of the rotation's nonce ([AuthenticationNonceRepository],
     * same nonces, under the device's address). In this order:
     *
     * 1. the device has no registration: [RotationReplacementResult.NOT_REGISTERED];
     * 2. the device's current key was installed by the rotation with
     *    [RotationReplacement.rotationId]: [RotationReplacementResult.ALREADY_APPLIED],
     *    nothing written;
     * 3. the key or epoch differ from [RotationReplacement.expected], or the
     *    replacement key is the current key: [RotationReplacementResult.CONFLICT],
     *    nothing written;
     * 4. the epoch is [Long.MAX_VALUE]: [RotationReplacementResult.EPOCH_EXHAUSTED],
     *    nothing written;
     * 5. prunes nonces older than [RotationReplacement.pruneBefore] and
     *    claims the nonce; already claimed: [RotationReplacementResult.REPLAY]
     *    (the prune may commit);
     * 6. stores the replacement key, epoch + 1, the rotation ID and
     *    [RotationReplacement.installedAt] as installation time, and clears
     *    the recovery ID and the last-device recovery ID:
     *    [RotationReplacementResult.REPLACED].
     *
     * The same compare-and-set as [replaceForRecovery]: of a recovery and a
     * rotation from the same state, exactly one replaces the key. Nothing
     * else changes: prekeys, mailboxes and other nonces stay.
     */
    suspend fun replaceForRotation(replacement: RotationReplacement): RotationReplacementResult

    /**
     * Replaces the target's key by a last-device recovery
     * (docs/last-device-recovery.md) in one atomic step, together with the
     * consumption of its challenge ([LastDeviceRecoveryRepository]). No
     * nonce is claimed: the server-issued challenge is the single-use value.
     * In this order:
     *
     * 1. the target has no registration: [LastDeviceRecoveryReplacementResult.NOT_REGISTERED];
     * 2. the target's current key was installed by the last-device recovery
     *    with [LastDeviceRecoveryReplacement.recoveryId]:
     *    [LastDeviceRecoveryReplacementResult.ALREADY_APPLIED], nothing written;
     * 3. the target's user has no active recovery key (none registered, or
     *    revoked), or another one than
     *    [LastDeviceRecoveryReplacement.expectedRecoveryPublicKey]:
     *    [LastDeviceRecoveryReplacementResult.NOT_CONFIGURED], nothing written;
     * 4. the target has no stored challenge with this ID and nonce, or it was
     *    issued under another recovery key epoch than the current one
     *    (docs/recovery-key-lifecycle.md):
     *    [LastDeviceRecoveryReplacementResult.CHALLENGE_INVALID];
     *    it has, but it expired before [LastDeviceRecoveryReplacement.now]:
     *    [LastDeviceRecoveryReplacementResult.EXPIRED];
     * 5. prunes every challenge that expired before `now`;
     * 6. the target's key or epoch differ from the expected state or from
     *    the challenge's, or the replacement key is the current key:
     *    [LastDeviceRecoveryReplacementResult.CONFLICT];
     * 7. the epoch is [Long.MAX_VALUE]: [LastDeviceRecoveryReplacementResult.EPOCH_EXHAUSTED];
     * 8. deletes the challenge, stores the replacement key, epoch + 1, the
     *    last-device recovery ID and `now` as installation time, and clears
     *    the recovery and rotation IDs: [LastDeviceRecoveryReplacementResult.REPLACED].
     *
     * Every result except [LastDeviceRecoveryReplacementResult.REPLACED]
     * leaves the registration and the challenge unchanged (pruning expired
     * challenges may commit). The same compare-and-set as [replaceForRecovery]
     * and [replaceForRotation]: of transitions from the same state, exactly
     * one replaces the key. Nothing else changes: prekeys, mailboxes and
     * nonces stay.
     */
    suspend fun replaceForLastDeviceRecovery(replacement: LastDeviceRecoveryReplacement): LastDeviceRecoveryReplacementResult

    /**
     * Registers [registration] if its address has none. Returns `true` if it
     * was stored, `false` if exactly this key is registered already. Throws
     * [DeviceRegistrationException.Conflict] and changes nothing if another
     * key is registered. Concurrent calls behave as if they ran one after the
     * other: of several different keys for one address, exactly one wins. A
     * new registration has epoch 1 and [installedAt] as installation time;
     * registering the registered key again changes neither.
     */
    suspend fun register(registration: DeviceRegistration, installedAt: Instant): Boolean
}

/**
 * A stored registration: [registration] with its [authEpoch], the server time
 * [authKeyInstalledAt] its key was installed at, and the transition that
 * installed the key: [recoveryId] for a device recovery, [rotationId] for a
 * routine rotation, [lastDeviceRecoveryId] for a last-device recovery, none
 * for a key from first registration. At most one of them is set.
 */
class DeviceRegistrationState(
    val registration: DeviceRegistration,
    val authEpoch: Long,
    val authKeyInstalledAt: Instant,
    val recoveryId: DeviceRecoveryId?,
    val rotationId: DeviceAuthenticationRotationId? = null,
    val lastDeviceRecoveryId: LastDeviceRecoveryId? = null,
) {
    init {
        require(authEpoch >= 1) { "Authentication epoch must be positive" }
        require(listOfNotNull(recoveryId, rotationId, lastDeviceRecoveryId).size <= 1) {
            "A key is installed by one transition only"
        }
    }

    val address: DeviceAddress get() = registration.address

    override fun toString(): String =
        "DeviceRegistrationState(address=$address, authEpoch=$authEpoch, authKeyInstalledAt=$authKeyInstalledAt)"
}

/**
 * A verified recovery for [DeviceRegistrationRepository.replaceForRecovery]:
 * replace [expectedTarget]'s key with [replacementPublicKey], authorized by
 * [expectedAuthorizer]. Both expected states are what the signatures were
 * verified against; the replacement only happens if they are still current.
 * [timestamp] is the request's (client-supplied) time, used for the nonce;
 * [installedAt] is the server time stored as the new key's installation time.
 */
class RecoveryReplacement(
    val expectedTarget: DeviceRegistrationState,
    val expectedAuthorizer: DeviceRegistrationState,
    replacementPublicKey: ByteArray,
    val recoveryId: DeviceRecoveryId,
    val nonce: RequestNonce,
    val timestamp: Instant,
    val pruneBefore: Instant,
    val installedAt: Instant,
) {
    private val key: ByteArray = replacementPublicKey.copyOf()

    /** A copy of the replacement key. */
    val replacementPublicKey: ByteArray get() = key.copyOf()

    val target: DeviceAddress get() = expectedTarget.address

    override fun toString(): String = "RecoveryReplacement(target=$target, authorizer=${expectedAuthorizer.address})"
}

/** Outcome of [DeviceRegistrationRepository.replaceForRecovery]. */
enum class RecoveryReplacementResult {
    /** The key was replaced and the epoch incremented. */
    REPLACED,

    /** This recovery installed the current key before; nothing changed. */
    ALREADY_APPLIED,

    /** The registrations are no longer the verified ones; nothing changed. */
    CONFLICT,

    /** The nonce was claimed before; the registration is unchanged. */
    REPLAY,

    /** The target has no registration; nothing changed. */
    TARGET_NOT_REGISTERED,

    /** The target's epoch cannot grow any more; nothing changed. */
    EPOCH_EXHAUSTED,
}

/**
 * A verified routine rotation for [DeviceRegistrationRepository.replaceForRotation]:
 * replace the key of [expected] with [replacementPublicKey]. [expected] is
 * the state the signatures were verified against; the replacement only
 * happens if it is still current. [timestamp] is the statement's
 * (client-supplied) time, used for the nonce; [installedAt] is the server
 * time stored as the new key's installation time.
 */
class RotationReplacement(
    val expected: DeviceRegistrationState,
    replacementPublicKey: ByteArray,
    val rotationId: DeviceAuthenticationRotationId,
    val nonce: RequestNonce,
    val timestamp: Instant,
    val pruneBefore: Instant,
    val installedAt: Instant,
) {
    private val key: ByteArray = replacementPublicKey.copyOf()

    /** A copy of the replacement key. */
    val replacementPublicKey: ByteArray get() = key.copyOf()

    val address: DeviceAddress get() = expected.address

    override fun toString(): String = "RotationReplacement(address=$address, expectedAuthEpoch=${expected.authEpoch})"
}

/** Outcome of [DeviceRegistrationRepository.replaceForRotation]. */
enum class RotationReplacementResult {
    /** The key was replaced and the epoch incremented. */
    REPLACED,

    /** This rotation installed the current key before; nothing changed. */
    ALREADY_APPLIED,

    /** The registration is no longer the verified one; nothing changed. */
    CONFLICT,

    /** The nonce was claimed before; the registration is unchanged. */
    REPLAY,

    /** The device has no registration; nothing changed. */
    NOT_REGISTERED,

    /** The epoch cannot grow any more; nothing changed. */
    EPOCH_EXHAUSTED,
}

/**
 * A verified last-device recovery for
 * [DeviceRegistrationRepository.replaceForLastDeviceRecovery]: replace the
 * key of [expected] with [replacementPublicKey], authorized by the recovery
 * key [expectedRecoveryPublicKey] over the challenge [challengeId] /
 * [challengeNonce]. [expected] is the state the signatures were verified
 * against. [now] is the server time: the challenge must not have expired
 * before it, and it becomes the new key's installation time.
 */
class LastDeviceRecoveryReplacement(
    val expected: DeviceRegistrationState,
    expectedRecoveryPublicKey: ByteArray,
    val challengeId: LastDeviceRecoveryChallengeId,
    challengeNonce: ByteArray,
    replacementPublicKey: ByteArray,
    val recoveryId: LastDeviceRecoveryId,
    val now: Instant,
) {
    private val recoveryKey: ByteArray = expectedRecoveryPublicKey.copyOf()
    private val nonce: ByteArray = challengeNonce.copyOf()
    private val key: ByteArray = replacementPublicKey.copyOf()

    /** A copy of the recovery public key the recovery signature was verified with. */
    val expectedRecoveryPublicKey: ByteArray get() = recoveryKey.copyOf()

    /** A copy of the challenge nonce. */
    val challengeNonce: ByteArray get() = nonce.copyOf()

    /** A copy of the replacement key. */
    val replacementPublicKey: ByteArray get() = key.copyOf()

    val target: DeviceAddress get() = expected.address

    override fun toString(): String = "LastDeviceRecoveryReplacement(target=$target, expectedAuthEpoch=${expected.authEpoch})"
}

/** Outcome of [DeviceRegistrationRepository.replaceForLastDeviceRecovery]. */
enum class LastDeviceRecoveryReplacementResult {
    /** The key was replaced, the epoch incremented and the challenge consumed. */
    REPLACED,

    /** This recovery installed the current key before; nothing changed. */
    ALREADY_APPLIED,

    /** The target has no registration; nothing changed. */
    NOT_REGISTERED,

    /** The user has no (or another) recovery key; nothing changed. */
    NOT_CONFIGURED,

    /** No such challenge for the target (unknown, consumed or replaced); nothing changed. */
    CHALLENGE_INVALID,

    /** The challenge expired; nothing changed. */
    EXPIRED,

    /** The registration is no longer the verified one or the challenge's; nothing changed. */
    CONFLICT,

    /** The epoch cannot grow any more; nothing changed. */
    EPOCH_EXHAUSTED,
}

/** A rejected device registration. Nothing was stored. Messages never contain key bytes. */
sealed class DeviceRegistrationException(message: String) : Exception(message) {
    /** The registration is malformed, for example a key of the wrong size. */
    class InvalidRegistration(message: String) : DeviceRegistrationException(message)

    /** The address is registered with a different key. Only a recovery or a rotation replaces it. */
    class Conflict : DeviceRegistrationException("Device is registered with a different authentication key")
}

/**
 * Nonces of accepted authenticated requests, per device, for replay
 * protection (docs/server-authentication.md). Entries only need to live as
 * long as their request timestamp is inside the server's validity window.
 */
interface AuthenticationNonceRepository {
    /**
     * In one atomic step: removes every entry (of any device) whose request
     * timestamp is before [pruneBefore], then records [nonce] for [address]
     * with [timestamp]. Returns `false`, and records nothing, if [nonce] is
     * already recorded for [address]. Of concurrent claims of the same
     * nonce for the same address, exactly one returns `true`.
     */
    suspend fun claim(address: DeviceAddress, nonce: ByteArray, timestamp: Instant, pruneBefore: Instant): Boolean
}

/**
 * Last-device recovery state (docs/last-device-recovery.md,
 * docs/recovery-key-lifecycle.md): per user the state of its offline
 * recovery key (public key, recovery key epoch, transition metadata), and per
 * device at most one outstanding server-issued challenge. Shares its
 * atomicity with [DeviceRegistrationRepository] and
 * [AuthenticationNonceRepository]:
 * [DeviceRegistrationRepository.replaceForLastDeviceRecovery] consumes a
 * challenge in the same step as it replaces the key, and a recovery key
 * rotation or revocation claims its nonce, compares the authorizing device's
 * registration and removes every challenge of the user in the same step as
 * it changes the recovery key. Never holds private key material.
 *
 * The recovery key epoch is 1 for a first registration and grows by one with
 * every rotation, revocation and registration after a revocation. It never
 * decreases, never wraps and is never reset: at [Long.MAX_VALUE] no further
 * transition is possible.
 */
interface LastDeviceRecoveryRepository {
    /** A copy of the **active** recovery public key of [userId], or `null` (none registered, or revoked). */
    suspend fun recoveryKey(userId: UserId): ByteArray?

    /** The recovery key state of [userId], or `null` if the user never registered one. */
    suspend fun recoveryKeyState(userId: UserId): RecoveryKeyState?

    /**
     * Registers [publicKey] (32 bytes) as [userId]'s recovery key:
     *
     * - the user never registered one: stores it at epoch 1, returns `true`;
     * - the user's key was revoked at epoch N: stores it at epoch N + 1 and
     *   clears the transition IDs, returns `true`; at N = [Long.MAX_VALUE]
     *   throws [LastDeviceRecoveryKeyException.EpochExhausted];
     * - exactly this key is active: returns `false`, nothing changes;
     * - another key is active: throws [LastDeviceRecoveryKeyException.Conflict],
     *   nothing changes. Only [rotateRecoveryKey] replaces an active key.
     *
     * [registeredAt] (server time) becomes the key's installation time.
     * Concurrent calls behave as if they ran one after the other.
     */
    suspend fun registerRecoveryKey(userId: UserId, publicKey: ByteArray, registeredAt: Instant): Boolean

    /**
     * Replaces the user's active recovery key in one atomic step. In this order:
     *
     * 1. the user never registered a key: [RecoveryKeyRotationResult.NOT_CONFIGURED];
     * 2. the active key was installed by the rotation with
     *    [RecoveryKeyRotationTransition.rotationId] and is its new key:
     *    [RecoveryKeyRotationResult.ALREADY_APPLIED], nothing written;
     * 3. the key is revoked, or its key or epoch differ from the expected
     *    ones, or the new key is the active key, or the authorizing device's
     *    registration differs from [RecoveryKeyRotationTransition.expectedAuthorizer]
     *    (key and epoch): [RecoveryKeyRotationResult.CONFLICT], nothing written;
     * 4. the epoch is [Long.MAX_VALUE]: [RecoveryKeyRotationResult.EPOCH_EXHAUSTED];
     * 5. prunes nonces older than [RecoveryKeyRotationTransition.pruneBefore]
     *    and claims the nonce under the authorizing device
     *    ([AuthenticationNonceRepository], same namespace); already claimed:
     *    [RecoveryKeyRotationResult.REPLAY] (the prune may commit);
     * 6. stores the new key, epoch + 1, the rotation ID (clearing a
     *    revocation ID) and [RecoveryKeyRotationTransition.now] as
     *    installation and transition time, and deletes every last-device
     *    recovery challenge of the user: [RecoveryKeyRotationResult.ROTATED].
     *
     * Nothing else changes: device registrations, epochs and installation
     * times, prekeys, mailboxes and other nonces stay.
     */
    suspend fun rotateRecoveryKey(transition: RecoveryKeyRotationTransition): RecoveryKeyRotationResult

    /**
     * Revokes the user's active recovery key in one atomic step. In this order:
     *
     * 1. the user never registered a key: [RecoveryKeyRevocationResult.NOT_CONFIGURED];
     * 2. the key is revoked and the revocation with
     *    [RecoveryKeyRevocationTransition.revocationId] revoked it:
     *    [RecoveryKeyRevocationResult.ALREADY_APPLIED], nothing written;
     * 3. the key is revoked (by another revocation), or its key or epoch
     *    differ from the expected ones, or the authorizing device's
     *    registration differs from the expected one:
     *    [RecoveryKeyRevocationResult.CONFLICT], nothing written;
     * 4. the epoch is [Long.MAX_VALUE]: [RecoveryKeyRevocationResult.EPOCH_EXHAUSTED];
     * 5. prunes and claims the nonce as [rotateRecoveryKey] does:
     *    [RecoveryKeyRevocationResult.REPLAY];
     * 6. removes the key, stores epoch + 1, the revocation ID (clearing a
     *    rotation ID) and [RecoveryKeyRevocationTransition.now] as
     *    revocation time, and deletes every last-device recovery challenge
     *    of the user: [RecoveryKeyRevocationResult.REVOKED].
     */
    suspend fun revokeRecoveryKey(transition: RecoveryKeyRevocationTransition): RecoveryKeyRevocationResult

    /**
     * In one atomic step: prunes every challenge that expired before
     * [LastDeviceRecoveryChallengeRequest.now]; then
     *
     * - the target has no registration: [LastDeviceRecoveryChallengeIssue.NotRegistered];
     * - its user has no active recovery key (none, or revoked):
     *   [LastDeviceRecoveryChallengeIssue.NotConfigured];
     * - the target has an unexpired challenge issued for its current key and
     *   epoch and the current recovery key epoch: returns that one unchanged;
     * - otherwise stores the request's candidate ID and nonce with the
     *   current key, epoch and recovery key epoch (replacing an outdated
     *   challenge of the target) and returns it.
     *
     * So a target has at most one challenge, and requesting another one while
     * it is valid returns the same challenge.
     */
    suspend fun issueChallenge(request: LastDeviceRecoveryChallengeRequest): LastDeviceRecoveryChallengeIssue

    /** The stored challenge of [target], expired or not, or `null`. */
    suspend fun challenge(target: DeviceAddress): StoredLastDeviceRecoveryChallenge?
}

/**
 * A request for a challenge for [target]: the server-chosen random
 * [candidateId] and [candidateNonce] (used only if a new challenge is
 * stored), the server time [now] and the new challenge's [expiresAt].
 */
class LastDeviceRecoveryChallengeRequest(
    val target: DeviceAddress,
    val candidateId: LastDeviceRecoveryChallengeId,
    candidateNonce: ByteArray,
    val now: Instant,
    val expiresAt: Instant,
) {
    private val nonce: ByteArray = candidateNonce.copyOf()

    init {
        require(nonce.size == LastDeviceRecoveryChallenge.NONCE_SIZE) { "Challenge nonce has an invalid size" }
    }

    /** A copy of the candidate nonce. */
    val candidateNonce: ByteArray get() = nonce.copyOf()

    override fun toString(): String = "LastDeviceRecoveryChallengeRequest(target=$target)"
}

/**
 * A stored challenge: the public [challenge], the registered key it was
 * issued for ([authPublicKey], server-side only, never returned to clients)
 * and the recovery key epoch it was issued under ([recoveryKeyEpoch]; a
 * rotation or revocation of the recovery key invalidates it).
 */
class StoredLastDeviceRecoveryChallenge(
    val challenge: LastDeviceRecoveryChallenge,
    authPublicKey: ByteArray,
    val recoveryKeyEpoch: Long,
) {
    private val key: ByteArray = authPublicKey.copyOf()

    /** A copy of the device authentication key registered when the challenge was issued. */
    val authPublicKey: ByteArray get() = key.copyOf()

    override fun toString(): String = "StoredLastDeviceRecoveryChallenge($challenge)"
}

/** Outcome of [LastDeviceRecoveryRepository.issueChallenge]. */
sealed interface LastDeviceRecoveryChallengeIssue {
    class Issued(val challenge: StoredLastDeviceRecoveryChallenge) : LastDeviceRecoveryChallengeIssue

    data object NotRegistered : LastDeviceRecoveryChallengeIssue

    data object NotConfigured : LastDeviceRecoveryChallengeIssue
}

/** A rejected recovery key registration. Nothing was stored. Messages never contain key bytes. */
sealed class LastDeviceRecoveryKeyException(message: String) : Exception(message) {
    /** The user has a different active recovery key. Only a rotation replaces it (docs/recovery-key-lifecycle.md). */
    class Conflict : LastDeviceRecoveryKeyException("A different last-device recovery key is registered")

    /** The recovery key epoch cannot grow any more. */
    class EpochExhausted : LastDeviceRecoveryKeyException("Recovery key epoch is exhausted")
}

/** Whether a user's recovery key is [ACTIVE] or [REVOKED]. A user that never registered one has no [RecoveryKeyState]. */
enum class RecoveryKeyStatus { ACTIVE, REVOKED }

/**
 * A user's stored recovery key state (docs/recovery-key-lifecycle.md):
 * [epoch], the [publicKey] and its server installation time [installedAt]
 * (both only while [status] is [RecoveryKeyStatus.ACTIVE]), the server time
 * of the last transition [transitionedAt] (registration, rotation or
 * revocation; for a revoked key the revocation time), and the transition
 * that produced this state: [rotationId] for a rotation, [revocationId] for
 * a revocation, none for a registration. At most one of them is set.
 */
class RecoveryKeyState(
    val epoch: Long,
    val status: RecoveryKeyStatus,
    publicKey: ByteArray?,
    val installedAt: Instant?,
    val transitionedAt: Instant,
    val rotationId: RecoveryKeyRotationId? = null,
    val revocationId: RecoveryKeyRevocationId? = null,
) {
    private val key: ByteArray? = publicKey?.copyOf()

    init {
        require(epoch >= 1) { "Recovery key epoch must be positive" }
        require(rotationId == null || revocationId == null) { "A state is produced by one transition only" }
        when (status) {
            RecoveryKeyStatus.ACTIVE -> {
                require(key != null && key.size == 32) { "An active recovery key needs a 32-byte public key" }
                require(installedAt != null) { "An active recovery key needs an installation time" }
                require(revocationId == null) { "An active recovery key was not revoked" }
            }
            RecoveryKeyStatus.REVOKED -> {
                require(key == null && installedAt == null) { "A revoked recovery key has no key" }
                require(rotationId == null) { "A revoked recovery key was not installed by a rotation" }
            }
        }
    }

    /** A copy of the active public key, or `null` when revoked. */
    val publicKey: ByteArray? get() = key?.copyOf()

    override fun toString(): String = "RecoveryKeyState(epoch=$epoch, status=$status)"
}

/**
 * A verified recovery key rotation for [LastDeviceRecoveryRepository.rotateRecoveryKey]:
 * replace [userId]'s key [expectedPublicKey] at [expectedEpoch] with
 * [newPublicKey]. [expectedAuthorizer] is the authorizing device's
 * registration the ServerAuth request was verified with; the rotation only
 * happens while it is still current. [nonce] / [timestamp] are the
 * statement's (client-supplied, used for replay protection only); [now] is
 * the server time stored as installation time.
 */
class RecoveryKeyRotationTransition(
    val userId: UserId,
    expectedPublicKey: ByteArray,
    val expectedEpoch: Long,
    newPublicKey: ByteArray,
    val expectedAuthorizer: DeviceRegistrationState,
    val rotationId: RecoveryKeyRotationId,
    val nonce: RequestNonce,
    val timestamp: Instant,
    val pruneBefore: Instant,
    val now: Instant,
) {
    private val expected: ByteArray = expectedPublicKey.copyOf()
    private val new: ByteArray = newPublicKey.copyOf()

    init {
        require(expectedAuthorizer.address.userId == userId) { "The authorizing device must belong to the user" }
    }

    /** A copy of the key the rotation replaces. */
    val expectedPublicKey: ByteArray get() = expected.copyOf()

    /** A copy of the new key. */
    val newPublicKey: ByteArray get() = new.copyOf()

    override fun toString(): String = "RecoveryKeyRotationTransition(userId=$userId, expectedEpoch=$expectedEpoch)"
}

/** Outcome of [LastDeviceRecoveryRepository.rotateRecoveryKey]. */
enum class RecoveryKeyRotationResult {
    /** The key was replaced, the epoch incremented and the user's challenges removed. */
    ROTATED,

    /** This rotation installed the active key before; nothing changed. */
    ALREADY_APPLIED,

    /** The user never registered a recovery key; nothing changed. */
    NOT_CONFIGURED,

    /** The recovery key state or the authorizing registration is no longer the verified one; nothing changed. */
    CONFLICT,

    /** The nonce was claimed before; nothing changed. */
    REPLAY,

    /** The recovery key epoch cannot grow any more; nothing changed. */
    EPOCH_EXHAUSTED,
}

/**
 * A verified recovery key revocation for [LastDeviceRecoveryRepository.revokeRecoveryKey]:
 * revoke [userId]'s key [expectedPublicKey] at [expectedEpoch]. The other
 * fields as in [RecoveryKeyRotationTransition]; [now] becomes the
 * revocation time.
 */
class RecoveryKeyRevocationTransition(
    val userId: UserId,
    expectedPublicKey: ByteArray,
    val expectedEpoch: Long,
    val expectedAuthorizer: DeviceRegistrationState,
    val revocationId: RecoveryKeyRevocationId,
    val nonce: RequestNonce,
    val timestamp: Instant,
    val pruneBefore: Instant,
    val now: Instant,
) {
    private val expected: ByteArray = expectedPublicKey.copyOf()

    init {
        require(expectedAuthorizer.address.userId == userId) { "The authorizing device must belong to the user" }
    }

    /** A copy of the key the revocation removes. */
    val expectedPublicKey: ByteArray get() = expected.copyOf()

    override fun toString(): String = "RecoveryKeyRevocationTransition(userId=$userId, expectedEpoch=$expectedEpoch)"
}

/** Outcome of [LastDeviceRecoveryRepository.revokeRecoveryKey]. */
enum class RecoveryKeyRevocationResult {
    /** The key was removed, the epoch incremented and the user's challenges removed. */
    REVOKED,

    /** This revocation revoked the key before; nothing changed. */
    ALREADY_APPLIED,

    /** The user never registered a recovery key; nothing changed. */
    NOT_CONFIGURED,

    /** The recovery key state or the authorizing registration is no longer the verified one; nothing changed. */
    CONFLICT,

    /** The nonce was claimed before; nothing changed. */
    REPLAY,

    /** The recovery key epoch cannot grow any more; nothing changed. */
    EPOCH_EXHAUSTED,
}

interface ServerStorage {
    val preKeys: PreKeyRepository
    val mailboxes: MailboxRepository
    val devices: DeviceRegistrationRepository
    val authenticationNonces: AuthenticationNonceRepository
    val lastDeviceRecovery: LastDeviceRecoveryRepository
}
