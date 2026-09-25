package dev.kreienbuehl.ksecuremessage.storage

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceRegistration
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication
import dev.kreienbuehl.ksecuremessage.protocol.DeviceRecoveryId
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
 * and replaced only by [replaceForRecovery] (docs/device-recovery.md); it is
 * never removed. Atomic; byte arrays are copied at the boundary.
 *
 * Every registration has an authentication epoch: 1 for the first
 * registration, one more for each recovery. Epochs only grow.
 */
interface DeviceRegistrationRepository {
    suspend fun registration(address: DeviceAddress): DeviceRegistration?

    /** The registration of [address] with its epoch and the recovery that installed its key, or `null`. */
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
     * 4. prunes nonces older than [RecoveryReplacement.pruneBefore] and
     *    claims the nonce; already claimed: [RecoveryReplacementResult.REPLAY]
     *    (the prune may commit);
     * 5. stores the replacement key, epoch + 1 and the recovery ID:
     *    [RecoveryReplacementResult.REPLACED].
     *
     * Nothing else changes: prekeys, mailboxes and other nonces stay.
     * Concurrent calls behave as if they ran one after the other.
     */
    suspend fun replaceForRecovery(replacement: RecoveryReplacement): RecoveryReplacementResult

    /**
     * Registers [registration] if its address has none. Returns `true` if it
     * was stored, `false` if exactly this key is registered already. Throws
     * [DeviceRegistrationException.Conflict] and changes nothing if another
     * key is registered. Concurrent calls behave as if they ran one after the
     * other: of several different keys for one address, exactly one wins. A
     * new registration has epoch 1.
     */
    suspend fun register(registration: DeviceRegistration): Boolean
}

/**
 * A stored registration: [registration] with its [authEpoch] and the
 * [recoveryId] of the recovery that installed the key (`null` for a key from
 * first registration).
 */
class DeviceRegistrationState(
    val registration: DeviceRegistration,
    val authEpoch: Long,
    val recoveryId: DeviceRecoveryId?,
) {
    init {
        require(authEpoch >= 1) { "Authentication epoch must be positive" }
    }

    val address: DeviceAddress get() = registration.address

    override fun toString(): String = "DeviceRegistrationState(address=$address, authEpoch=$authEpoch)"
}

/**
 * A verified recovery for [DeviceRegistrationRepository.replaceForRecovery]:
 * replace [expectedTarget]'s key with [replacementPublicKey], authorized by
 * [expectedAuthorizer]. Both expected states are what the signatures were
 * verified against; the replacement only happens if they are still current.
 */
class RecoveryReplacement(
    val expectedTarget: DeviceRegistrationState,
    val expectedAuthorizer: DeviceRegistrationState,
    replacementPublicKey: ByteArray,
    val recoveryId: DeviceRecoveryId,
    val nonce: RequestNonce,
    val timestamp: Instant,
    val pruneBefore: Instant,
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
}

/** A rejected device registration. Nothing was stored. Messages never contain key bytes. */
sealed class DeviceRegistrationException(message: String) : Exception(message) {
    /** The registration is malformed, for example a key of the wrong size. */
    class InvalidRegistration(message: String) : DeviceRegistrationException(message)

    /** The address is registered with a different key. Only a recovery replaces it (docs/device-recovery.md). */
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

interface ServerStorage {
    val preKeys: PreKeyRepository
    val mailboxes: MailboxRepository
    val devices: DeviceRegistrationRepository
    val authenticationNonces: AuthenticationNonceRepository
}
